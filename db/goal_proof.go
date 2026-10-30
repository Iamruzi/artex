package db

import (
	"context"
	"database/sql"
	"fmt"
)

// proofEvidenceSQL is shared by proof submission and final completion. A node's
// label alone is insufficient: dismissed/origin facts and untriaged findings
// must not prove success. Direct source visibility follows the existing graph
// read contract; transitive sources remain excluded.
const proofEvidenceSQL = `
e.state='confirmed' AND (
  e.kind='fact' OR (e.kind='finding' AND EXISTS (
    SELECT 1 FROM findings f WHERE f.node_id=e.id AND f.status='confirmed'
  ))
) AND (
  e.exploration_id=g.exploration_id OR EXISTS (
    SELECT 1 FROM tasks owner
    JOIN task_relations r ON r.task_id=owner.id
    JOIN tasks source ON source.id=r.source_task_id
    WHERE owner.exploration_id=g.exploration_id AND owner.deleted_at IS NULL
      AND source.exploration_id=e.exploration_id AND source.deleted_at IS NULL
  )
)`

const goalHasProofSQL = `EXISTS (
  SELECT 1 FROM exploration_edges p
  JOIN exploration_nodes e ON e.id=p.src_id
  WHERE p.exploration_id=g.exploration_id AND p.dst_id=g.id AND p.rel='proves'
    AND ` + proofEvidenceSQL + `
)`

const allGoalsProvenSQL = `
EXISTS (SELECT 1 FROM exploration_nodes WHERE exploration_id=$1 AND kind='goal')
AND NOT EXISTS (
  SELECT 1 FROM exploration_nodes g
  WHERE g.exploration_id=$1 AND g.kind='goal' AND (
    g.state<>'met' OR NOT ` + goalHasProofSQL + `
  )
)`

const pendingGoalReviewSQL = `EXISTS (
 SELECT 1 FROM exploration_nodes g WHERE g.exploration_id=$1 AND g.kind='goal'
 AND (g.state='open' OR (g.state='met' AND NOT ` + goalHasProofSQL + `))
)`

// NeedsGoalReview prevents the drained-frontier branch from treating a stale
// met label as accepted proof. Explicitly abandoned goals remain resolved.
func (s *ExplorationStore) NeedsGoalReview(ctx context.Context) (bool, error) {
	var pending bool
	err := s.db.QueryRowContext(ctx, `SELECT `+pendingGoalReviewSQL, s.expID).Scan(&pending)
	return pending, err
}

// AllGoalsProven checks every local goal without a presentation/page limit.
// This validates persistence and evidence eligibility, not semantic sufficiency
// of an arbitrary fact for free-text acceptance criteria.
func (s *ExplorationStore) AllGoalsProven(ctx context.Context) (bool, error) {
	var met bool
	err := s.db.QueryRowContext(ctx, `SELECT `+allGoalsProvenSQL, s.expID).Scan(&met)
	return met, err
}

// ProveGoal commits the edge and state together. No partially saved proof may
// report success. The transaction rechecks evidence against live DB state.
func (s *ExplorationStore) ProveGoal(ctx context.Context, goal, evidence int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var state string
	err = tx.QueryRowContext(ctx, `SELECT state FROM exploration_nodes
WHERE id=$1 AND exploration_id=$2 AND kind='goal' FOR UPDATE`, goal, s.expID).Scan(&state)
	if err == sql.ErrNoRows {
		return fmt.Errorf("goal_id 必须是本任务的目标节点")
	}
	if err != nil {
		return err
	}
	if state != "open" && state != "met" {
		return fmt.Errorf("目标已放弃，请显式恢复后再提交证明")
	}
	var valid bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS (
 SELECT 1 FROM exploration_nodes g, exploration_nodes e
 WHERE g.id=$1 AND e.id=$2 AND `+proofEvidenceSQL+`
)`, goal, evidence).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return fmt.Errorf("证据必须是本任务或直接关联任务的 confirmed 事实/漏洞；漏洞还须有已确认的独立记录，线索、起点、已驳回或未验证记录不能证明目标")
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id)
VALUES ($1,$2,'proves',$3) ON CONFLICT DO NOTHING`, s.expID, evidence, goal); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE exploration_nodes SET state='met',
blocked_reason=NULL, content_version=content_version+1 WHERE id=$1`, goal); err != nil {
		return err
	}
	return tx.Commit()
}

// CompleteTaskWithGoals makes the final persisted success transition conditional
// on current proof records and lifecycle state in the same SQL statement.
func (d *DB) CompleteTaskWithGoals(ctx context.Context, taskID, explorationID int64) (bool, error) {
	return d.completeTaskChecked(ctx, taskID, explorationID, allGoalsProvenSQL)
}

// CompleteDrainedTask preserves execution-end behavior for zero/abandoned goals
// without claiming goal success. Recheck frontier and proofs at the final write.
func (d *DB) CompleteDrainedTask(ctx context.Context, taskID, explorationID int64) (bool, error) {
	return d.completeTaskChecked(ctx, taskID, explorationID, `NOT (`+pendingGoalReviewSQL+`) AND NOT EXISTS (
 SELECT 1 FROM exploration_nodes WHERE exploration_id=$1 AND kind='intent' AND state IN ('open','running')
)`)
}

func (d *DB) completeTaskChecked(ctx context.Context, taskID, explorationID int64, predicate string) (bool, error) {
	res, err := d.ExecContext(ctx, `UPDATE tasks SET status='done',
completed_at=COALESCE(completed_at,now()) WHERE id=$2 AND exploration_id=$1
AND deleted_at IS NULL AND NOT paused AND NOT queued
AND status NOT IN ('done','failed','timeout') AND (`+predicate+`)`, explorationID, taskID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}
