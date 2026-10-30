package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

var knowledgeCVE = regexp.MustCompile(`^CVE-\d{4}-\d{4,8}$`)

type KnowledgeEntry struct {
	ID          int64      `json:"id"`
	Title       string     `json:"title"`
	Kind        string     `json:"kind"`
	Product     string     `json:"product"`
	Versions    string     `json:"versions"`
	CVEs        []string   `json:"cves"`
	Tags        []string   `json:"tags"`
	Summary     string     `json:"summary"`
	Content     string     `json:"content,omitempty"`
	SourceURL   string     `json:"source_url"`
	SourceRef   string     `json:"source_ref"`
	SHA256      string     `json:"sha256"`
	State       string     `json:"state"`
	ScopeTaskID *int64     `json:"scope_task_id,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

func (e *KnowledgeEntry) Validate() error {
	for name, part := range map[string]struct {
		s string
		n int
	}{"title": {e.Title, 200}, "summary": {e.Summary, 1200}, "content": {e.Content, 32768}, "product": {e.Product, 120}, "versions": {e.Versions, 300}, "source_url": {e.SourceURL, 2048}, "source_ref": {e.SourceRef, 300}} {
		if len(part.s) > part.n || !utf8.ValidString(part.s) || strings.ContainsRune(part.s, 0) {
			return fmt.Errorf("%s 长度或编码无效", name)
		}
	}
	if strings.TrimSpace(e.Title) == "" || strings.TrimSpace(e.Content) == "" || strings.TrimSpace(e.SourceRef) == "" {
		return errors.New("title、content、source_ref 必填；需记录来源")
	}
	switch e.Kind {
	case "poc", "advisory", "methodology", "negative", "context":
	default:
		return errors.New("kind 必须为 poc/advisory/methodology/negative/context")
	}
	switch e.State {
	case "draft", "active", "retired":
	default:
		return errors.New("state 必须为 draft/active/retired")
	}
	if e.ScopeTaskID != nil && *e.ScopeTaskID <= 0 {
		return errors.New("scope_task_id 无效")
	}
	if len(e.CVEs) > 16 || len(e.Tags) > 16 {
		return errors.New("CVE 或标签超过 16 个")
	}
	for i, v := range e.CVEs {
		e.CVEs[i] = strings.ToUpper(strings.TrimSpace(v))
		if !knowledgeCVE.MatchString(e.CVEs[i]) {
			return errors.New("CVE 格式无效")
		}
	}
	for _, v := range e.Tags {
		if len(v) > 64 || !utf8.ValidString(v) || strings.ContainsRune(v, 0) {
			return errors.New("标签无效")
		}
	}
	if e.SourceURL != "" {
		u, err := url.Parse(e.SourceURL)
		if err != nil || u.Hostname() == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
			return errors.New("source_url 必须是无凭据的 HTTP(S) 来源链接")
		}
	}
	e.SHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte(e.Content)))
	return nil
}

const knowledgeCols = `id,title,kind,product,versions,cves,tags,summary,content,source_url,source_ref,sha256,state,scope_task_id,expires_at,updated_at`

func scanKnowledge(row interface{ Scan(...any) error }) (*KnowledgeEntry, error) {
	var e KnowledgeEntry
	var cves, tags []byte
	err := row.Scan(&e.ID, &e.Title, &e.Kind, &e.Product, &e.Versions, &cves, &tags, &e.Summary, &e.Content, &e.SourceURL, &e.SourceRef, &e.SHA256, &e.State, &e.ScopeTaskID, &e.ExpiresAt, &e.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(cves, &e.CVEs); err != nil {
		return nil, err
	}
	if err = json.Unmarshal(tags, &e.Tags); err != nil {
		return nil, err
	}
	return &e, nil
}

func (d *DB) SaveKnowledge(ctx context.Context, e KnowledgeEntry) (*KnowledgeEntry, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	cves, _ := json.Marshal(e.CVEs)
	tags, _ := json.Marshal(e.Tags)
	if e.CVEs == nil {
		cves = []byte("[]")
	}
	if e.Tags == nil {
		tags = []byte("[]")
	}
	args := []any{e.Title, e.Kind, e.Product, e.Versions, string(cves), string(tags), e.Summary, e.Content, e.SourceURL, e.SourceRef, e.SHA256, e.State, e.ScopeTaskID, e.ExpiresAt}
	if e.ID == 0 {
		return scanKnowledge(d.QueryRowContext(ctx, `INSERT INTO knowledge_entries(title,kind,product,versions,cves,tags,summary,content,source_url,source_ref,sha256,state,scope_task_id,expires_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING `+knowledgeCols, args...))
	}
	args = append(args, e.ID)
	return scanKnowledge(d.QueryRowContext(ctx, `UPDATE knowledge_entries SET title=$1,kind=$2,product=$3,versions=$4,cves=$5,tags=$6,summary=$7,content=$8,source_url=$9,source_ref=$10,sha256=$11,state=$12,scope_task_id=$13,expires_at=$14,updated_at=now() WHERE id=$15 RETURNING `+knowledgeCols, args...))
}

type KnowledgeQuery struct {
	Query   string `json:"query"`
	Product string `json:"product"`
	CVE     string `json:"cve"`
	Kind    string `json:"kind"`
	Limit   int    `json:"limit"`
	TaskID  int64  `json:"-"`
	Review  bool   `json:"-"`
}

func (d *DB) SearchKnowledge(ctx context.Context, q KnowledgeQuery) ([]KnowledgeEntry, error) {
	if len(q.Query) > 200 || len(q.Product) > 120 || len(q.CVE) > 32 || len(q.Kind) > 24 {
		return nil, errors.New("知识检索条件过长")
	}
	if q.Limit <= 0 {
		q.Limit = 5
	}
	if q.Limit > 30 {
		q.Limit = 30
	}
	// Parameters remain literals even for LIKE; wildcard characters are escaped.
	pattern := func(s string) string {
		return "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s) + "%"
	}
	rows, err := d.QueryContext(ctx, `SELECT `+knowledgeCols+` FROM knowledge_entries k WHERE
($1 OR (state='active' AND (expires_at IS NULL OR expires_at>now()) AND (scope_task_id IS NULL OR (scope_task_id=$2 AND EXISTS(SELECT 1 FROM tasks WHERE id=$2 AND deleted_at IS NULL)))))
AND ($3='' OR search_vector @@ plainto_tsquery('simple',$3) OR title ILIKE $4 ESCAPE '\' OR summary ILIKE $4 ESCAPE '\')
AND ($5='' OR product ILIKE $6 ESCAPE '\') AND ($7='' OR cves ? $7) AND ($8='' OR kind=$8)
ORDER BY (CASE WHEN $7<>'' AND cves ? $7 THEN 1 ELSE 0 END) DESC,updated_at DESC,id DESC LIMIT $9`, q.Review, q.TaskID, q.Query, pattern(q.Query), q.Product, pattern(q.Product), strings.ToUpper(q.CVE), q.Kind, q.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []KnowledgeEntry{}
	for rows.Next() {
		e, err := scanKnowledge(rows)
		if err != nil {
			return nil, err
		}
		e.Content = ""
		out = append(out, *e)
	}
	return out, rows.Err()
}

func (d *DB) GetKnowledge(ctx context.Context, id, taskID int64, review bool) (*KnowledgeEntry, error) {
	e, err := scanKnowledge(d.QueryRowContext(ctx, `SELECT `+knowledgeCols+` FROM knowledge_entries WHERE id=$1 AND ($2 OR (state='active' AND (expires_at IS NULL OR expires_at>now()) AND (scope_task_id IS NULL OR (scope_task_id=$3 AND EXISTS(SELECT 1 FROM tasks WHERE id=$3 AND deleted_at IS NULL)))))`, id, review, taskID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return e, err
}

func (d *DB) KnowledgeCache(ctx context.Context, key string) (json.RawMessage, error) {
	var raw []byte
	err := d.QueryRowContext(ctx, `SELECT payload FROM knowledge_lookup_cache WHERE key=$1 AND expires_at>now()`, key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return raw, err
}
func (d *DB) SaveKnowledgeCache(ctx context.Context, key string, payload []byte) error {
	if len(payload) > 1<<20 {
		return errors.New("lookup cache exceeds budget")
	}
	// Expiry must eventually reclaim disk, not merely hide stale rows. A bounded
	// lazy sweep avoids another daemon and large maintenance transactions.
	if _, err := d.ExecContext(ctx, `DELETE FROM knowledge_lookup_cache WHERE key IN (SELECT key FROM knowledge_lookup_cache WHERE expires_at<=now() ORDER BY expires_at LIMIT 100)`); err != nil {
		return err
	}
	_, err := d.ExecContext(ctx, `INSERT INTO knowledge_lookup_cache(key,payload,expires_at) VALUES($1,$2,now()+interval '24 hours') ON CONFLICT(key) DO UPDATE SET payload=EXCLUDED.payload,expires_at=EXCLUDED.expires_at`, key, string(payload))
	return err
}

type KnowledgeEvent struct {
	ID        int64     `json:"id"`
	TaskID    *int64    `json:"task_id,omitempty"`
	IntentID  int64     `json:"intent_id"`
	Agent     string    `json:"agent"`
	Action    string    `json:"action"`
	Status    string    `json:"status"`
	EntryIDs  []int64   `json:"entry_ids"`
	SHA256    string    `json:"sha256"`
	Bytes     int       `json:"bytes"`
	CreatedAt time.Time `json:"created_at"`
}

func (d *DB) AddKnowledgeEvent(ctx context.Context, e KnowledgeEvent) error {
	ids, _ := json.Marshal(e.EntryIDs)
	if e.EntryIDs == nil {
		ids = []byte("[]")
	}
	_, err := d.ExecContext(ctx, `INSERT INTO knowledge_events(task_id,intent_id,agent,action,status,entry_ids,sha256,bytes) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, e.TaskID, e.IntentID, e.Agent, e.Action, e.Status, string(ids), e.SHA256, e.Bytes)
	return err
}
func (d *DB) KnowledgeEvents(ctx context.Context) ([]KnowledgeEvent, error) {
	rows, err := d.QueryContext(ctx, `SELECT id,task_id,intent_id,agent,action,status,entry_ids,sha256,bytes,created_at FROM knowledge_events ORDER BY id DESC LIMIT 40`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []KnowledgeEvent{}
	for rows.Next() {
		var e KnowledgeEvent
		var ids []byte
		if err = rows.Scan(&e.ID, &e.TaskID, &e.IntentID, &e.Agent, &e.Action, &e.Status, &ids, &e.SHA256, &e.Bytes, &e.CreatedAt); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(ids, &e.EntryIDs); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// KnowledgeAssetHints reads product/version fields only from the current task's
// assets or anchors. Credentials, hostnames, URLs and banners are never returned.
func (d *DB) KnowledgeAssetHints(ctx context.Context, taskID, intentID int64) ([]map[string]any, error) {
	rows, err := d.QueryContext(ctx, `SELECT a.id,COALESCE(a.service_name,''),COALESCE(to_jsonb(a.technologies),'[]'::jsonb),COALESCE(a.extra,'{}'::jsonb) FROM assets a
WHERE EXISTS(SELECT 1 FROM tasks WHERE id=$1 AND deleted_at IS NULL AND NOT paused AND NOT queued AND status NOT IN ('done','failed','timeout'))
AND ($1=ANY(a.task_ids) OR EXISTS(SELECT 1 FROM exploration_anchors ea JOIN exploration_nodes n ON n.id=ea.node_id JOIN tasks t ON t.exploration_id=n.exploration_id WHERE ea.asset_id=a.id AND t.id=$1))
AND ($2=0 OR EXISTS(SELECT 1 FROM exploration_anchors ea JOIN exploration_nodes n ON n.id=ea.node_id JOIN tasks t ON t.exploration_id=n.exploration_id WHERE ea.asset_id=a.id AND n.id=$2 AND t.id=$1)) ORDER BY a.id DESC LIMIT 3`, taskID, intentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int64
		var name string
		var techRaw, extraRaw []byte
		if err = rows.Scan(&id, &name, &techRaw, &extraRaw); err != nil {
			return nil, err
		}
		var tech []string
		var extra map[string]any
		_ = json.Unmarshal(techRaw, &tech)
		_ = json.Unmarshal(extraRaw, &extra)
		out = append(out, map[string]any{"asset_id": id, "service_name": name, "technologies": tech, "product": extra["product"], "version": extra["version"]})
	}
	return out, rows.Err()
}
