package db

import (
	"fmt"
	"strconv"
	"strings"
)

// NodeFilter narrows a NodesPage query. Empty fields include every value.
type NodeFilter struct {
	Kinds  []string // exploration_nodes.kind
	States []string // exploration_nodes.state
	Query  string   // case-insensitive substring over payload text / origin
	Asc    bool     // true = oldest first (replay); default newest first (broadcast)
}

// NodesPage returns one 1-based page of this exploration's nodes plus the total
// matching count. The 播报板 reads the graph as a time series, so it pages in SQL
// rather than pulling the whole graph like Nodes does. Ordering is by id, which
// is BIGSERIAL and therefore creation order — stable when several nodes share a
// created_at second.
func (s *ExplorationStore) NodesPage(f NodeFilter, page, size int) ([]*Node, int, error) {
	if page < 1 {
		page = 1
	}
	if size <= 0 {
		size = 20
	}
	if size > 200 {
		size = 200
	}
	offset := (page - 1) * size

	conds := []string{"exploration_id=$1"}
	args := []any{s.expID}
	addIn := func(column string, values []string) {
		if len(values) == 0 {
			return
		}
		marks := make([]string, 0, len(values))
		for _, v := range values {
			args = append(args, v)
			marks = append(marks, "$"+fmt.Sprint(len(args)))
		}
		conds = append(conds, column+" IN ("+strings.Join(marks, ",")+")")
	}
	addIn("kind", f.Kinds)
	addIn("state", f.States)
	if q := strings.TrimSpace(f.Query); q != "" {
		args = append(args, "%"+q+"%")
		mark := "$" + fmt.Sprint(len(args))
		ors := []string{"payload::text ILIKE " + mark, "COALESCE(origin,'') ILIKE " + mark}
		// 纯数字(或 UI 里带 # 前缀的形式,如「#41」)当作节点 id 精确匹配,方便直接定位某个节点。
		if idStr := strings.TrimPrefix(q, "#"); idStr != "" {
			if id, err := strconv.ParseInt(idStr, 10, 64); err == nil {
				args = append(args, id)
				ors = append(ors, "id = $"+fmt.Sprint(len(args)))
			}
		}
		conds = append(conds, "("+strings.Join(ors, " OR ")+")")
	}
	where := " WHERE " + strings.Join(conds, " AND ")

	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM exploration_nodes`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	order := "DESC"
	if f.Asc {
		order = "ASC"
	}
	args = append(args, size, offset)
	rows, err := s.db.Query(`SELECT `+nodeCols+` FROM exploration_nodes`+where+
		` ORDER BY id `+order+
		` LIMIT $`+fmt.Sprint(len(args)-1)+` OFFSET $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	nodes, err := scanNodes(rows)
	if err != nil {
		return nil, 0, err
	}
	return nodes, total, nil
}

// NodesByIDs loads the given nodes of this exploration in id order. Used to
// resolve the neighbours of a 播报板 page without fetching the whole graph.
func (s *ExplorationStore) NodesByIDs(ids []int64) ([]*Node, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	args := make([]any, 0, len(ids)+1)
	args = append(args, s.expID)
	marks := make([]string, 0, len(ids))
	for _, id := range ids {
		args = append(args, id)
		marks = append(marks, "$"+fmt.Sprint(len(args)))
	}
	rows, err := s.db.Query(`SELECT `+nodeCols+` FROM exploration_nodes
WHERE exploration_id=$1 AND id IN (`+strings.Join(marks, ",")+`) ORDER BY id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanNodes(rows)
}

// EdgesTouching returns every edge with one end among ids — the 播报板 uses it to
// spell out where a node came from and what it produced.
func (s *ExplorationStore) EdgesTouching(ids []int64) ([]Edge, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	args := make([]any, 0, len(ids)+1)
	args = append(args, s.expID)
	marks := make([]string, 0, len(ids))
	for _, id := range ids {
		args = append(args, id)
		marks = append(marks, "$"+fmt.Sprint(len(args)))
	}
	list := strings.Join(marks, ",")
	rows, err := s.db.Query(`SELECT src_id, rel, dst_id FROM exploration_edges
WHERE exploration_id=$1 AND (src_id IN (`+list+`) OR dst_id IN (`+list+`))`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Edge
	for rows.Next() {
		var e Edge
		if err := rows.Scan(&e.From, &e.Rel, &e.To); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
