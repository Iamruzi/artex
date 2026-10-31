package server

import (
	"encoding/json"
	"github.com/Autumn-27/artex/db"
)

func seedEndpointHTMLImportSchema(pg *db.DB) error {
	fields, _ := json.Marshal(map[string]any{
		"html_path": map[string]any{"type": "string", "description": "本任务已保存的 HTML 路径；与 base_url 同用，由内置解析器登记接口，无需填写 assets"},
		"base_url":  map[string]any{"type": "string", "description": "HTML 抓取时的完整来源 URL；只登记同源、任务范围内的链接和表单"},
	})
	_, err := pg.Exec(`UPDATE tools SET schema=jsonb_set(schema-'required','{properties}',(schema->'properties')||$1::jsonb),description=description||E'\nHTML 导入可只传 html_path 与 base_url，由程序生成 url/method；不发请求，不代表已测试。' WHERE key='insert_assets' AND system=true AND kind='builtin' AND schema->'required'='["assets"]'::jsonb AND NOT ((schema->'properties') ? 'html_path')`, fields)
	return err
}
