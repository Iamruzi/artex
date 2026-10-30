package mcphttp

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Both the Agent and backend paths must retain structured-only results. Native
// image/audio rendering and outputSchema validation are intentionally separate;
// unsupported blocks remain JSON data and resource links are never fetched here.
type decodedToolResult struct {
	Text       string
	Structured json.RawMessage
	IsError    bool
}

func decodeToolResult(raw json.RawMessage) (decodedToolResult, error) {
	var result *struct {
		Content           []json.RawMessage `json:"content"`
		StructuredContent json.RawMessage   `json:"structuredContent"`
		IsError           bool              `json:"isError"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return decodedToolResult{}, err
	}
	if result == nil {
		return decodedToolResult{}, fmt.Errorf("tool result must be an object")
	}
	if result.Content == nil && len(result.StructuredContent) == 0 {
		return decodedToolResult{}, fmt.Errorf("tool result is missing content")
	}
	var text strings.Builder
	for _, block := range result.Content {
		var item struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}
		if err := json.Unmarshal(block, &item); err != nil {
			return decodedToolResult{}, fmt.Errorf("invalid content block: %w", err)
		}
		if item.Type == "" {
			return decodedToolResult{}, fmt.Errorf("content block is missing its type")
		}
		if item.Type == "text" {
			text.WriteString(item.Text)
		} else {
			if text.Len() > 0 {
				text.WriteString("\n\n")
			}
			text.Write(block)
		}
	}
	if len(result.StructuredContent) > 0 {
		if text.Len() > 0 {
			text.WriteString("\n\n[structuredContent]\n")
		}
		text.Write(result.StructuredContent)
	}
	return decodedToolResult{Text: text.String(), Structured: result.StructuredContent, IsError: result.IsError}, nil
}
