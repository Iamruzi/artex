package server

import (
	"net/url"
	"testing"
)

func TestApprovalFilterAcceptsExplicitAutoAllowSource(t *testing.T) {
	filter, err := interceptFilterParams(url.Values{"decision_source": []string{"auto_allow"}})
	if err != nil || filter.DecisionSource != "auto_allow" {
		t.Fatalf("filter rejected audit source: %+v %v", filter, err)
	}
	if _, err := interceptFilterParams(url.Values{"decision_source": []string{"arbitrary"}}); err == nil {
		t.Fatal("invalid source accepted")
	}
}

func TestApprovalFilterAcceptsBackgroundAutoAllowSource(t *testing.T) {
	filter, err := interceptFilterParams(url.Values{"decision_source": []string{"background_auto_allow"}})
	if err != nil || filter.DecisionSource != "background_auto_allow" {
		t.Fatalf("filter=%+v err=%v", filter, err)
	}
}
