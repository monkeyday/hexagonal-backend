package middleware

import (
	"encoding/json"
	coreerror "sc/core/error"
	"strings"
	"testing"
)

func assertErrCode(t *testing.T, body []byte, wantCode coreerror.ErrCode) {
	t.Helper()
	var resp struct {
		ErrCode coreerror.ErrCode `json:"err_code"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.ErrCode != wantCode {
		t.Errorf("err_code = %d, want %d", resp.ErrCode, wantCode)
	}
}

func assertBodyContains(t *testing.T, body []byte, substr string) {
	t.Helper()
	if !strings.Contains(string(body), substr) {
		t.Errorf("body does not contain %q\nbody: %s", substr, body)
	}
}
