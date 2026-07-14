package display

import (
	"errors"
	"strings"
	"testing"

	"lpe-checker/internal/collector"
)

func TestGUIErrorMessageClassification(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{err: &collector.ConnectionError{Err: errors.New("timeout")}, want: "无法连接主机"},
		{err: &collector.CommandError{Name: "find", Err: errors.New("exit 1")}, want: "部分采集命令失败"},
		{err: &collector.CommandNotAllowedError{Name: "sh"}, want: "只读白名单拒绝"},
	}
	for _, tt := range tests {
		if got := GUIErrorMessage(tt.err); !strings.Contains(got, tt.want) {
			t.Fatalf("GUIErrorMessage(%T) = %q; want substring %q", tt.err, got, tt.want)
		}
	}
}
