package exceptions

import (
	"testing"
	"time"
)

func TestExceptionApplies(t *testing.T) {
	tests := []struct {
		name      string
		exception func() Exception
		context   Context
		want      bool
	}{
		{
			name: "scope all",
			exception: func() Exception {
				e := validException()
				e.Scope.All = true
				return e
			},
			context: Context{Profile: "server"},
			want:    true,
		},
		{
			name: "host scope case insensitive",
			exception: func() Exception {
				e := validException()
				e.Scope.Hosts = []string{"Node01.Example"}
				return e
			},
			context: Context{Host: "node01.example"},
			want:    true,
		},
		{
			name: "profile mismatch",
			exception: func() Exception {
				e := validException()
				e.Scope.Profiles = []string{"server"}
				return e
			},
			context: Context{Profile: "workstation"},
			want:    false,
		},
		{
			name: "applies on expiry date",
			exception: func() Exception {
				e := validException()
				e.Scope.All = true
				e.Lifecycle.Expires = "2026-01-01"
				return e
			},
			context: Context{Now: time.Date(2026, 1, 1, 23, 59, 59, 0, time.UTC)},
			want:    true,
		},
		{
			name: "does not apply after expiry date",
			exception: func() Exception {
				e := validException()
				e.Scope.All = true
				e.Lifecycle.Expires = "2026-01-01"
				return e
			},
			context: Context{Now: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)},
			want:    false,
		},
		{
			name: "hyphenated status does not apply",
			exception: func() Exception {
				e := validException()
				e.Status = "not-applicable"
				e.Scope.All = true
				return e
			},
			context: Context{},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.exception().Applies(tt.context); got != tt.want {
				t.Fatalf("Applies() = %v, want %v", got, tt.want)
			}
		})
	}
}

func validException() Exception {
	var e Exception
	e.Status = "exception"
	return e
}
