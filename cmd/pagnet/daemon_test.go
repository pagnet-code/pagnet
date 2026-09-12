package main

import (
	"reflect"
	"testing"
)

func TestDetachArgs(t *testing.T) {
	cases := []struct {
		name    string
		osArgs  []string
		changed map[string]bool
		want    []string
	}{
		{
			name:    "bare -d",
			osArgs:  []string{"-d"},
			changed: map[string]bool{},
			want:    []string{"daemon"},
		},
		{
			name:    "--detach stripped",
			osArgs:  []string{"--detach"},
			changed: map[string]bool{},
			want:    []string{"daemon"},
		},
		{
			name:    "state-dir forwarded",
			osArgs:  []string{"-d", "--state-dir", "/tmp/pagnet-detach-test"},
			changed: map[string]bool{"state-dir": true},
			want:    []string{"daemon", "--state-dir", "/tmp/pagnet-detach-test"},
		},
		{
			name:    "state-dir equals form forwarded",
			osArgs:  []string{"-d", "--state-dir=/tmp/x"},
			changed: map[string]bool{"state-dir": true},
			want:    []string{"daemon", "--state-dir=/tmp/x"},
		},
		{
			name:    "unset flags not forwarded",
			osArgs:  []string{"-d", "--state-dir", "/tmp/x", "--log-level", "debug"},
			changed: map[string]bool{},
			want:    []string{"daemon"},
		},
		{
			name:    "all daemon flags forwarded",
			osArgs:  []string{"-d", "--log-level", "debug", "--debug", "--no-auto-update"},
			changed: map[string]bool{"log-level": true, "debug": true, "no-auto-update": true},
			want:    []string{"daemon", "--log-level", "debug", "--debug", "--no-auto-update"},
		},
		{
			name:    "root flags dropped",
			osArgs:  []string{"-d", "--server", "http://x", "--token", "t", "--state-dir", "/tmp/x"},
			changed: map[string]bool{"state-dir": true},
			want:    []string{"daemon", "--state-dir", "/tmp/x"},
		},
		{
			name:    "detach equals form stripped",
			osArgs:  []string{"-d=true", "--debug"},
			changed: map[string]bool{"debug": true},
			want:    []string{"daemon", "--debug"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detachArgs(tc.osArgs, tc.changed)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("detachArgs(%v, %v) = %v, want %v", tc.osArgs, tc.changed, got, tc.want)
			}
		})
	}
}
