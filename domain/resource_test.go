package domain

import "testing"

func TestNormalizeGitRemote(t *testing.T) {
	tests := []struct {
		remote string
		want   string
		ok     bool
	}{
		{"git@github.com:xemahq/dsl.git", "github.com/xemahq/dsl", true},
		{"https://github.com/xemahq/dsl.git", "github.com/xemahq/dsl", true},
		{"ssh://git@github.com/xemahq/dsl.git", "github.com/xemahq/dsl", true},
		{"http://github.com/xemahq/dsl.git", "github.com/xemahq/dsl", true},
		{"git@github.com:xemahq/dsl", "github.com/xemahq/dsl", true},
		{"git@GITHUB.COM:xemahq/dsl.git", "github.com/xemahq/dsl", true},
		{"ssh://git@gitlab.example.com:2222/group/repo.git", "gitlab.example.com:2222/group/repo", true},
		{"git@gitlab.com:group/sub/repo.git", "gitlab.com/group/sub/repo", true},
		{" /home/user/dev/repo ", "", false}, // local path
		{"./relative/path", "", false},
		{"", "", false},
		{"not a url", "", false},
		{"file:///srv/repos/dsl.git", "", false}, // local path, not a shared resource
	}
	for _, tt := range tests {
		got, ok := NormalizeGitRemote(tt.remote)
		if ok != tt.ok || got != tt.want {
			t.Errorf("NormalizeGitRemote(%q) = (%q, %v), want (%q, %v)", tt.remote, got, ok, tt.want, tt.ok)
		}
	}
}

func TestNormalizeGitRemoteSameResourceAcrossNotations(t *testing.T) {
	a, okA := NormalizeGitRemote("git@github.com:xemahq/dsl.git")
	b, okB := NormalizeGitRemote("https://github.com/xemahq/dsl.git")
	if !okA || !okB || a != b {
		t.Fatalf("expected same canonical resource, got %q and %q", a, b)
	}
}
