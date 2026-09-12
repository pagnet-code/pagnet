package domain

import (
	"net/url"
	"strings"
	"time"
)

// Resource is a logical thing agents can be responsible for. Resources are
// NEVER identified by a local filesystem path; workspaces map (host, path)
// onto a resource.
type Resource struct {
	ID           ID
	NetworkID    ID
	Kind         ResourceKind
	CanonicalKey string // e.g. "github.com/xemahq/dsl" or "billing"
	DisplayName  string
	Metadata     map[string]any
	CreatedAt    time.Time
}

// NormalizeGitRemote canonicalizes a Git remote URL so that different
// notations of the same repository resolve to the same logical resource:
//
//	git@github.com:xemahq/dsl.git
//	https://github.com/xemahq/dsl.git
//	ssh://git@github.com/xemahq/dsl.git
//	  -> github.com/xemahq/dsl
//
// It returns (canonical, ok). Local paths and non-Git inputs yield ok=false.
func NormalizeGitRemote(remote string) (string, bool) {
	remote = strings.TrimSpace(remote)
	if remote == "" {
		return "", false
	}

	var host, path string
	if i := strings.Index(remote, "://"); i > 0 {
		u, err := url.Parse(remote)
		if err != nil || u.Host == "" {
			return "", false
		}
		host = u.Hostname()
		if p := u.Port(); p != "" {
			host += ":" + p
		}
		path = u.EscapedPath()
	} else if at := strings.LastIndex(remote, "@"); at >= 0 {
		// scp-style: [user@]host:path
		rest := remote[at+1:]
		colon := strings.IndexByte(rest, ':')
		if colon < 0 {
			return "", false
		}
		host = rest[:colon]
		path = rest[colon+1:]
	} else {
		// No host component: local path, bare ref, or non-Git URL.
		return "", false
	}

	host = strings.ToLower(strings.TrimSpace(host))
	path = strings.Trim(path, "/")
	path = strings.TrimSuffix(path, ".git")
	if host == "" || path == "" {
		return "", false
	}
	return host + "/" + path, true
}

// IsLocalPath reports whether p looks like a local filesystem path
// (used to reject it as a remote URL).
func IsLocalPath(p string) bool {
	if p == "" {
		return true
	}
	if strings.Contains(p, "://") {
		return false
	}
	return strings.HasPrefix(p, "/") || strings.HasPrefix(p, ".") || strings.Contains(p, ":\\")
}
