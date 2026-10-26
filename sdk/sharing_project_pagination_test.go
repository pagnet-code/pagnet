package sdk

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListSharingProjectsPagination(t *testing.T) {
	_, c := newProjectEnrollmentFixture(t)
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/sharing-project-transports" || r.URL.Query().Get("endpointId") != "endpoint" || r.Header.Get("Authorization") != "Bearer pgn_epd_v1_test" {
			t.Error("invalid project list request")
		}
		var page []SharingProjectStatus
		switch r.URL.Query().Get("cursor") {
		case "":
			for i := range 100 {
				page = append(page, SharingProjectStatus{ProjectID: fmt.Sprintf("project-%03d", i)})
			}
			w.Header().Set("X-Next-Cursor", "next")
		case "next":
			page = append(page, SharingProjectStatus{ProjectID: "project-100"})
		default:
			t.Error("unexpected project cursor")
		}
		_ = json.NewEncoder(w).Encode(page)
	}))
	t.Cleanup(server.Close)
	c.rest = newRestClient(server.URL, "test", func() string { return "pgn_epd_v1_test" })
	projects, err := c.ListSharingProjects(t.Context())
	if err != nil || len(projects) != 101 || requests != 2 {
		t.Fatalf("list: %d projects, %d requests, %v", len(projects), requests, err)
	}
	for i, project := range projects {
		if project.ProjectID != fmt.Sprintf("project-%03d", i) {
			t.Fatalf("project %d: %s", i, project.ProjectID)
		}
	}
}

func TestListSharingProjectsRejectsRepeatedCursor(t *testing.T) {
	_, c := newProjectEnrollmentFixture(t)
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("X-Next-Cursor", "repeat")
		_ = json.NewEncoder(w).Encode([]SharingProjectStatus{})
	}))
	t.Cleanup(server.Close)
	c.rest = newRestClient(server.URL, "test", func() string { return "pgn_epd_v1_test" })
	if _, err := c.ListSharingProjects(t.Context()); err == nil || requests != 2 {
		t.Fatalf("repeated cursor: %d requests, %v", requests, err)
	}
}
