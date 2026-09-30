package daemon

import (
	"path/filepath"
	"testing"
	"time"
)

func TestTerminalDetachTombstoneSurvivesRestartAndPrunes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	st, err := OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.MarkTerminalDetached("instance", "old"); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for _, target := range []struct {
		instance, session string
		canceled          bool
	}{
		{"instance", "old", true}, {"instance", "new", false}, {"other", "old", false},
	} {
		canceled, err := st.TerminalDetached(target.instance, target.session)
		if err != nil || canceled != target.canceled {
			t.Fatalf("%s/%s canceled=%v err=%v", target.instance, target.session, canceled, err)
		}
	}
	if err := st.PruneProcessed(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	canceled, err := st.TerminalDetached("instance", "old")
	if err != nil || canceled {
		t.Fatalf("expired tombstone retained: canceled=%v err=%v", canceled, err)
	}
}
