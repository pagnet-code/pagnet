package daemon

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/pagnet-code/pagnet/transport"
)

func TestAccountReplyReadFinalOutput(t *testing.T) {
	got, err := decodeAccountReplyOutput([]byte(`{"textBlocks":["  private <&> answer\n","","€\tend  ","\ud83d\ude00"],"version":1}`))
	if err != nil || got.Version != 1 || !reflect.DeepEqual(got.TextBlocks, []string{"  private <&> answer\n", "", "€\tend  ", "😀"}) {
		t.Fatal("final output changed text or boundaries")
	}
	if got, err := decodeAccountReplyOutput([]byte(`{"version":1,"textBlocks":[]}`)); err != nil || got.TextBlocks == nil || len(got.TextBlocks) != 0 {
		t.Fatal("empty block list rejected")
	}
}

func TestAccountReplyReadFinalOutputRejectsMalformed(t *testing.T) {
	for name, raw := range map[string]string{
		"duplicate":        `{"version":1,"textBlocks":[],"version":1}`,
		"unknown":          `{"version":1,"textBlocks":[],"output":"private"}`,
		"case":             `{"Version":1,"textBlocks":[]}`,
		"missing":          `{"version":1}`,
		"null blocks":      `{"version":1,"textBlocks":null}`,
		"null block":       `{"version":1,"textBlocks":[null]}`,
		"null version":     `{"version":null,"textBlocks":[]}`,
		"version":          `{"version":2,"textBlocks":[]}`,
		"fraction version": `{"version":1.0,"textBlocks":[]}`,
		"nested":           `{"version":1,"textBlocks":[["private"]]}`,
		"trailing":         `{"version":1,"textBlocks":[]} {}`,
		"truncated":        `{"version":1,"textBlocks":["private"`,
		"invalid utf8":     "{\"version\":1,\"textBlocks\":[\"\xff\"]}",
		"high surrogate":   `{"version":1,"textBlocks":["\ud800"]}`,
		"low surrogate":    `{"version":1,"textBlocks":["\udc00"]}`,
		"bad pair":         `{"version":1,"textBlocks":["\ud800\u0061"]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeAccountReplyOutput([]byte(raw)); err == nil {
				t.Fatal("accepted malformed output")
			}
		})
	}
	if _, err := decodeAccountReplyOutput(bytes.Repeat([]byte(" "), transport.NativeContentMaxPlaintextBytes+1)); err == nil {
		t.Fatal("accepted oversized output")
	}
}

func TestAccountReplyReadFinalOutputBlockLimit(t *testing.T) {
	for _, count := range []int{transport.BrowserAccountReplyReadMaxTextBlocks, transport.BrowserAccountReplyReadMaxTextBlocks + 1} {
		raw := []byte(`{"version":1,"textBlocks":[` + strings.Repeat(`"",`, count-1) + `""]}`)
		output, err := decodeAccountReplyOutput(raw)
		if count == transport.BrowserAccountReplyReadMaxTextBlocks {
			if err != nil || len(output.TextBlocks) != count {
				t.Fatal("rejected bounded final text blocks")
			}
		} else if err == nil {
			t.Fatal("accepted too many final text blocks")
		}
	}
}
