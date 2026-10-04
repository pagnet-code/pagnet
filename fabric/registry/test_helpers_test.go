package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/pagnet-code/pagnet/fabric/search"
)

func digestForTest(b []byte) [32]byte { return sha256.Sum256(b) }
func indexHashForTest(r search.CommitRecord) string {
	r.SHA256 = ""
	raw, _ := json.Marshal(r)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
