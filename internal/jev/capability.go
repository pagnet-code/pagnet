package jev

import (
	"encoding/json"
	"github.com/pagnet-code/pagnet/domain"
)

// Capability describes the fixed invocation contract, not permission to invoke it.
func Capability() domain.Capability {
	return domain.Capability{ID: CapabilityID, Version: 1, Name: "Evaluate typed judgments with Jev", Description: "Evaluates text or structured state using 1–16 Choice, Score or Noul questions. Returns typed answers and probabilities. The service sends this invocation's state and questions to TypeSafe; callers decide how to use uncertain answers.", Tags: []string{"typesafe", "jev", "classification", "routing", "verification"}, InputSchema: json.RawMessage(`{"type":"object","additionalProperties":false,"required":["state","questions"],"properties":{"state":{"type":["string","object","array"]},"questions":{"type":"object","minProperties":1,"maxProperties":16,"propertyNames":{"minLength":1,"maxLength":128},"additionalProperties":{"type":"object","additionalProperties":false,"required":["type","instructions"],"properties":{"type":{"enum":["noul","choice","score"]},"instructions":{"type":["string","object","array"]},"criteria":{"type":["object","array"]}}}}}}`), OutputSchema: json.RawMessage(`{"type":"object","required":["model","answers","usage"],"properties":{"model":{"type":"string"},"answers":{"type":"object"},"usage":{"type":"object","required":["input_tokens","output_tokens"],"properties":{"input_tokens":{"type":"integer","minimum":0},"output_tokens":{"type":"integer","minimum":0}}}}}`)}
}
