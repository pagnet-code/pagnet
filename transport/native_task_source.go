package transport

import "github.com/pagnet-code/pagnet/e2ee"

// NativeTaskSource is public original command metadata. The server derives it
// from the original offered task under admission locks; the worker pins it
// before native acceptance. No body, key or fresh transport grant belongs here.
// InputAAD preserves the exact original task crypto epoch/context across retry.
type NativeTaskSource struct {
	TaskID   string   `json:"taskId"`
	InputAAD e2ee.AAD `json:"inputAAD"`
}
