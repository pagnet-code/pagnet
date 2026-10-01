package daemon

import (
	"errors"
	"testing"
)

func TestKernelProcessTreeBinding(t *testing.T) {
	for _, scenario := range []string{"valid", "sibling", "owner", "older", "parent newer", "missing", "cycle", "wrong pid", "changed start", "changed owner", "changed parent", "invalid root", "changed root", "disappeared", "depth"} {
		t.Run(scenario, func(t *testing.T) {
			rows := map[int]bridgeProcessSnapshot{10: {PID: 10, Parent: 2, UID: 501, Start: 100}, 20: {PID: 20, Parent: 10, UID: 501, Start: 200}, 30: {PID: 30, Parent: 20, UID: 501, Start: 300}}
			peer := 30
			switch scenario {
			case "sibling":
				row := rows[20]
				row.Parent = 2
				rows[20] = row
			case "owner":
				row := rows[20]
				row.UID = 502
				rows[20] = row
			case "older":
				row := rows[30]
				row.Start = 99
				rows[30] = row
			case "parent newer":
				row := rows[20]
				row.Start = 400
				rows[20] = row
			case "missing":
				delete(rows, 20)
			case "cycle":
				row := rows[20]
				row.Parent = 30
				row.Start = 300
				rows[20] = row
			case "wrong pid":
				row := rows[20]
				row.PID = 21
				rows[20] = row
			case "invalid root":
				row := rows[10]
				row.Start = 0
				rows[10] = row
			case "depth":
				peer = 100
				for pid := 40; pid <= 100; pid++ {
					rows[pid] = bridgeProcessSnapshot{PID: pid, Parent: pid - 1, UID: 501, Start: int64(pid * 10)}
				}
				row := rows[40]
				row.Parent = 30
				rows[40] = row
			}
			reads := map[int]int{}
			read := func(pid int) (bridgeProcessSnapshot, error) {
				row, ok := rows[pid]
				if !ok {
					return row, errors.New("absent")
				}
				reads[pid]++
				if scenario == "changed root" && pid == 10 && reads[pid] > 1 {
					row.Start++
				}
				if scenario == "disappeared" && pid == 20 && reads[pid] > 1 {
					return row, errors.New("exited")
				}
				if pid == 30 && reads[pid] > 1 {
					switch scenario {
					case "changed start":
						row.Start++
					case "changed owner":
						row.UID++
					case "changed parent":
						row.Parent = 10
					}
				}
				return row, nil
			}
			err := verifyKernelProcessTree(peer, 10, 501, read)
			if scenario == "valid" && err != nil {
				t.Fatal(err)
			}
			if scenario != "valid" && err == nil {
				t.Fatal("accepted invalid kernel ancestry")
			}
		})
	}
}
