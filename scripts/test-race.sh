#!/usr/bin/env bash
# Keep sessionworker's aggregate fixture time within each 20m package budget.
set -euo pipefail

worker=./internal/sessionworker
search_skip='TestSearchPerformanceTargets|TestSearchAdversarialWorstCase'

# Discovery uses the same race build constraints as execution. Keep Go's build
# diagnostics on stderr, and reject empty/duplicate inventories before any run.
discover_tests() {
  local dir=$1
  if ! go test -race -timeout=20m -list '^(Test|Example|Fuzz)' "$worker" > "$dir/discovery"; then
    cat "$dir/discovery" >&2
    echo 'sessionworker test discovery failed' >&2
    return 1
  fi
  LC_ALL=C awk '/^(Test|Example|Fuzz)[^[:space:]]*$/ { print }' "$dir/discovery" | LC_ALL=C sort > "$dir/tests"
  if [[ $(wc -l < "$dir/tests") -lt 4 ]]; then
    echo 'sessionworker discovery must produce at least four tests' >&2
    return 1
  fi
  if [[ -n $(uniq -d "$dir/tests") ]]; then
    echo 'sessionworker discovery contains duplicate names' >&2
    return 1
  fi
}

partition_tests() {
  local dir=$1 shard
  # Round-robin over the sorted inventory is deterministic and differs in
  # size by at most one. Exact top-level anchors also include every subtest.
  for shard in 0 1 2 3; do
    awk -v shard="$shard" '(NR - 1) % 4 == shard' "$dir/tests" > "$dir/shard-$shard"
    if [[ ! -s "$dir/shard-$shard" ]]; then
      echo "sessionworker shard $shard is empty" >&2
      return 1
    fi
  done
}

self_test() (
  local dir shard pattern
  dir=$(mktemp -d)
  trap 'rm -rf "$dir"' EXIT
  # Deliberately unsorted, with all three kinds and one similarly named test.
  go() { printf '%s\n' TestZulu FuzzSeed ExampleOutput TestAlpha TestAlphaExtra TestBeta TestGamma TestDelta TestEpsilon 'ok example 0.001s'; }
  discover_tests "$dir"
  partition_tests "$dir"
  cat "$dir"/shard-* | LC_ALL=C sort > "$dir/actual"
  cmp "$dir/tests" "$dir/actual"
  [[ $(wc -l < "$dir/actual") -eq 9 ]]
  [[ $(wc -l < "$dir/shard-0") -eq 3 ]]
  for shard in 1 2 3; do [[ $(wc -l < "$dir/shard-$shard") -eq 2 ]]; done
  for shard in 0 1 2 3; do
    pattern="^($(paste -sd '|' "$dir/shard-$shard"))$"
    LC_ALL=C grep -E "$pattern" "$dir/tests" > "$dir/selected"
    cmp "$dir/shard-$shard" "$dir/selected"
  done
  cp "$dir/shard-0" "$dir/first"
  partition_tests "$dir"
  cmp "$dir/first" "$dir/shard-0"
  go() { return 1; }
  if discover_tests "$dir" 2>/dev/null; then echo 'failed discovery accepted' >&2; exit 1; fi
  go() { printf 'ok example 0.001s\n'; }
  if discover_tests "$dir" 2>/dev/null; then echo 'empty discovery accepted' >&2; exit 1; fi
  go() { printf '%s\n' TestA TestA TestB TestC; }
  if discover_tests "$dir" 2>/dev/null; then echo 'duplicate discovery accepted' >&2; exit 1; fi
  printf 'TestOnly\n' > "$dir/tests"
  if partition_tests "$dir" 2>/dev/null; then echo 'empty shard accepted' >&2; exit 1; fi
  echo 'race runner self-test passed (partition, determinism, failed/empty/duplicate discovery, empty shard)'
)

main() (
  local dir worker_package shard pattern
  local -a packages
  cd "$(dirname "${BASH_SOURCE[0]}")/.."
  dir=$(mktemp -d)
  trap 'rm -rf "$dir"' EXIT
  discover_tests "$dir"
  partition_tests "$dir"
  worker_package=$(go list "$worker")
  go list ./... > "$dir/packages"
  mapfile -t packages < <(awk -v worker="$worker_package" '$0 != worker' "$dir/packages")
  if [[ ${#packages[@]} -eq 0 ]]; then
    echo 'no packages found outside sessionworker' >&2
    exit 1
  fi
  echo "Race suite: ${#packages[@]} other packages; $(wc -l < "$dir/tests") sessionworker tests in four sequential shards"
  go test -race -timeout=20m -count=1 -p 2 -skip "$search_skip" "${packages[@]}"
  # JSON reports each worker test's start, output, result and elapsed time,
  # including the active test and its diagnostics if a shard times out.
  for shard in 0 1 2 3; do
    pattern="^($(paste -sd '|' "$dir/shard-$shard"))$"
    echo "sessionworker race shard $((shard + 1))/4 ($(wc -l < "$dir/shard-$shard") tests): $pattern"
    go test -json -race -timeout=20m -count=1 -p 2 -run "$pattern" "$worker"
  done
)

case "${1:-}" in
  --self-test) self_test ;;
  '') main ;;
  *) echo "usage: $0 [--self-test]" >&2; exit 2 ;;
esac
