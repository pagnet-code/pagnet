#!/usr/bin/env bash
# Keep large packages' aggregate fixture time within each 20m process budget.
set -euo pipefail

sharded_packages=(./internal/daemon ./internal/sessionworker)
search_skip='TestSearchPerformanceTargets|TestSearchAdversarialWorstCase'

# Discovery uses the same race build constraints as execution. Keep Go's build
# diagnostics on stderr, and reject empty/duplicate inventories before any run.
discover_tests() {
  local package=$1 dir=$2
  if ! go test -race -timeout=20m -list '^(Test|Example|Fuzz)' "$package" > "$dir/discovery"; then
    cat "$dir/discovery" >&2
    echo "$package test discovery failed" >&2
    return 1
  fi
  LC_ALL=C awk '/^(Test|Example|Fuzz)[^[:space:]]*$/ { print }' "$dir/discovery" | LC_ALL=C sort > "$dir/tests"
  if [[ $(wc -l < "$dir/tests") -lt 4 ]]; then
    echo "$package discovery must produce at least four tests" >&2
    return 1
  fi
  if [[ -n $(uniq -d "$dir/tests") ]]; then
    echo "$package discovery contains duplicate names" >&2
    return 1
  fi
}

partition_tests() {
  local package=$1 dir=$2 shard
  # Round-robin over the sorted inventory is deterministic and differs in
  # size by at most one. Exact top-level anchors also include every subtest.
  for shard in 0 1 2 3; do
    awk -v shard="$shard" '(NR - 1) % 4 == shard' "$dir/tests" > "$dir/shard-$shard"
    if [[ ! -s "$dir/shard-$shard" ]]; then
      echo "$package shard $shard is empty" >&2
      return 1
    fi
  done
}

self_test() (
  local dir shard pattern package
  dir=$(mktemp -d)
  trap 'rm -rf "$dir"' EXIT
  for package in "${sharded_packages[@]}"; do
    # Deliberately unsorted, with all three kinds and one similarly named test.
    go() { [[ ${!#} == "$package" ]] || return 1; printf '%s\n' TestZulu FuzzSeed ExampleOutput TestAlpha TestAlphaExtra TestBeta TestGamma TestDelta TestEpsilon 'ok example 0.001s'; }
    discover_tests "$package" "$dir"
    partition_tests "$package" "$dir"
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
    partition_tests "$package" "$dir"
    cmp "$dir/first" "$dir/shard-0"
    go() { return 1; }
    if discover_tests "$package" "$dir" 2>/dev/null; then echo 'failed discovery accepted' >&2; exit 1; fi
    go() { printf 'ok example 0.001s\n'; }
    if discover_tests "$package" "$dir" 2>/dev/null; then echo 'empty discovery accepted' >&2; exit 1; fi
    go() { printf '%s\n' TestA TestA TestB TestC; }
    if discover_tests "$package" "$dir" 2>/dev/null; then echo 'duplicate discovery accepted' >&2; exit 1; fi
    printf 'TestOnly\n' > "$dir/tests"
    if partition_tests "$package" "$dir" 2>/dev/null; then echo 'empty shard accepted' >&2; exit 1; fi
  done
  echo 'race runner self-test passed (partition, determinism, failed/empty/duplicate discovery, empty shard)'
)

main() (
  local dir package package_dir shard pattern
  local -a packages
  cd "$(dirname "${BASH_SOURCE[0]}")/.."
  dir=$(mktemp -d)
  trap 'rm -rf "$dir"' EXIT
  for package in "${sharded_packages[@]}"; do
    package_dir="$dir/${package##*/}"
    mkdir "$package_dir"
    discover_tests "$package" "$package_dir"
    partition_tests "$package" "$package_dir"
  done
  go list "${sharded_packages[@]}" > "$dir/sharded-packages"
  go list ./... > "$dir/packages"
  mapfile -t packages < <(awk 'NR == FNR { sharded[$0] = 1; next } !($0 in sharded)' "$dir/sharded-packages" "$dir/packages")
  if [[ ${#packages[@]} -eq 0 ]]; then
    echo 'no packages found outside sharded packages' >&2
    exit 1
  fi
  echo "Race suite: ${#packages[@]} other packages; daemon and sessionworker each in four sequential shards"
  go test -race -timeout=20m -count=1 -p 2 -skip "$search_skip" "${packages[@]}"
  # JSON reports each test's start, output, result and elapsed time,
  # including the active test and its diagnostics if a shard times out.
  for package in "${sharded_packages[@]}"; do
    package_dir="$dir/${package##*/}"
    for shard in 0 1 2 3; do
      pattern="^($(paste -sd '|' "$package_dir/shard-$shard"))$"
      echo "$package race shard $((shard + 1))/4 ($(wc -l < "$package_dir/shard-$shard") tests): $pattern"
      go test -json -race -timeout=20m -count=1 -p 2 -skip "$search_skip" -run "$pattern" "$package"
    done
  done
)

case "${1:-}" in
  --self-test) self_test ;;
  '') main ;;
  *) echo "usage: $0 [--self-test]" >&2; exit 2 ;;
esac
