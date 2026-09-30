#!/bin/sh
# One version policy for local builds, release assets, and image builds.
# Rolling `dev` tags never identify a release. Only stable SemVer tags
# anchor development versions; metadata retains the exact source revision.
set -eu

validate() {
 printf '%s\n' "$1" | LC_ALL=C awk '
  NR != 1 { exit 1 }
  /^(v)?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$/ {
   version=$0; sub(/^v/, "", version); split(version, metadata, "[+]")
   prerelease=metadata[1]; sub(/^[0-9]+\.[0-9]+\.[0-9]+/, "", prerelease)
   sub(/^-/, "", prerelease); count=split(prerelease, identifiers, "[.]")
   for (i=1; i<=count; i++) if (identifiers[i] ~ /^0[0-9]+$/) exit 1
   valid=1
  }
  END { if (!valid) exit 1 }
 '
}

case "${1:-}" in
 --validate)
  [ "$#" -eq 2 ] || { echo 'usage: version.sh --validate VERSION' >&2; exit 1; }
  validate "$2" || { echo "invalid SemVer version: $2" >&2; exit 1; }
  printf '%s\n' "$2"
  exit 0
 ;;
 --stable)
  [ "$#" -eq 2 ] || { echo 'usage: version.sh --stable VERSION' >&2; exit 1; }
  validate "$2" && case "$2" in v*.*.*) case "$2" in *-*|*+*) false;; *) true;; esac;; *) false;; esac || {
   echo "release tags must be stable SemVer (vMAJOR.MINOR.PATCH): $2" >&2; exit 1;
  }
  printf '%s\n' "$2"
  exit 0
 ;;
 --*) echo 'usage: version.sh [GIT_DIRECTORY] | --validate VERSION | --stable VERSION' >&2; exit 1 ;;
esac

repo=${1:-.}
[ "$#" -le 1 ] || { echo 'usage: version.sh [GIT_DIRECTORY]' >&2; exit 1; }
# No source history is a source build, never a bare hash or a release claim.
if ! git -C "$repo" rev-parse --verify HEAD >/dev/null 2>&1; then
 printf '%s\n' 'v0.0.0-dev.0+source'
 exit 0
fi
sha=$(git -C "$repo" rev-parse --short=12 HEAD)
dirty=
if [ -n "$(git -C "$repo" status --porcelain --untracked-files=normal)" ]; then dirty=.dirty; fi
# Pass exact validated tags as describe matches, ignoring dev and arbitrary
# tag names. This also prevents a malformed v* tag from shadowing a release.
tags=$(git -C "$repo" tag --merged HEAD | LC_ALL=C awk '/^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/')
if [ -n "$tags" ]; then
 set --
 for tag in $tags; do set -- "$@" --match "$tag"; done
 described=$(git -C "$repo" describe --tags --long --abbrev=12 "$@" HEAD)
 base=${described%-*}; base=${base%-*}
 distance=${described#"$base"-}; distance=${distance%-*}
 if [ "$distance" -eq 0 ] && [ -z "$dirty" ]; then
  printf '%s\n' "$base"
 else
  printf '%s-dev.%s+g%s%s\n' "$base" "$distance" "$sha" "$dirty"
 fi
else
 distance=$(git -C "$repo" rev-list --count HEAD)
 printf 'v0.0.0-dev.%s+g%s%s\n' "$distance" "$sha" "$dirty"
fi
