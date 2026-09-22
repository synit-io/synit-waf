#!/bin/bash
# Generates GitHub release notes from the git history between the previous
# release tag and the released tag. The commit history is the changelog:
# every commit follows Conventional Commits, and this script groups the
# subjects by type. Usage: scripts/release-notes.sh <tag> [previous-tag]
set -euo pipefail

tag="${1:?usage: release-notes.sh <tag> [previous-tag]}"
previous="${2:-}"

git rev-parse -q --verify "refs/tags/$tag" >/dev/null || { echo "unknown tag: $tag" >&2; exit 1; }

if [ -z "$previous" ]; then
  # The newest tag that is an ancestor of the released tag, excluding itself.
  previous=$(git describe --tags --abbrev=0 --exclude "$tag" "$tag^" 2>/dev/null || true)
fi

if [ -n "$previous" ]; then
  range="$previous..$tag"
else
  range="$tag"
fi

# Sections in display order: type prefix -> heading.
sections=(
  "security|Security"
  "feat|Features"
  "fix|Fixes"
  "perf|Performance"
  "refactor|Refactoring"
  "docs|Documentation"
  "build|Build and dependencies"
  "ci|Continuous integration"
  "test|Tests"
  "revert|Reverts"
  "chore|Maintenance"
)

commits=$(git log --no-merges --format='%H%x1f%s%x1f%b%x1e' "$range")

# emit_section TYPE HEADING: prints the commits whose subject starts with the
# type, with or without a scope, and marks breaking changes.
emit_section() {
  local type="$1" heading="$2" lines=""
  while IFS=$'\x1f' read -r -d $'\x1e' hash subject body; do
    hash=${hash#$'\n'}
    [ -n "$hash" ] || continue
    local pattern="^${type}(\\([^)]*\\))?(!)?: (.*)$"
    if [[ "$subject" =~ $pattern ]]; then
      local scope="${BASH_REMATCH[1]}" bang="${BASH_REMATCH[2]}" text="${BASH_REMATCH[3]}"
      local marker=""
      if [ -n "$bang" ] || grep -q '^BREAKING CHANGE:' <<<"$body"; then
        marker="**Breaking:** "
      fi
      scope="${scope#(}"; scope="${scope%)}"
      if [ -n "$scope" ]; then
        lines+="- ${marker}${scope}: ${text} (${hash:0:7})"$'\n'
      else
        lines+="- ${marker}${text} (${hash:0:7})"$'\n'
      fi
    fi
  done <<<"$commits"
  if [ -n "$lines" ]; then
    printf '## %s\n\n%s\n' "$heading" "$lines"
  fi
}

# Commits that follow no known type are listed so nothing is lost.
emit_other() {
  local lines="" known
  known=$(printf '%s\n' "${sections[@]}" | cut -d'|' -f1 | paste -sd'|' -)
  while IFS=$'\x1f' read -r -d $'\x1e' hash subject body; do
    hash=${hash#$'\n'}
    [ -n "$hash" ] || continue
    local pattern="^(${known})(\\([^)]*\\))?(!)?: "
    if ! [[ "$subject" =~ $pattern ]]; then
      lines+="- ${subject} (${hash:0:7})"$'\n'
    fi
  done <<<"$commits"
  if [ -n "$lines" ]; then
    printf '## Other changes\n\n%s\n' "$lines"
  fi
}

for entry in "${sections[@]}"; do
  emit_section "${entry%%|*}" "${entry#*|}"
done
emit_other

# The backticks are Markdown code spans in the release notes, not command
# substitution; single quotes keep them literal on purpose.
# shellcheck disable=SC2016
if [ -n "$previous" ]; then
  printf 'Full history: `git log %s..%s`\n' "$previous" "$tag"
else
  printf 'First release. Full history: `git log %s`\n' "$tag"
fi
