#!/usr/bin/env bash
# publish-registry.sh <manifest.json> <commit message> [<bundle.sigstore.json>]
#
# Adds one versioned sensor manifest (and its Sigstore signature bundle, which
# the Hub requires) to the registry-pages branch, rebuilds index.json and
# pushes. Called by the publish-sensor-registry workflow from
# the repository checkout.
#
# Several sensor tags pushed together run as parallel jobs that all write to
# registry-pages. A GitHub concurrency group would cancel all but the newest
# queued job, so instead each job retries: fetch the branch fresh, re-apply
# its manifest, rebuild the index, push; on a rejected push, back off and
# start again. The first job to push creates the branch; the others see it on
# their next attempt.
#
# Requirements: git, jq. REGISTRY_INDEX_SCRIPT may point at the index builder
# (default: scripts/build-registry-index.sh, copied before the checkout
# switches branches).

set -euo pipefail

MANIFEST="${1:?usage: publish-registry.sh <manifest.json> <message>}"
MESSAGE="${2:?usage: publish-registry.sh <manifest.json> <message>}"
BUNDLE="${3:-}"
BRANCH="${REGISTRY_BRANCH:-registry-pages}"
ATTEMPTS="${REGISTRY_ATTEMPTS:-10}"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cp "$MANIFEST" "$WORK/manifest.json"
if [ -n "$BUNDLE" ]; then
  cp "$BUNDLE" "$WORK/bundle.json"
fi
cp "${REGISTRY_INDEX_SCRIPT:-scripts/build-registry-index.sh}" "$WORK/build-index.sh"
chmod +x "$WORK/build-index.sh"
NAME=$(basename "$MANIFEST")

for attempt in $(seq 1 "$ATTEMPTS"); do
  if git ls-remote --exit-code --heads origin "$BRANCH" >/dev/null 2>&1; then
    git fetch -q origin "$BRANCH"
    git checkout -q -f -B "$BRANCH" FETCH_HEAD
    git clean -q -fdx
  else
    git checkout -q -f --orphan "$BRANCH"
    git rm -q -rf . >/dev/null 2>&1 || true
    git clean -q -fdx
    echo "# TrueSignal Sensor Registry" > README.md
    git add README.md
    git commit -q -m "Initialize $BRANCH branch"
  fi

  if [ -e "$NAME" ]; then
    # Released manifests are immutable, like their tags; a re-run of the same
    # release is a no-op.
    if cmp -s "$WORK/manifest.json" "$NAME"; then
      echo "✅ $NAME already published."
      exit 0
    fi
    echo "❌ $NAME already exists in $BRANCH with different content. Bump the version instead." >&2
    exit 1
  fi
  cp "$WORK/manifest.json" "$NAME"
  if [ -n "$BUNDLE" ]; then
    cp "$WORK/bundle.json" "$NAME.sigstore.json"
    git add "$NAME.sigstore.json"
  fi
  "$WORK/build-index.sh" >/dev/null
  git add "$NAME" index.json
  git commit -q -m "$MESSAGE"

  if git push -q origin "$BRANCH" 2>/dev/null; then
    echo "✅ Published $NAME (attempt $attempt)."
    exit 0
  fi
  delay=$(( attempt * 3 + RANDOM % 5 ))
  echo "↻ Push to $BRANCH rejected (attempt $attempt); retrying in ${delay}s."
  sleep "$delay"
done

echo "❌ Could not push to $BRANCH after $ATTEMPTS attempts." >&2
exit 1
