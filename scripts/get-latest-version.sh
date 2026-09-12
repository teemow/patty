#!/bin/bash
set -euo pipefail

git fetch origin --tags --force >/dev/null 2>&1 || true

LATEST_TAG=$(git tag --sort=-version:refname | head -n1 || true)

if [ -z "$LATEST_TAG" ]; then
  LATEST_TAG="v0.0.0"
fi

echo "${LATEST_TAG#v}"
