#!/usr/bin/env bash
# One-time setup so git uses the repo's shared hooks.
set -euo pipefail
cd "$(dirname "$0")/.."
git config core.hooksPath .githooks
echo "core.hooksPath -> .githooks (pre-push gate enabled)"
