#!/bin/sh
#
# Use this script to run your program LOCALLY.
#
# Note: Changing this script WILL NOT affect how CodeCrafters runs your program.
#
# Learn more: https://codecrafters.io/program-interface

set -e # Exit early if any commands fail

# Copied from .codecrafters/run.sh
#
# - Edit this to change how your program runs locally
# - Edit .codecrafters/run.sh to change how your program runs remotely
PROJECT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
if [ "$(basename "$PROJECT_DIR")" = ".codecrafters" ]; then
  PROJECT_DIR="$(dirname "$PROJECT_DIR")"
fi
PYTHONSAFEPATH=1 PYTHONPATH="$PROJECT_DIR" exec uv run \
  --project "$PROJECT_DIR" --quiet -m app.main "$@"
