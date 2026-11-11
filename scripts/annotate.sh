#!/usr/bin/env bash
# For action.yml: turn the `warning: ` and `error: ` lines of check's stderr
# (the file $1) into workflow annotations. The command is fixed here and
# the rest of the line is its message, so the line's own text cannot start
# a command; a carriage return could end the line early, so it is dropped.
set -euo pipefail
while IFS= read -r line || [ -n "$line" ]; do
  line=${line//$'\r'/}
  case "$line" in
    "warning: "*) echo "::warning::${line#warning: }" ;;
    "error: "*) echo "::error::${line#error: }" ;;
  esac
done < "$1"
