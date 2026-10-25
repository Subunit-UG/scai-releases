#!/usr/bin/env bash
# Execute a command without copying its potentially source-bearing output into a
# public GitHub Actions log. The temporary log exists only for the lifetime of
# this process and is removed on both success and failure.

set -u
set +x

if [ "$#" -lt 2 ]; then
  echo "usage: run-confidential.sh <label> <command> [args...]" >&2
  exit 64
fi

label=$1
shift

case "$label" in
  *[!A-Za-z0-9._-]*|'')
    echo "invalid confidential command label" >&2
    exit 64
    ;;
esac

temp_root=${RUNNER_TEMP:-${TMPDIR:-/tmp}}
log_dir="$temp_root/scai-confidential-logs"
mkdir -p "$log_dir"
log_file="$log_dir/${label}-$$.log"
diagnostic_path=${SCAI_ENCRYPTED_DIAGNOSTIC_PATH:-}
diagnostic_key=${SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64:-}

if { [ -n "$diagnostic_path" ] && [ -z "$diagnostic_key" ]; } \
  || { [ -z "$diagnostic_path" ] && [ -n "$diagnostic_key" ]; }; then
  echo "encrypted diagnostic path and public key must be configured together" >&2
  exit 64
fi
if [ -n "$diagnostic_path" ]; then
  case "$diagnostic_path" in
    "$temp_root"/*) ;;
    *) echo "encrypted diagnostic path must stay below RUNNER_TEMP" >&2; exit 64 ;;
  esac
  case "$diagnostic_path" in
    *.json) ;;
    *) echo "encrypted diagnostic path must name a .json envelope" >&2; exit 64 ;;
  esac
  case "$diagnostic_path" in
    */../*|*/./*) echo "encrypted diagnostic path must stay below RUNNER_TEMP" >&2; exit 64 ;;
  esac
  if [ -L "$diagnostic_path" ]; then
    echo "encrypted diagnostic path must not be a symlink" >&2
    exit 64
  fi
fi

sealed_dir=''
# shellcheck disable=SC2329 # invoked by trap
cleanup() {
  rm -f "$log_file"
  if [ -n "$sealed_dir" ]; then
    rm -f "$sealed_dir/envelope"
    rmdir "$sealed_dir"
  fi
}
trap cleanup EXIT HUP INT TERM

"$@" >"$log_file" 2>&1
status=$?

if command -v sha256sum >/dev/null 2>&1; then
  digest=$(sha256sum <"$log_file" | cut -d ' ' -f 1)
else
  digest=$(shasum -a 256 <"$log_file" | cut -d ' ' -f 1)
fi
bytes=$(wc -c <"$log_file" | tr -d '[:space:]')

if [ "$status" -eq 0 ]; then
  echo "PASS $label (private-log-sha256=$digest, bytes=$bytes)"
else
  if [ -n "$diagnostic_path" ]; then
    # Seal privately first, then publish via an atomic no-replace hard link.
    # Nested wrappers and repeated labels must retain every failure envelope.
    sealed_dir=$(mktemp -d "$temp_root/scai-sealed.XXXXXX") || exit 70
    if ! node "$(dirname -- "$0")/encrypt-confidential-log.mjs" \
      "$log_file" "$sealed_dir/envelope" "$diagnostic_key"; then
      echo "::error title=Encrypted diagnostic unavailable::Failed to seal $label; private output remains suppressed and no diagnostic may be uploaded."
      exit 70
    fi
    if ! node - "$sealed_dir/envelope" "$diagnostic_path" "$label" <<'NODE'
const { linkSync } = require('node:fs');
const [sealed, base, label] = process.argv.slice(2);
for (let index = 0; ; index += 1) {
  // Keep the encrypted suffix discoverable by a step-scoped *.encrypted.json
  // upload, while preserving legacy .json collision names byte-for-byte.
  const suffix = base.endsWith('.encrypted.json') ? '.encrypted.json' : '.json';
  const output = index === 0 ? base : `${base.slice(0, -suffix.length)}-${label}-${index}${suffix}`;
  try { linkSync(sealed, output); break; }
  catch (error) { if (error.code !== 'EEXIST') process.exit(70); }
}
NODE
    then
      echo "::error title=Encrypted diagnostic unavailable::Failed to retain $label; private output remains suppressed."
      exit 70
    fi
    echo "PASS $label: private failure log sealed to the supplied one-time public key."
  fi
  echo "::error title=Confidential check failed::$label failed with exit $status; private output suppressed (sha256=$digest, bytes=$bytes). Reproduce at the pinned source SHA in the private worktree."
fi

exit "$status"
