#!/usr/bin/env bash
# Deploy-Key-Wächter (Vorfall 2026-11-08-ci-deploy-keys-verschwunden): Kann der Schlüssel aus genau einem
# *_SOURCE_DEPLOY_KEY-Secret sein privates Quell-Repo noch lesen? Am 08.11. verschwanden die öffentlichen Gegenstücke in
# 9 von 10 Repos still; aufgefallen ist es erst beim nächsten Gate. Dieser Probelauf liest nur die Ref-Liste
# (git ls-remote), gibt keine Refs, keine Transportausgabe und nie Schlüsselmaterial aus, nur PASS/FAIL.
#   probe-deploy-key.sh <secret-name> <repository>     Schlüssel kommt in SOURCE_DEPLOY_KEY (Umgebung).
# Exit: 0 lesbar · 1 nicht lesbar · 64 Aufruf/Allowlist · 65 Schlüssel fehlt · 68 GitHub-Hostschlüssel falsch.

set -euo pipefail
set +x
umask 077

if [ "$#" -ne 2 ]; then
  echo "usage: probe-deploy-key.sh <secret-name> <repository>" >&2
  exit 64
fi
secret=$1
repository=$2

# Feste Zuordnung Secret → Repo (wie scripts/checkout-private-source.sh); nichts aus der Eingabe wird URL.
case "$secret:$repository" in
  SOURCE_DEPLOY_KEY:Subunit-UG/scai-app) ;;
  AUTH_SOURCE_DEPLOY_KEY:Subunit-UG/infra-auth) ;;
  U1_CHAT_SOURCE_DEPLOY_KEY:Subunit-UG/infra-u1-chat) ;;
  ATLAS_SOURCE_DEPLOY_KEY:Subunit-UG/infra-atlas) ;;
  ECHO_SOURCE_DEPLOY_KEY:Subunit-UG/echo-server) ;;
  NOTCH_SOURCE_DEPLOY_KEY:Subunit-UG/mac-notch) ;;
  ZENTRALE_SOURCE_DEPLOY_KEY:Subunit-UG/notch-zentrale) ;;
  SONAR_SOURCE_DEPLOY_KEY:Subunit-UG/sonar-tauri) ;;
  BRIDGE_SOURCE_DEPLOY_KEY:Subunit-UG/bridge-tauri) ;;
  TRACE_SOURCE_DEPLOY_KEY:Subunit-UG/trace-tauri) ;;
  *)
    echo "secret/repository is not allowlisted" >&2
    exit 64
    ;;
esac

if [ -z "${SOURCE_DEPLOY_KEY:-}" ]; then
  echo "::error title=Deploy-Key fehlt::$secret ist leer oder nicht gesetzt."
  exit 65
fi

temp_root=${RUNNER_TEMP:?RUNNER_TEMP is required}
github_ed25519_fingerprint="SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU"
credential_dir=''
# shellcheck disable=SC2329 # invoked by trap
cleanup() {
  if [ -n "$credential_dir" ]; then
    rm -f "$credential_dir/key" "$credential_dir/known_hosts"
    rmdir "$credential_dir"
  fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

credential_dir=$(mktemp -d "$temp_root/scai-key-probe.XXXXXX")
key_file="$credential_dir/key"
known_hosts="$credential_dir/known_hosts"
printf '%s\n' "$SOURCE_DEPLOY_KEY" > "$key_file"
chmod 600 "$key_file"
unset SOURCE_DEPLOY_KEY
{ ssh-keyscan -t ed25519 github.com 2>/dev/null || true; } | { grep -v '^#' || true; } > "$known_hosts"
chmod 600 "$known_hosts"
host_key_count=$(wc -l < "$known_hosts" | tr -d '[:space:]')
actual_fingerprint=$(ssh-keygen -lf "$known_hosts" -E sha256 | awk 'NR == 1 { print $2 }')
if [ "$host_key_count" != "1" ] || [ "$actual_fingerprint" != "$github_ed25519_fingerprint" ]; then
  echo "::error title=GitHub host verification failed::The pinned GitHub ED25519 host fingerprint did not match."
  exit 68
fi

printf -v ssh_command '%q -i %q -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=%q -o BatchMode=yes -o ConnectTimeout=20' \
  ssh "$key_file" "$known_hosts"
if GIT_SSH_COMMAND="$ssh_command" GIT_TERMINAL_PROMPT=0 git ls-remote --heads "git@github.com:$repository.git" >/dev/null 2>&1; then
  echo "PASS deploy-key $secret → $repository lesbar"
  exit 0
fi
echo "::error title=Deploy-Key ungültig::$secret kann $repository nicht lesen (Schlüssel fehlt im Repo oder wurde entfernt)."
exit 1
