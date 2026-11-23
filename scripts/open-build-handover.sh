#!/usr/bin/env bash
# Signier-Job: prueft, dass im Uebergabe-Ordner genau der Umschlag liegt, den der Bau-Job gemeldet hat,
# und oeffnet ihn erst danach. Das Ergebnis ist <arbeitsordner>/unsigned.zip in einem neuen Ordner.
#
# Aufruf: open-build-handover.sh <uebergabe-ordner> <neuer-arbeitsordner>
# Umgebung: RELEASE_HANDOVER_PRIVATE_KEY (PEM), HANDOVER_SHA256 (Ausgabe des Bau-Jobs), RUNNER_TEMP.
# Exit 0 = geoeffnet, sonst abgewiesen.
set -euo pipefail
set +x
umask 077
[ "$#" -eq 2 ] || { echo "usage: open-build-handover.sh <handover-directory> <new-work-directory>" >&2; exit 64; }
dir=$1
work=$2
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
fail() { echo "::error::$1"; exit 1; }

[ -n "${RELEASE_HANDOVER_PRIVATE_KEY:-}" ] || fail "Uebergabe-Schluessel fehlt."
envelope="$dir/unsigned.zip.envelope.json"
# Genau der Umschlag, den der Bau-Job gemeldet hat: erst der Digest, dann das Oeffnen.
[[ "${HANDOVER_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] || fail "Digest des Umschlags fehlt."
[ -d "$dir" ] && [ ! -L "$dir" ] || fail "Uebergabe fehlt."
[ "$(find "$dir" -mindepth 1 | wc -l | tr -d ' ')" = 1 ] && [ -f "$envelope" ] && [ ! -L "$envelope" ] || fail "Uebergabe enthaelt nicht genau den Umschlag."
digest=$(python3 -I -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$envelope")
[ "$digest" = "$HANDOVER_SHA256" ] || fail "Umschlag passt nicht zum Digest des Bau-Jobs."
mkdir "$work"
key=$(mktemp "${RUNNER_TEMP:?RUNNER_TEMP is required}/handover-key.XXXXXX")
trap 'rm -f "$key"' EXIT
printf '%s\n' "$RELEASE_HANDOVER_PRIVATE_KEY" > "$key"
# Fehlertext von Node kann Inhalt des Umschlags zitieren: nur die feste Meldung erreicht das Protokoll.
node "$here/decrypt-confidential-envelope.mjs" "$envelope" "$work/unsigned.zip" "$key" > /dev/null 2>&1 \
  || { rm -f "$work/unsigned.zip"; fail "Umschlag laesst sich nicht oeffnen."; }
rm -f "$key"
echo "PASS handover-opened"
