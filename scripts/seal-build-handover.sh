#!/usr/bin/env bash
# Bau-Job: packt das gebaute Bundle und verschluesselt es an den oeffentlichen Uebergabe-Schluessel.
# Im neuen Ausgabe-Ordner liegt danach genau der Umschlag; sein SHA-256 geht als Ausgabe `sha256` an den Job.
#
# Aufruf: seal-build-handover.sh <App.app> <neuer-ausgabe-ordner>
# Braucht RUNNER_TEMP und GITHUB_OUTPUT. Exit 0 = Umschlag liegt bereit, sonst abgewiesen.
set -euo pipefail
umask 077
[ "$#" -eq 2 ] || { echo "usage: seal-build-handover.sh <App.app> <new-output-directory>" >&2; exit 64; }
app=$1
out=$2
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
key_file="$here/../config/release-handover-public-key.b64"
[ -f "$key_file" ] && [ ! -L "$key_file" ] && [ -s "$key_file" ] || { echo "::error::Oeffentlicher Uebergabe-Schluessel fehlt."; exit 1; }
key=$(tr -d '[:space:]' < "$key_file")
plain=$(mktemp -d "${RUNNER_TEMP:?RUNNER_TEMP is required}/handover-plain.XXXXXX")
trap 'rm -rf "$plain"' EXIT
mkdir "$out"
python3 -I "$here/pack-app-bundle.py" "$app" "$plain/unsigned.zip" > /dev/null
node "$here/encrypt-confidential-log.mjs" "$plain/unsigned.zip" "$out/unsigned.zip.envelope.json" "$key" > /dev/null
digest=$(python3 -I -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$out/unsigned.zip.envelope.json")
echo "sha256=$digest" >> "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
