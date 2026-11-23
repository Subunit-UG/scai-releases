#!/usr/bin/env bash
# Prueft die Eingaben eines signierten Baus, bevor Quelltext oder ein Geheimnis geladen wird:
# Commit-Pin, Version, Signierweg, Einmal-Empfaengerschluessel und oeffentlicher Uebergabe-Schluessel.
#
# Aufruf: check-signed-build-request.sh notch|charge
# Eingaben aus der Umgebung: SOURCE_SHA, EXPECTED_VERSION, RECIPIENT_PUBLIC_KEY_BASE64,
# fuer notch zusaetzlich SIGNING, ZENTRALE_SHA, ZENTRALE_VERSION.
# Exit 0 = in Ordnung, 1 = abgewiesen, 64 = Aufruf.
set -euo pipefail
product=${1:-}
[ "$#" -eq 1 ] || product=""
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

fail() { echo "::error::$1"; exit 1; }
is_sha() { [[ "$1" =~ ^[0-9a-f]{40}$ ]]; }
is_version() { [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; }
is_rsa_key() {
  KEY_BASE64="$1" node -e 'try{const k=require("node:crypto").createPublicKey(Buffer.from(process.env.KEY_BASE64,"base64").toString("utf8"));process.exit(k.asymmetricKeyType==="rsa"&&k.asymmetricKeyDetails.modulusLength>=3072?0:1)}catch{process.exit(1)}'
}

case "$product" in
  notch|charge) ;;
  *) echo "usage: check-signed-build-request.sh notch|charge" >&2; exit 64 ;;
esac

is_sha "${SOURCE_SHA:-}" || fail "Quell-Pin ist kein vollstaendiger Commit-SHA."
is_version "${EXPECTED_VERSION:-}" || fail "Erwartete Version hat nicht die Form x.y.z."
way=""
if [ "$product" = notch ]; then
  case "${SIGNING:-}" in
    developer-id)
      # Der Store-Weg liefert die Zentrale immer mit: beide Pins sind Pflicht.
      is_sha "${ZENTRALE_SHA:-}" || fail "Pin der Zentrale ist kein vollstaendiger Commit-SHA."
      is_version "${ZENTRALE_VERSION:-}" || fail "Version der Zentrale hat nicht die Form x.y.z."
      ;;
    development)
      [ -z "${ZENTRALE_SHA:-}${ZENTRALE_VERSION:-}" ] || fail "Die Zentrale wird nur im developer-id-Weg mitgebaut."
      ;;
    *) fail "Unbekannter Signierweg." ;;
  esac
  way=" signing=$SIGNING zentrale-sha=${ZENTRALE_SHA:-none}"
fi
is_rsa_key "${RECIPIENT_PUBLIC_KEY_BASE64:-}" || fail "Empfaengerschluessel ist kein RSA-Schluessel mit mindestens 3072 Bit."
key_file="$here/../config/release-handover-public-key.b64"
[ -f "$key_file" ] && [ ! -L "$key_file" ] && [ -s "$key_file" ] || fail "Oeffentlicher Uebergabe-Schluessel fehlt."
is_rsa_key "$(tr -d '[:space:]' < "$key_file")" || fail "Oeffentlicher Uebergabe-Schluessel ist kein RSA-Schluessel mit mindestens 3072 Bit."
echo "PASS $product-build-request (source-sha=$SOURCE_SHA version=$EXPECTED_VERSION$way)"
