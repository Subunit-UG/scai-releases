#!/usr/bin/env bash
# Signier-Job: laedt die Signier-Identitaet in einen eigenen, temporaeren Schluesselbund und nennt dessen Pfad
# den folgenden Schritten ueber die Umgebung. Die Zertifikatsdatei entsteht mit engen Rechten und verschwindet
# in jedem Ausgang. Der Pfad des Schluesselbunds steht vor dem ersten Schreiben fest, damit das Aufraeumen ihn findet.
#
# Aufruf: load-signing-identity.sh
# Umgebung: APPLE_CERTIFICATE (PKCS#12, base64), APPLE_CERTIFICATE_PASSWORD, KEYCHAIN_ENV (Name der Variablen
# fuer den Pfad, z. B. NOTCH_KEYCHAIN), RUNNER_TEMP, GITHUB_ENV. Exit 0 = geladen, sonst abgewiesen.
set -euo pipefail
set +x
umask 077
[ "$#" -eq 0 ] || { echo "usage: load-signing-identity.sh" >&2; exit 64; }
[[ "${KEYCHAIN_ENV:-}" =~ ^[A-Z]+_KEYCHAIN$ ]] || { echo "usage: KEYCHAIN_ENV=<NAME>_KEYCHAIN load-signing-identity.sh" >&2; exit 64; }
[ -n "${APPLE_CERTIFICATE:-}" ] || { echo "::error::Signier-Zertifikat fehlt."; exit 1; }
temp=${RUNNER_TEMP:?RUNNER_TEMP is required}
p12="$temp/signing-identity.p12"
keychain="$temp/signing-identity.keychain-db"
trap 'rm -f "$p12"' EXIT
echo "$KEYCHAIN_ENV=$keychain" >> "${GITHUB_ENV:?GITHUB_ENV is required}"
printf '%s' "$APPLE_CERTIFICATE" | base64 --decode > "$p12"
keychain_password="$(openssl rand -hex 24)"
security create-keychain -p "$keychain_password" "$keychain"
security set-keychain-settings -lut 1800 "$keychain"
security unlock-keychain -p "$keychain_password" "$keychain"
security import "$p12" -k "$keychain" -P "${APPLE_CERTIFICATE_PASSWORD:-}" -T /usr/bin/codesign > /dev/null
rm -f "$p12"
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$keychain_password" "$keychain" > /dev/null
# Bestehende Schluesselbunde bleiben in der Suchliste; Pfade zeilenweise, ohne Wortteilung.
existing=()
while IFS= read -r line; do
  line="${line#"${line%%[![:space:]]*}"}"; line="${line#\"}"; line="${line%\"}"
  [ -n "$line" ] && existing+=("$line")
done < <(security list-keychains -d user)
security list-keychains -d user -s "$keychain" ${existing[@]+"${existing[@]}"}
# Nur die Anzahl: der Name der Identitaet steht nie im Protokoll. Ohne gueltige Identitaet ist der Schluesselbund wertlos.
count=$(security find-identity -v -p codesigning "$keychain" | sed -n 's/^ *\([0-9][0-9]*\) valid identities found$/\1/p')
[[ "$count" =~ ^[1-9][0-9]*$ ]] || { echo "::error::Im Schluesselbund liegt keine gueltige Signier-Identitaet."; exit 1; }
echo "PASS signing-identity-loaded"
