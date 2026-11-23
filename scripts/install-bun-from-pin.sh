#!/usr/bin/env bash
# Richtet Bun genau in der Version ein, die der Pin der privaten Quelle nennt (Format wie
# verify-bun-runtime-pin.sh: genau eine Zeile `VERSION = "x.y.z"`), aber nur, wenn diese Version in
# config/bun-runtimes.json des Gate-Checkouts mit Zip- und Binary-Hash zugelassen ist.
# Warum: vorher legte jeder Workflow die Bun-Version selbst fest (setup-bun vor dem privaten Checkout).
# Ein Bun-Wechsel musste dadurch in allen Quellen und Workflows gleichzeitig passieren. Jetzt gilt der
# Quell-Pin, begrenzt durch die zentrale Liste. Es läuft keine fremde Action neben privatem Code:
# nur dieses Skript, curl, unzip und sha256sum. Aus der Quelle wird nichts ausgegeben.
# Aufruf: install-bun-from-pin.sh <pin-datei> [--zip <lokale-datei>]   (--zip nur für Tests)
set -euo pipefail

usage() { echo "usage: install-bun-from-pin.sh <pin-file> [--zip <file>]" >&2; exit 64; }
[ "$#" -eq 1 ] || [ "$#" -eq 3 ] || usage
pin_file=$1; local_zip=""
if [ "$#" -eq 3 ]; then [ "$2" = "--zip" ] || usage; local_zip=$3; fi

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
allow="$here/../config/bun-runtimes.json"
[ -f "$allow" ] && [ ! -L "$allow" ] || { echo "bun allowlist missing" >&2; exit 65; }
[ -f "$pin_file" ] && [ ! -L "$pin_file" ] || { echo "bun pin file missing" >&2; exit 65; }

matches=$(grep -cE '^VERSION = "[0-9]+\.[0-9]+\.[0-9]+"$' "$pin_file" || true)
[ "$matches" = "1" ] || { echo "bun pin must appear exactly once" >&2; exit 65; }
version=$(grep -E '^VERSION = "[0-9]+\.[0-9]+\.[0-9]+"$' "$pin_file" | sed -E 's/^VERSION = "([0-9.]+)"$/\1/')

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) platform=linux-x64; asset=bun-linux-x64 ;;
  *) echo "unsupported runner platform" >&2; exit 65 ;;
esac

read -r zip_sha bun_sha < <(python3 -I -c '
import json, re, sys
data = json.load(open(sys.argv[1]))
entry = data.get(sys.argv[2], {}).get(sys.argv[3])
if not isinstance(entry, dict): sys.exit(3)
z, b = entry.get("zip_sha256", ""), entry.get("bun_sha256", "")
if not (re.fullmatch(r"[0-9a-f]{64}", z) and re.fullmatch(r"[0-9a-f]{64}", b)): sys.exit(4)
print(z, b)' "$allow" "$platform" "$version") || { echo "bun $version is not allowed by config/bun-runtimes.json" >&2; exit 66; }

work=$(mktemp -d "${RUNNER_TEMP:-/tmp}/bun-from-pin.XXXXXX")
trap 'rm -rf -- "$work/unpack" "$work/bun.zip"' EXIT
if [ -n "$local_zip" ]; then
  cp -- "$local_zip" "$work/bun.zip"
else
  curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location --retry 3 \
    "https://github.com/oven-sh/bun/releases/download/bun-v${version}/${asset}.zip" --output "$work/bun.zip"
fi
[ "$(sha256sum "$work/bun.zip" | cut -d' ' -f1)" = "$zip_sha" ] || { echo "bun archive hash mismatch" >&2; exit 67; }
mkdir "$work/unpack"
unzip -q "$work/bun.zip" -d "$work/unpack"
[ "$(find "$work/unpack" -type f | wc -l)" -eq 1 ] && [ -z "$(find "$work/unpack" -type l -print -quit)" ] \
  && [ -f "$work/unpack/$asset/bun" ] || { echo "bun archive has unexpected content" >&2; exit 67; }
[ "$(sha256sum "$work/unpack/$asset/bun" | cut -d' ' -f1)" = "$bun_sha" ] || { echo "bun binary hash mismatch" >&2; exit 67; }
mkdir -p "$work/bin"
install -m 0755 "$work/unpack/$asset/bun" "$work/bin/bun"
[ "$("$work/bin/bun" --version)" = "$version" ] || { echo "bun reports unexpected version" >&2; exit 67; }
if [ -n "${GITHUB_PATH:-}" ]; then echo "$work/bin" >> "$GITHUB_PATH"; else echo "$work/bin"; fi
echo "PASS bun from source pin (bun=$version)" >&2
