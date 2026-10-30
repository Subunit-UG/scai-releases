#!/usr/bin/env bash
# Prueft im vertraulichen Runner, dass die Bun-Laufzeit der CI genau der Pin der privaten Quelle ist
# (z. B. u1-chat scripts/install-bun-runtime.py: VERSION = "x.y.z"). Gibt nichts aus der Quelle aus.
# Hintergrund 30.10.2026: CI pruefte u1-chat mit Bun 1.3.14, live lief 1.4.4. setup-bun laeuft vor dem
# privaten Checkout (keine Action neben privatem Code); dieser Schritt macht jede Abweichung rot.
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: verify-bun-runtime-pin.sh <pin-file>" >&2
  exit 64
fi
pin_file=$1
[ -f "$pin_file" ] && [ ! -L "$pin_file" ] || { echo "bun pin file missing" >&2; exit 65; }

matches=$(grep -cE '^VERSION = "[0-9]+\.[0-9]+\.[0-9]+"$' "$pin_file" || true)
[ "$matches" = "1" ] || { echo "bun pin must appear exactly once" >&2; exit 65; }
pinned=$(grep -E '^VERSION = "[0-9]+\.[0-9]+\.[0-9]+"$' "$pin_file" | sed -E 's/^VERSION = "([0-9.]+)"$/\1/')

actual=$(bun --version)
printf '%s' "$actual" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || { echo "bun --version is malformed" >&2; exit 65; }

if [ "$actual" != "$pinned" ]; then
  echo "bun runtime drift: CI $actual, source pin $pinned" >&2
  exit 1
fi
echo "PASS bun runtime pin (bun=$actual)"
