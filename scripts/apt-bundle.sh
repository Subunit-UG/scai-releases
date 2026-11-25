#!/usr/bin/env bash
# Install Ubuntu packages from a pinned, prebuilt .deb bundle instead of the apt mirror.
#
#   apt-bundle.sh build   <name> <package>...            # writes <name>.tar (refresh workflow)
#   apt-bundle.sh install <name> <tar-sha256> <package>... # CI: pinned bundle, apt fallback
#
# The bundle is a release asset of this repository (tag "apt-bundles"). Its SHA-256 is pinned in
# the calling workflow, so a changed asset is rejected. If the bundle is missing, does not match
# or cannot be installed on the current runner image, the packages are installed from apt with
# bounded timeouts and retries instead. Either way the script verifies that every requested
# package is installed before it returns.
set -euo pipefail

mode="${1:-}"; name="${2:-}"
[[ "$name" =~ ^[a-z0-9][a-z0-9.-]{0,63}$ ]] || { echo "apt-bundle: invalid bundle name" >&2; exit 2; }

APT_OPTS=(-o Acquire::Retries=3 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20)
BUNDLE_URL_BASE="${APT_BUNDLE_URL_BASE:-https://github.com/${GITHUB_REPOSITORY:-Subunit-UG/scai-releases}/releases/download/apt-bundles}"

installed() {
  local pkg
  for pkg in "$@"; do
    dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed" || return 1
  done
}

from_apt() {
  echo "apt-bundle: installing from apt: $*"
  sudo apt-get "${APT_OPTS[@]}" update -qq
  sudo apt-get "${APT_OPTS[@]}" install -y --no-install-recommends "$@"
}

case "$mode" in
  build)
    shift 2
    (($#)) || { echo "apt-bundle: no packages" >&2; exit 2; }
    work="$(mktemp -d)"
    mkdir -p "$work/debs/partial"
    sudo apt-get "${APT_OPTS[@]}" update -qq
    # Only what this runner image lacks: exactly the debs an identical image needs.
    sudo apt-get "${APT_OPTS[@]}" install -y --no-install-recommends --download-only \
      -o Dir::Cache::archives="$work/debs" "$@"
    sudo chown -R "$(id -u):$(id -g)" "$work/debs"
    rm -rf "$work/debs/partial" "$work/debs/lock"
    printf '%s\n' "$@" > "$work/debs/PACKAGES"
    printf '%s %s\n' "${ImageOS:-unknown}" "${ImageVersion:-unknown}" > "$work/debs/IMAGE"
    (cd "$work/debs" && ls ./*.deb >/dev/null && sha256sum ./*.deb > SHA256SUMS)
    tar -C "$work" --sort=name --mtime='2000-01-01 00:00:00Z' --owner=0 --group=0 --numeric-owner \
      -cf "$name.tar" debs
    sha256sum "$name.tar"
    ;;
  install)
    want="${3:-}"; shift 3 || true
    [[ "$want" =~ ^[0-9a-f]{64}$ ]] || { echo "apt-bundle: pinned sha256 required" >&2; exit 2; }
    (($#)) || { echo "apt-bundle: no packages" >&2; exit 2; }
    if installed "$@"; then echo "apt-bundle: already installed: $*"; exit 0; fi
    work="$(mktemp -d)"
    ok=0
    if curl -fsSL --retry 3 --retry-delay 2 --max-time 120 -o "$work/b.tar" "$BUNDLE_URL_BASE/$name.tar"; then
      got="$(sha256sum "$work/b.tar" | cut -d' ' -f1)"
      if [[ "$got" == "$want" ]]; then
        tar -C "$work" -xf "$work/b.tar"
        # Never replace what the runner image already has (no downgrades): only debs for
        # packages that are not installed at all; anything that then does not fit -> apt.
        new=()
        for deb in "$work"/debs/*.deb; do
          pkg="$(dpkg-deb -f "$deb" Package)"
          installed "$pkg" || new+=("$deb")
        done
        if (cd "$work/debs" && sha256sum -c --quiet SHA256SUMS) && { ((${#new[@]} == 0)) || sudo dpkg -i "${new[@]}" >/dev/null; }; then
          ok=1
        else
          echo "apt-bundle: bundle does not install on this image" >&2
          sudo apt-get "${APT_OPTS[@]}" install -f -y -qq >/dev/null 2>&1 || true
        fi
      else
        echo "apt-bundle: bundle sha256 mismatch (got $got)" >&2
      fi
    else
      echo "apt-bundle: bundle not downloadable" >&2
    fi
    if ((ok)) && installed "$@"; then
      echo "apt-bundle: installed from pinned bundle $name: $*"
    else
      from_apt "$@"
    fi
    installed "$@" || { echo "apt-bundle: packages missing after install: $*" >&2; exit 1; }
    ;;
  *)
    echo "usage: apt-bundle.sh build <name> <pkg>... | install <name> <sha256> <pkg>..." >&2
    exit 2
    ;;
esac
