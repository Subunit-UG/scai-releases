#!/usr/bin/env bash
# Checkout one explicitly allowlisted private Fleet repository at an immutable
# commit without exposing the deploy key, Git transport output, or a mutable ref.

set -euo pipefail
set +x
umask 077

# A second, fail-closed barrier for a killed checkout. Only this helper's
# generated credentials are removed; never touch the user's SSH files.
if [ "$#" -eq 1 ] && [ "$1" = --cleanup-credentials ]; then
  unset SOURCE_DEPLOY_KEY GIT_SSH_COMMAND
  temp_root=${RUNNER_TEMP:?RUNNER_TEMP is required}
  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) temp_root=$(cygpath -u "$temp_root") ;;
  esac
  for root in "$temp_root" "$HOME/.ssh"; do
    for lease in "$root"/scai-checkout-credentials.*; do
      [ -e "$lease" ] || [ -L "$lease" ] || continue
      if [ -L "$lease" ] || [ ! -d "$lease" ]; then
        echo "::error::Unexpected checkout credential lease type." >&2
        exit 70
      fi
      rm -f "$lease/key" "$lease/known_hosts"
      rmdir "$lease"
    done
  done
  echo 'PASS checkout-credentials-removed'
  exit 0
fi

if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
  echo "usage: checkout-private-source.sh <component> <repository> <source-sha> [component-tag]" >&2
  exit 64
fi

component=$1
source_repo=$2
source_sha=$3
component_tag=${4:-}
if [ -n "$component_tag" ] && ! printf '%s' "$component_tag" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'; then
  echo "Ungültiges Komponenten-Tag" >&2
  exit 64
fi

# Kanonische Pfade nach dem Org-Umzug (TJ 2026-10-30). Der Komponentenname links bleibt
# der Zielordner private/<component>; Deploy-Keys hängen am Repo, nicht am Pfad.
case "$component:$source_repo" in
  u1-chat:git@github.com:Subunit-UG/infra-u1-chat.git) ;;
  atlas:git@github.com:Subunit-UG/infra-atlas.git) ;;
  subunit-auth:git@github.com:Subunit-UG/infra-auth.git) ;;
  subunit-scai:git@github.com:Subunit-UG/scai-app.git) ;;
  echo:git@github.com:Subunit-UG/echo-server.git) ;;
  subunit-notch:git@github.com:Subunit-UG/mac-notch.git) ;;
  sonar-tauri:git@github.com:Subunit-UG/sonar-tauri.git) ;;
  bridge-tauri:git@github.com:Subunit-UG/bridge-tauri.git) ;;
  trace-tauri:git@github.com:Subunit-UG/trace-tauri.git) ;;
  *)
    echo "component/repository is not allowlisted" >&2
    exit 64
    ;;
esac

if ! printf '%s' "$source_sha" | grep -Eq '^[0-9a-f]{40}$'; then
  echo "source SHA must be 40 lowercase hexadecimal characters" >&2
  exit 64
fi

if [ -z "${SOURCE_DEPLOY_KEY:-}" ]; then
  echo "::error title=Private checkout unavailable::$component read-only deploy key is missing."
  exit 65
fi

workspace=${GITHUB_WORKSPACE:?GITHUB_WORKSPACE is required}
temp_root=${RUNNER_TEMP:?RUNNER_TEMP is required}
windows=false
ssh_bin=ssh
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    workspace=$(cygpath -u "$workspace")
    temp_root=$(cygpath -u "$temp_root")
    windows=true
    ;;
esac
script_dir=$(dirname -- "$0")
script_dir=$(cd -- "$script_dir" && pwd)
private_root="$workspace/private"
destination="$private_root/$component"
credential_dir=''
github_ed25519_fingerprint="SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU"

if [ -e "$destination" ]; then
  echo "private checkout destination already exists" >&2
  exit 66
fi

# shellcheck disable=SC2329 # invoked by trap
cleanup() {
  if [ -n "$credential_dir" ]; then
    rm -f "$credential_dir/key" "$credential_dir/known_hosts"
    rmdir "$credential_dir"
  fi
}
# Install the trap BEFORE allocating or writing any credential.
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

credential_root=$temp_root
if [ "$windows" = true ]; then
  mkdir -p "$HOME/.ssh"
  credential_root="$HOME/.ssh"
fi
credential_dir=$(mktemp -d "$credential_root/scai-checkout-credentials.XXXXXX")
key_file="$credential_dir/key"
known_hosts="$credential_dir/known_hosts"

mkdir -p "$private_root"
chmod 700 "$private_root"
printf '%s\n' "$SOURCE_DEPLOY_KEY" > "$key_file"
chmod 600 "$key_file"
# Git/SSH/diagnostic children must not inherit the private key in their env.
unset SOURCE_DEPLOY_KEY
# OpenSSH >= 10 (macOS-Runner) schreibt die Banner-Kommentarzeile auf stdout;
# nur Schluesselzeilen zaehlen, die Pruefung auf genau EINEN gepinnten Schluessel bleibt.
{ ssh-keyscan -t ed25519 github.com 2>/dev/null || true; } | { grep -v '^#' || true; } > "$known_hosts"
chmod 600 "$known_hosts"

host_key_count=$(wc -l < "$known_hosts" | tr -d '[:space:]')
actual_fingerprint=$(ssh-keygen -lf "$known_hosts" -E sha256 | awk 'NR == 1 { print $2 }')
if [ "$host_key_count" != "1" ] || [ "$actual_fingerprint" != "$github_ed25519_fingerprint" ]; then
  echo "::error title=GitHub host verification failed::The pinned GitHub ED25519 host fingerprint did not match."
  exit 68
fi

# Git reparses this command through a shell: quote every path, including spaces
# and apostrophes, rather than relying on the outer assignment's quotes.
printf -v ssh_command '%q' "$ssh_bin"
printf -v key_arg '%q' "$key_file"
printf -v hosts_arg '%q' "UserKnownHostsFile=$known_hosts"
# Git Bash's PATH ssh and slash paths on Windows, with an isolated pin on ALL
# platforms. Disable global/user config and additional system host trust.
export GIT_SSH_COMMAND="$ssh_command -i $key_arg -F /dev/null -o IdentitiesOnly=yes -o $hosts_arg -o GlobalKnownHostsFile=/dev/null -o HostKeyAlgorithms=ssh-ed25519 -o StrictHostKeyChecking=yes"
git init -q "$destination"
if [ "$windows" = true ]; then
  git -C "$destination" config core.autocrlf false
  git -C "$destination" config core.eol lf
fi
git -C "$destination" remote add origin "$source_repo"
# Echo's deployment contracts compare an exact historical live Dockerfile.
# Keep its ancestry, matching server-contracts.yml's fetch-depth: 0. The checked
# out candidate is still the immutable SHA validated below; other lanes stay shallow.
if [ "$component" = echo ]; then
  bash "$script_dir/run-confidential.sh" "checkout-$component-fetch" \
    git -C "$destination" fetch origin "$source_sha"
else
  bash "$script_dir/run-confidential.sh" "checkout-$component-fetch" \
    git -C "$destination" fetch --depth 1 origin "$source_sha"
fi
if [ "$component" = echo ]; then
  # This deployed baseline is not an ancestor of the current release branch.
  # Fetch only the exact fixture pin, never a mutable branch or extra checkout.
  bash "$script_dir/run-confidential.sh" "checkout-echo-deploy-fixture" \
    git -C "$destination" fetch --depth 1 origin 5c37154c83464b1f5a203bd4e0f1d66af9bf75d1
fi
bash "$script_dir/run-confidential.sh" "checkout-$component-detach" \
  git -C "$destination" checkout --detach "$source_sha"

actual_sha=$(git -C "$destination" rev-parse HEAD)
if [ "$actual_sha" != "$source_sha" ]; then
  echo "::error title=Private checkout drift::$component expected $source_sha but received $actual_sha."
  exit 67
fi

# Tag-Objekte (auch annotierte Tags) zum Commit auflösen, solange der read-only Key lebt.
if [ -n "$component_tag" ]; then
  bash "$script_dir/run-confidential.sh" "checkout-$component-tag" \
    git -C "$destination" fetch --depth 1 -- origin "refs/tags/$component_tag"
  tag_sha=$(git -C "$destination" rev-parse 'FETCH_HEAD^{commit}')
  if [ "$tag_sha" != "$source_sha" ]; then
    echo "::error::Komponenten-Tag stimmt nicht mit dem Pin überein."
    exit 67
  fi
fi

git -C "$destination" remote remove origin
cleanup
trap - EXIT HUP INT TERM
unset GIT_SSH_COMMAND SOURCE_DEPLOY_KEY
echo "PASS private-checkout-$component (source-sha=$actual_sha)"
