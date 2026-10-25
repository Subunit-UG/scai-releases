#!/usr/bin/env python3
"""Trusted gate code: fixed Charge pin, credential-free local SwiftPM mirror.

Never executes a package manifest, source hook, or source-provided script.
"""
import base64
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

REPOSITORY = "https://github.com/Subunit-UG/subunit-charge.git"
API = "https://api.github.com"
HEX = re.compile(r"[0-9a-f]{40}\Z")


class Blocked(Exception):
    pass


def regular_text(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "r") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise Blocked("Pin input must be a regular file")
        text = stream.read(65537)
    if len(text) > 65536:
        raise Blocked("Pin input is too large")
    return text


def source_pin(source):
    manifest = regular_text(source / "Package.swift")
    # Deliberately narrow grammar: formatting changes need a reviewed gate update.
    # No Swift evaluation, imports, shell parsing, arbitrary URL, or mutable ref.
    declarations = re.findall(r"\.package\s*\(", manifest)
    lock = source / "Package.resolved"
    if not declarations:
        if lock.exists():
            data = json.loads(regular_text(lock))
            if data.get("pins"):
                raise Blocked("Lockfile dependencies without a manifest declaration")
        return None  # Older Notch revisions remain buildable without a Charge token.
    expected = re.compile(
        r'^\s*dependencies:\s*\[\.package\(url:\s*"'
        + re.escape(REPOSITORY)
        + r'",\s*revision:\s*"([0-9a-f]{40})"\)\],\s*$', re.M)
    matches = expected.findall(manifest)
    if len(declarations) != 1 or len(matches) != 1:
        raise Blocked("Only the reviewed fixed Charge repository and exact revision are accepted")
    data = json.loads(regular_text(lock))
    pins = data.get("pins")
    if data.get("version") != 2 or not isinstance(pins, list) or len(pins) != 1:
        raise Blocked("Expected exactly one version-2 lockfile pin")
    pin = pins[0]
    if (pin.get("identity") != "subunit-charge"
            or pin.get("kind") != "remoteSourceControl"
            or pin.get("location") != REPOSITORY
            or pin.get("state") != {"revision": matches[0]}):
        raise Blocked("Manifest and lockfile must identify the same exact Charge commit")
    return matches[0]


def isolated_environment(home, config):
    # Allowlist, not a growing denylist: no inherited auth, trace, helper,
    # URL rewrite, alternate object store, SSH agent, or Git config environment.
    result = {key: os.environ[key] for key in ("PATH", "SYSTEMROOT") if key in os.environ}
    result.update(HOME=str(home), XDG_CONFIG_HOME=str(home), LANG="C", LC_ALL="C",
                  GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=str(config),
                  GIT_CONFIG_SYSTEM=os.devnull, GIT_TERMINAL_PROMPT="0",
                  GIT_ALLOW_PROTOCOL="https")
    return result


def run_git(arguments, environment):
    command = ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
               "-c", "init.templateDir=", *map(str, arguments)]
    # Both channels stay private and are discarded on failure, not echoed.
    result = subprocess.run(command, env=environment, capture_output=True, timeout=120)
    if result.returncode:
        raise Blocked("Charge Git transport or exact-commit check failed (private output suppressed)")
    return result.stdout.decode().strip()


def root_path():
    temp = Path(os.environ["RUNNER_TEMP"])
    if not temp.is_absolute() or "\n" in str(temp) or "\r" in str(temp):
        raise Blocked("Invalid runner temporary directory")
    return temp / "charge-local-mirror"


def prepare(source, expected):
    if not HEX.fullmatch(expected) or source_pin(source) != expected:
        raise Blocked("Charge pin changed before checkout")
    token = os.environ.pop("CHARGE_TOKEN", "")
    if not token or "\n" in token or "\r" in token:
        raise Blocked("Charge read access unavailable; approved App installation is required")
    root = root_path()
    root.mkdir(mode=0o700)  # Refuse existing state, including symlinks.
    auth_dir = Path(tempfile.mkdtemp(prefix="charge-auth-", dir=root.parent))
    config = auth_dir / "gitconfig"
    try:
        encoded = base64.b64encode(("x-access-token:" + token).encode()).decode()
        with open(config, "x", opener=lambda p, flags: os.open(p, flags, 0o600)) as stream:
            stream.write('[credential]\n\thelper =\n'
                         '[http]\n\tfollowRedirects = false\n'
                         f'[http "{REPOSITORY}"]\n\textraHeader = AUTHORIZATION: basic {encoded}\n')
        environment = isolated_environment(auth_dir, config)
        bare = root / "subunit-charge.git"
        run_git(["init", "--bare", bare], environment)
        run_git(["-C", bare, "fetch", "--no-tags", "--depth", "1", "--",
                 REPOSITORY, expected], environment)
        if run_git(["-C", bare, "rev-parse", "FETCH_HEAD^{commit}"], environment) != expected:
            raise Blocked("Fetched Charge commit differs from the reviewed pin")
        run_git(["-C", bare, "update-ref", "refs/heads/pinned", expected], environment)
        run_git(["-C", bare, "symbolic-ref", "HEAD", "refs/heads/pinned"], environment)
        if run_git(["-C", bare, "remote"], environment):
            raise Blocked("Charge mirror unexpectedly contains a remote")
        charge_manifest = run_git(["-C", bare, "show", expected + ":Package.swift"], environment)
        if re.search(r"\.(?:package|binaryTarget)\s*\(", charge_manifest):
            raise Blocked("Unknown transitive Charge dependency requires a reviewed gate update")
    except BaseException:
        shutil.rmtree(root)
        raise
    finally:
        # A cleanup exception fails this command; workflow revocation still runs.
        shutil.rmtree(auth_dir)
        token = encoded = ""
    if auth_dir.exists():
        raise Blocked("Charge credential cleanup failed")
    # Data only. SwiftPM is invoked solely by later private steps, after revoke.
    mirror = {"version": 1, "object": [{"original": REPOSITORY,
                                           "mirror": (root / "subunit-charge.git").as_uri()}]}
    (root / "mirrors.json").write_text(json.dumps(mirror) + "\n")
    (root / "prepared.json").write_text(json.dumps({"revision": expected}) + "\n")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request_status(method, path, token):
    request = urllib.request.Request(API + path, method=method, headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2026-03-10",
        "User-Agent": "subunit-notch-charge-gate"})
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code
    except Exception:
        raise Blocked("Charge token revocation transport failed") from None


def revoke():
    token = os.environ.pop("CHARGE_TOKEN", "")
    if not token:
        raise Blocked("Cannot prove revocation without the issued token")
    if request_status("DELETE", "/installation/token", token) != 204:
        raise Blocked("Charge token revocation failed; private builds are blocked")
    if request_status("GET", "/installation/repositories", token) != 401:
        raise Blocked("Charge token still usable or revocation cannot be proved")
    token = ""
    # Receipt is written only after GitHub has rejected the revoked credential.
    root_path().mkdir(mode=0o700, exist_ok=True)
    (root_path() / "revoked").write_text("204 then 401\n")


def ready(source, expected):
    root = root_path()
    if "CHARGE_TOKEN" in os.environ or list(root.parent.glob("charge-auth-*")):
        raise Blocked("Charge credential material remains before private execution")
    if source_pin(source) != expected or not (root / "revoked").is_file():
        raise Blocked("Charge pin or early token revocation receipt missing")
    if json.loads((root / "prepared.json").read_text()) != {"revision": expected}:
        raise Blocked("Prepared Charge revision mismatch")
    # Build-step shell scopes file-only transport; later release actions keep
    # their previous Git environment. This is only the local SwiftPM map.
    env_file = Path(os.environ["GITHUB_ENV"])
    with env_file.open("a") as stream:
        stream.write(f"SWIFTPM_MIRROR_CONFIG={root / 'mirrors.json'}\n")


def main():
    try:
        mode, *args = sys.argv[1:]
        if mode == "pin" and len(args) == 1:
            pin = source_pin(Path(args[0]))
            print("required=" + ("true" if pin else "false"))
            if pin:
                print("sha=" + pin)
        elif mode == "prepare" and len(args) == 2:
            prepare(Path(args[0]), args[1])
        elif mode == "revoke" and not args:
            revoke()
        elif mode == "ready" and len(args) == 2:
            ready(Path(args[0]), args[1])
        else:
            raise Blocked("Invalid Charge preparation arguments")
    except Exception as error:
        # Never interpolate arbitrary exceptions, transport output, URLs, tokens,
        # manifest contents, or file contents into a public Actions log.
        message = str(error) if isinstance(error, Blocked) else "Charge preparation failed safely"
        print("::error::" + message, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
