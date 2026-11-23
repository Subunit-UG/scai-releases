#!/usr/bin/env python3
"""Signiert ein fertig gebautes App-Bundle neu, ohne etwas daraus auszuführen und ohne ihm etwas zu glauben.

Das Bundle ist Eingabe aus einem Bau, dem dieser Schritt nicht vertraut. Was signiert wird, mit welcher Kennung
und mit welchen Rechten (Entitlements), steht allein in einer Liste aus diesem Repo (--manifest):

  bundle, executable, identifier   Name des Bundles, sein Hauptprogramm und seine Kennung
  entitlements                     Rechte der App; jedes andere Teil bekommt keine
  code                             weitere Teile in Signier-Reihenfolge: eine Datei (path, identifier) oder ein
                                   eingebettetes Bundle (path, identifier, binary); mit "when" nur, wenn --with
                                   den Namen nennt

Enthält das Bundle ausführbaren Code oder eingebettete Bundles, die nicht in der Liste stehen, oder fehlt ein
Teil der Liste, wird nichts signiert. Aus vorhandenen Signaturen wird nichts übernommen. Symbolischen Verweisen
wird nie gefolgt. Hardened Runtime ist immer an.

Danach, und allein mit --verify-only, wird das Ergebnis geprüft: Die Signatur des ganzen Bundles muss gelten;
jedes Teil trägt seine Kennung, das erwartete Team, Hardened Runtime und (bei secure) einen sicheren Zeitstempel;
die App trägt genau ihre Rechte, jedes andere Teil keine.

Die Ausgabe nennt nur Anzahlen, nie Namen oder Inhalte aus dem Bundle.

Aufruf: resign-app-bundle.py <App.app> --manifest <liste.json> --expect-team <Team-ID> --timestamp secure|none
          [--with <name>]... [--verify-only] [--codesign <Pfad>]
Die Signier-Identität steht in der Umgebung (APPLE_SIGNING_IDENTITY); --verify-only braucht keine.
Exit 0 = signiert und geprüft, 1 = abgewiesen oder gescheitert, 64 = Aufruf.
"""
import json
import os
import plistlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile

BUNDLE_SUFFIXES = (".app", ".framework", ".xpc", ".appex", ".bundle", ".plugin")
MACHO_MAGICS = (0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE, 0xCAFEBABE, 0xCAFEBABF)
RUNTIME_FLAG = re.compile(rb"^CodeDirectory [^\n]*flags=0x[0-9a-f]+\([^)\n]*runtime[^)\n]*\)", re.M)
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,126}")
ENTITLEMENT = re.compile(r"com\.apple\.[A-Za-z0-9.-]{1,120}")
PLAIN_PATH = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]*(/[A-Za-z0-9][A-Za-z0-9 ._-]*)*")
MAX_FILES = 20000


class Rejected(Exception):
    pass


class Usage(Exception):
    pass


def is_code(path):
    """Mach-O in jeder Form. Dieselbe Kennzahl wie ein Mach-O für mehrere Architekturen tragen Java-Klassen:
    Auch sie zählen hier als Code und müssen deshalb in der Liste stehen, sonst wird nichts signiert."""
    try:
        with open(path, "rb") as handle:
            head = handle.read(4)
    except OSError as error:
        raise Rejected("bundle cannot be read") from error
    return len(head) == 4 and struct.unpack(">I", head)[0] in MACHO_MAGICS


def found_code(app):
    """Alle Mach-O-Dateien und eingebetteten Bundles, relativ zum Bundle. Verweise zählen nie."""
    files, bundles, seen = set(), set(), 0
    for folder, dirnames, filenames in os.walk(app, followlinks=False):
        kept = []
        for name in dirnames:
            path = os.path.join(folder, name)
            if os.path.islink(path):
                continue
            kept.append(name)
            if name.endswith(BUNDLE_SUFFIXES):
                bundles.add(os.path.relpath(path, app))
        dirnames[:] = kept
        for name in filenames:
            path = os.path.join(folder, name)
            seen += 1
            if seen > MAX_FILES:
                raise Rejected("too many files")
            if os.path.islink(path) or not os.path.isfile(path):
                continue
            if is_code(path):
                files.add(os.path.relpath(path, app))
    return files, bundles


def load_manifest(path, tags):
    try:
        with open(path, encoding="utf-8") as handle:
            manifest = json.load(handle)
        bundle, executable, identifier = manifest["bundle"], manifest["executable"], manifest["identifier"]
        entitlements, code = manifest["entitlements"], manifest["code"]
        ok = (isinstance(bundle, str) and bundle.endswith(".app") and PLAIN_PATH.fullmatch(bundle) and "/" not in bundle
              and isinstance(executable, str) and PLAIN_PATH.fullmatch(executable) and "/" not in executable
              and isinstance(identifier, str) and IDENTIFIER.fullmatch(identifier)
              and isinstance(entitlements, list) and all(isinstance(e, str) and ENTITLEMENT.fullmatch(e) for e in entitlements)
              and len(set(entitlements)) == len(entitlements) and isinstance(code, list))
        units = []
        for entry in code if ok else []:
            keys = set(entry) - {"path", "identifier", "binary", "when"}
            relative, unit_id, binary, when = entry["path"], entry["identifier"], entry.get("binary"), entry.get("when")
            ok = (ok and not keys and isinstance(relative, str) and PLAIN_PATH.fullmatch(relative)
                  and isinstance(unit_id, str) and IDENTIFIER.fullmatch(unit_id)
                  and (binary is None or isinstance(binary, str) and PLAIN_PATH.fullmatch(binary))
                  and (binary is None) != relative.endswith(BUNDLE_SUFFIXES)
                  and (when is None or isinstance(when, str) and when))
            if ok and (when is None or when in tags):
                units.append({"path": relative, "identifier": unit_id, "binary": None if binary is None else f"{relative}/{binary}"})
        known = {entry.get("when") for entry in code if isinstance(entry, dict)} if ok else set()
        if not ok or any(tag not in known for tag in tags):
            raise ValueError
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        raise Usage("manifest") from error
    main = f"Contents/MacOS/{executable}"
    signed = [main, *[unit["binary"] or unit["path"] for unit in units]]
    if len(set(signed)) != len(signed) or len({unit["path"] for unit in units}) != len(units):
        raise Usage("manifest")
    return {"bundle": bundle, "executable": executable, "identifier": identifier, "entitlements": sorted(entitlements), "units": units, "main": main}


def check_layout(app, manifest):
    """Das Bundle enthält genau den Code der Liste, nicht mehr und nicht weniger."""
    if os.path.basename(app) != manifest["bundle"] or os.path.islink(app) or not os.path.isdir(app):
        raise Rejected("not the expected bundle")
    try:
        with open(os.path.join(app, "Contents", "Info.plist"), "rb") as handle:
            info = plistlib.load(handle)
        named = (info.get("CFBundleIdentifier"), info.get("CFBundleExecutable"))
    except Exception as error:  # plistlib meldet je nach Fehler verschiedene Arten
        raise Rejected("bundle description cannot be read") from error
    if named != (manifest["identifier"], manifest["executable"]):
        raise Rejected("bundle description does not match")
    files, bundles = found_code(app)
    expected_files = {manifest["main"], *[unit["binary"] or unit["path"] for unit in manifest["units"]]}
    expected_bundles = {unit["path"] for unit in manifest["units"] if unit["binary"]}
    if files - expected_files or bundles - expected_bundles:
        raise Rejected("unexpected code in the bundle")
    if expected_files - files or expected_bundles - bundles:
        raise Rejected("expected code missing")


def run(codesign, arguments):
    try:
        return subprocess.run([codesign, *arguments], stdin=subprocess.DEVNULL, capture_output=True, timeout=900)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise Rejected("codesign cannot be run") from error


def read_entitlements(codesign, path):
    result = run(codesign, ["-d", "--entitlements", "-", "--xml", path])
    if result.returncode != 0:
        raise Rejected("signature cannot be read")
    blob = result.stdout.strip()
    if not blob:
        return {}
    try:
        entitlements = plistlib.loads(blob)
    except Exception as error:
        raise Rejected("entitlements cannot be read") from error
    if not isinstance(entitlements, dict):
        raise Rejected("entitlements cannot be read")
    return entitlements


def verify(app, manifest, team, timestamp, codesign):
    if run(codesign, ["--verify", "--strict", "--deep", app]).returncode != 0:
        raise Rejected("signature does not verify")
    parts = [(unit["binary"] or unit["path"], unit["identifier"], {}) for unit in manifest["units"]]
    rights = {key: True for key in manifest["entitlements"]}
    parts += [(manifest["main"], manifest["identifier"], rights), ("", manifest["identifier"], rights)]
    for relative, identifier, expected in parts:
        path = os.path.join(app, relative) if relative else app
        result = run(codesign, ["-dvvv", path])
        if result.returncode != 0:
            raise Rejected("signature cannot be read")
        lines = result.stderr.split(b"\n")
        if b"Identifier=" + identifier.encode() not in lines:
            raise Rejected("unexpected identifier")
        if b"TeamIdentifier=" + team.encode() not in lines:
            raise Rejected("unexpected team")
        if not RUNTIME_FLAG.search(result.stderr):
            raise Rejected("hardened runtime missing")
        if timestamp == "secure" and not any(line.startswith(b"Timestamp=") for line in lines):
            raise Rejected("secure timestamp missing")
        if read_entitlements(codesign, path) != expected:
            raise Rejected("unexpected entitlements")


def resign(app, manifest, identity, timestamp, codesign):
    base = ["--force", "--options", "runtime", "--timestamp" if timestamp == "secure" else "--timestamp=none"]
    scratch = tempfile.mkdtemp(prefix="resign-app-")
    try:
        rights = []
        if manifest["entitlements"]:
            rights_file = os.path.join(scratch, "app.entitlements")
            with open(rights_file, "wb") as handle:
                plistlib.dump({key: True for key in manifest["entitlements"]}, handle)
            rights = ["--entitlements", rights_file]
        targets = [(os.path.join(app, unit["path"]), unit["identifier"], []) for unit in manifest["units"]]
        targets.append((app, manifest["identifier"], rights))
        for path, identifier, extra in targets:
            if run(codesign, [*base, "--identifier", identifier, *extra, "--sign", identity, path]).returncode != 0:
                raise Rejected("signing failed")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return len(targets)


def parse(argv):
    options = {"app": None, "manifest": None, "team": "", "timestamp": None, "tags": [], "verify_only": False, "codesign": "/usr/bin/codesign"}
    arguments = argv[1:]
    try:
        while arguments:
            argument = arguments.pop(0)
            if argument == "--manifest":
                options["manifest"] = arguments.pop(0)
            elif argument == "--expect-team":
                options["team"] = arguments.pop(0)
            elif argument == "--timestamp":
                options["timestamp"] = arguments.pop(0)
            elif argument == "--with":
                options["tags"].append(arguments.pop(0))
            elif argument == "--verify-only":
                options["verify_only"] = True
            elif argument == "--codesign":
                options["codesign"] = arguments.pop(0)
            elif argument.startswith("-") or options["app"] is not None:
                raise Usage("argument")
            else:
                options["app"] = argument
    except IndexError as error:
        raise Usage("argument") from error
    identity = os.environ.get("APPLE_SIGNING_IDENTITY", "")
    if (not options["app"] or not options["manifest"] or options["timestamp"] not in ("secure", "none")
            or not re.fullmatch(r"[A-Z0-9]{10}", options["team"])
            or not (options["verify_only"] or identity and not identity.startswith("-"))):
        raise Usage("argument")
    options["identity"] = identity
    return options


def main(argv):
    try:
        options = parse(argv)
        manifest = load_manifest(options["manifest"], options["tags"])
    except Usage:
        print("usage: APPLE_SIGNING_IDENTITY=… resign-app-bundle.py <App.app> --manifest <list.json> --expect-team <team-id>"
              " --timestamp secure|none [--with <name>]... [--verify-only] [--codesign <path>]", file=sys.stderr)
        return 64
    app = os.path.normpath(options["app"])
    try:
        check_layout(app, manifest)
        signed = 0 if options["verify_only"] else resign(app, manifest, options["identity"], options["timestamp"], options["codesign"])
        verify(app, manifest, options["team"], options["timestamp"], options["codesign"])
    except Rejected as error:
        print(f"rejected: {error}", file=sys.stderr)
        return 1
    print(f"verified: {len(manifest['units']) + 1} parts" if options["verify_only"] else f"resigned and verified: {signed} parts")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
