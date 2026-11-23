#!/usr/bin/env python3
"""Packt genau ein App-Bundle aus einem Zip-Archiv in einen neuen Ordner aus.

Das Archiv gilt als nicht vertrauenswürdige Eingabe. Abgewiesen werden: absolute Pfade, leere Pfadteile,
"." und "..", Rückstriche, Einträge ausserhalb von <Bundle>/, alles, was weder Datei, Ordner noch Verweis
ist, doppelte Namen (auch bei abweichender Gross-/Kleinschreibung oder Unicode-Form), verschlüsselte Einträge
und Archive über den Grenzen für Anzahl und Grösse. Geprüft wird das ganze Verzeichnis des Archivs, bevor die
erste Datei entsteht. Geschrieben wird nur in den neuen Ordner; vorhandene Dateien werden nie überschrieben.
Von den Rechten bleibt nur, ob eine Datei ausführbar ist.

Symbolische Verweise bleiben nur in der Form erhalten, die ein Framework braucht: Das Ziel ist ein relativer
Pfad aus einfachen Namen (kein "..", kein "."), zeigt also nie aus dem Ordner des Verweises hinaus. Unter einem
Verweis liegt kein weiterer Eintrag, das Bundle selbst ist nie ein Verweis, und jeder Verweis muss nach dem
Auspacken auf etwas im Bundle zeigen. Verweise entstehen erst, wenn alle Dateien geschrieben sind.

Aufruf: extract-app-bundle.py <archiv.zip> <neuer-ordner> <Bundle-Name>
Exit 0 = ausgepackt, 1 = abgewiesen, 64 = Aufruf.
"""
import os
import stat
import sys
import unicodedata
import zipfile

MAX_ENTRIES = 20000
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_NAME_BYTES = 1024
MAX_LINK_BYTES = 255


class Rejected(Exception):
    pass


def link_target(raw):
    """Ziel eines Verweises: relativer Pfad aus einfachen Namen."""
    try:
        target = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise Rejected("link target") from error
    if not target or len(raw) > MAX_LINK_BYTES or "\\" in target or "\0" in target or target.startswith("/"):
        raise Rejected("link target")
    if any(part in ("", ".", "..") for part in target.split("/")):
        raise Rejected("link target")
    return target


def plan_entries(infos, bundle):
    if not infos or len(infos) > MAX_ENTRIES:
        raise Rejected("entry count")
    seen = set()
    links = set()
    total = 0
    plan = []
    for info in infos:
        name = info.filename
        if not name or "\\" in name or "\0" in name or name.startswith("/") or len(name.encode("utf-8", "surrogatepass")) > MAX_NAME_BYTES:
            raise Rejected("entry name")
        is_dir = name.endswith("/")
        parts = (name[:-1] if is_dir else name).split("/")
        if any(part in ("", ".", "..") for part in parts):
            raise Rejected("entry path")
        if parts[0] != bundle:
            raise Rejected("entry outside the bundle")
        if info.flag_bits & 0x1:
            raise Rejected("encrypted entry")
        mode = info.external_attr >> 16
        kind = stat.S_IFMT(mode)
        is_link = kind == stat.S_IFLNK
        if is_link and (is_dir or len(parts) == 1 or info.file_size > MAX_LINK_BYTES):
            raise Rejected("symbolic link")
        if not is_link and (kind not in (0, stat.S_IFREG, stat.S_IFDIR) or (kind == stat.S_IFDIR) != is_dir and kind != 0):
            raise Rejected("entry type")
        key = unicodedata.normalize("NFC", "/".join(parts)).casefold()
        if key in seen:
            raise Rejected("duplicate entry")
        seen.add(key)
        if is_link:
            links.add(key)
        total += info.file_size
        if total > MAX_TOTAL_BYTES:
            raise Rejected("archive size")
        plan.append((info, parts, is_dir, is_link, bool(mode & 0o111)))
    # Kein Eintrag liegt unter einem Verweis: Geschrieben wird nie durch einen Verweis hindurch.
    for _, parts, _, _, _ in plan:
        for depth in range(1, len(parts)):
            if unicodedata.normalize("NFC", "/".join(parts[:depth])).casefold() in links:
                raise Rejected("entry below a link")
    return plan


def extract(archive, dest, bundle):
    try:
        os.mkdir(dest, 0o700)
    except OSError as error:
        raise Rejected("destination must be new") from error
    try:
        handle = zipfile.ZipFile(archive)
    except (zipfile.BadZipFile, OSError) as error:
        raise Rejected("not a zip archive") from error
    files = 0
    created = []
    with handle:
        plan = plan_entries(handle.infolist(), bundle)
        for info, parts, is_dir, is_link, executable in plan:
            if is_link:
                continue
            path = os.path.join(dest, *parts)
            try:
                if is_dir:
                    os.makedirs(path, 0o755, exist_ok=True)
                    continue
                os.makedirs(os.path.dirname(path), 0o755, exist_ok=True)
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o755 if executable else 0o644)
                with os.fdopen(fd, "wb") as out, handle.open(info) as source:
                    written = 0
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > info.file_size:
                            raise Rejected("entry larger than declared")
                        out.write(chunk)
                files += 1
            except (OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
                raise Rejected("entry cannot be written") from error
        # Verweise zuletzt: Bis hierher gibt es im neuen Ordner keinen einzigen.
        for info, parts, _, is_link, _ in plan:
            if not is_link:
                continue
            path = os.path.join(dest, *parts)
            try:
                with handle.open(info) as source:
                    raw = source.read(MAX_LINK_BYTES + 1)
                target = link_target(raw)
                os.makedirs(os.path.dirname(path), 0o755, exist_ok=True)
                os.symlink(target, path)
            except (OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
                raise Rejected("entry cannot be written") from error
            created.append(path)
    root = os.path.join(dest, bundle)
    if os.listdir(dest) != [bundle] or not os.path.isdir(root) or os.path.islink(root):
        raise Rejected("archive does not hold exactly the bundle")
    inside = os.path.realpath(root) + os.sep
    for path in created:
        if not os.path.exists(path) or not os.path.realpath(path).startswith(inside):
            raise Rejected("link target missing")
    return files, len(created)


def main(argv):
    if len(argv) != 4 or not argv[3] or "/" in argv[3] or argv[3] in (".", ".."):
        print("usage: extract-app-bundle.py <archive.zip> <new-directory> <bundle-name>", file=sys.stderr)
        return 64
    try:
        files, links = extract(argv[1], argv[2], argv[3])
    except Rejected as error:
        print(f"rejected: {error}", file=sys.stderr)
        return 1
    print(f"extracted: {files} files, {links} links")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
