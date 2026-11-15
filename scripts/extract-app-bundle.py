#!/usr/bin/env python3
"""Packt genau ein App-Bundle aus einem Zip-Archiv in einen neuen Ordner aus.

Das Archiv gilt als nicht vertrauenswürdige Eingabe. Abgewiesen werden: absolute Pfade, leere Pfadteile,
"." und "..", Rückstriche, Einträge ausserhalb von <Bundle>/, symbolische Verweise und alles, was weder
Datei noch Ordner ist, doppelte Namen (auch bei abweichender Gross-/Kleinschreibung oder Unicode-Form),
verschlüsselte Einträge und Archive über den Grenzen für Anzahl und Grösse. Geprüft wird das ganze
Verzeichnis des Archivs, bevor die erste Datei entsteht. Geschrieben wird nur in den neuen Ordner; vorhandene
Dateien werden nie überschrieben, Verweise nie angelegt und nie verfolgt. Von den Rechten bleibt nur, ob eine
Datei ausführbar ist.

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


class Rejected(Exception):
    pass


def plan_entries(infos, bundle):
    if not infos or len(infos) > MAX_ENTRIES:
        raise Rejected("entry count")
    seen = set()
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
        if kind == stat.S_IFLNK:
            raise Rejected("symbolic link")
        if kind not in (0, stat.S_IFREG, stat.S_IFDIR) or (kind == stat.S_IFDIR) != is_dir and kind != 0:
            raise Rejected("entry type")
        key = unicodedata.normalize("NFC", "/".join(parts)).casefold()
        if key in seen:
            raise Rejected("duplicate entry")
        seen.add(key)
        total += info.file_size
        if total > MAX_TOTAL_BYTES:
            raise Rejected("archive size")
        plan.append((info, parts, is_dir, bool(mode & 0o111)))
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
    with handle:
        plan = plan_entries(handle.infolist(), bundle)
        for info, parts, is_dir, executable in plan:
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
    if os.listdir(dest) != [bundle] or not os.path.isdir(os.path.join(dest, bundle)) or os.path.islink(os.path.join(dest, bundle)):
        raise Rejected("archive does not hold exactly the bundle")
    return files


def main(argv):
    if len(argv) != 4 or not argv[3] or "/" in argv[3] or argv[3] in (".", ".."):
        print("usage: extract-app-bundle.py <archive.zip> <new-directory> <bundle-name>", file=sys.stderr)
        return 64
    try:
        files = extract(argv[1], argv[2], argv[3])
    except Rejected as error:
        print(f"rejected: {error}", file=sys.stderr)
        return 1
    print(f"extracted: {files} files")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
