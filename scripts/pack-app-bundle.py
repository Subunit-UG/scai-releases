#!/usr/bin/env python3
"""Packt genau ein App-Bundle in ein neues Zip-Archiv, das extract-app-bundle.py wieder auspackt.

Im Archiv stehen Ordner, Dateien (von den Rechten nur, ob ausführbar) und symbolische Verweise als Verweise.
Verweisen wird nie gefolgt. Ein Verweis, den das Auspacken abweisen würde (absolutes Ziel, "..", "."), bricht
schon hier ab, ebenso alles, was weder Datei, Ordner noch Verweis ist. Das Archiv entsteht neu und nur für den
eigenen Benutzer lesbar.

Aufruf: pack-app-bundle.py <App.app> <neues-archiv.zip>
Exit 0 = gepackt, 1 = abgewiesen, 64 = Aufruf.
"""
import os
import stat
import sys
import zipfile

MAX_LINK_BYTES = 255


class Rejected(Exception):
    pass


def entries(app):
    bundle = os.path.basename(app)
    yield bundle + "/", app, "dir"
    for folder, dirnames, filenames in os.walk(app, followlinks=False):
        dirnames.sort()
        kept = []
        for name in dirnames:
            path = os.path.join(folder, name)
            relative = bundle + "/" + os.path.relpath(path, app).replace(os.sep, "/")
            if os.path.islink(path):
                yield relative, path, "link"
            else:
                kept.append(name)
                yield relative + "/", path, "dir"
        dirnames[:] = kept
        for name in sorted(filenames):
            path = os.path.join(folder, name)
            relative = bundle + "/" + os.path.relpath(path, app).replace(os.sep, "/")
            mode = os.lstat(path).st_mode
            if stat.S_ISLNK(mode):
                yield relative, path, "link"
            elif stat.S_ISREG(mode):
                yield relative, path, "file"
            else:
                raise Rejected("entry type")


def pack(app, archive):
    app = os.path.normpath(app)
    if os.path.islink(app) or not os.path.isdir(app) or os.path.basename(app) in ("", ".", ".."):
        raise Rejected("not a bundle directory")
    try:
        fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as error:
        raise Rejected("archive must be new") from error
    count = 0
    with os.fdopen(fd, "wb") as raw, zipfile.ZipFile(raw, "w", zipfile.ZIP_DEFLATED) as out:
        for name, path, kind in entries(app):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            if kind == "dir":
                info.external_attr = (stat.S_IFDIR | 0o755) << 16
                out.writestr(info, b"")
            elif kind == "link":
                target = os.readlink(path)
                raw_target = target.encode("utf-8", "surrogateescape")
                if (not target or len(raw_target) > MAX_LINK_BYTES or target.startswith("/") or "\\" in target
                        or any(part in ("", ".", "..") for part in target.split("/"))):
                    raise Rejected("link target")
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                out.writestr(info, raw_target)
            else:
                executable = bool(os.lstat(path).st_mode & 0o111)
                info.external_attr = (stat.S_IFREG | (0o755 if executable else 0o644)) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                with open(path, "rb") as source, out.open(info, "w") as target:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        target.write(chunk)
            count += 1
    return count


def main(argv):
    if len(argv) != 3:
        print("usage: pack-app-bundle.py <App.app> <new-archive.zip>", file=sys.stderr)
        return 64
    try:
        count = pack(argv[1], argv[2])
    except Rejected as error:
        print(f"rejected: {error}", file=sys.stderr)
        return 1
    except OSError:
        print("rejected: bundle cannot be read", file=sys.stderr)
        return 1
    print(f"packed: {count} entries")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
