import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), "extract-app-bundle.py");
const BUNDLE = "Probe.app";

// Baut ein Zip aus einer Liste von Einträgen: {name, data?, mode?, kind?: "link" | "fifo"}.
const BUILD_ZIP = `
import json, stat, sys, zipfile
spec = json.load(sys.stdin)
with zipfile.ZipFile(sys.argv[1], "w") as z:
    for e in spec:
        info = zipfile.ZipInfo(e["name"])
        kind = {"link": stat.S_IFLNK, "fifo": stat.S_IFIFO, "dir": stat.S_IFDIR}.get(e.get("kind"), stat.S_IFDIR if e["name"].endswith("/") else stat.S_IFREG)
        info.external_attr = (kind | e.get("mode", 0o644)) << 16
        z.writestr(info, e.get("data", ""))
`;

function run(entries, { prepare } = {}) {
  const root = mkdtempSync(join(tmpdir(), "extract-app-"));
  const zip = join(root, "in.zip");
  const dest = join(root, "out");
  if (entries !== null) {
    const built = spawnSync("python3", ["-I", "-c", BUILD_ZIP, zip], { input: JSON.stringify(entries), encoding: "utf8" });
    assert.equal(built.status, 0, built.stderr);
  }
  prepare?.({ root, zip, dest });
  const result = spawnSync("python3", ["-I", SCRIPT, zip, dest, BUNDLE], { encoding: "utf8" });
  return { root, dest, status: result.status, out: result.stdout + result.stderr };
}
const good = [
  { name: `${BUNDLE}/` },
  { name: `${BUNDLE}/Contents/Info.plist`, data: "<plist/>" },
  { name: `${BUNDLE}/Contents/MacOS/probe`, data: "#!/bin/sh\n", mode: 0o755 },
  { name: `${BUNDLE}/Contents/Resources/hinweis.txt`, data: "x" },
];
function rejected(name, entries, pattern, options) {
  test(`abgewiesen: ${name}`, () => {
    const r = run(entries, options);
    try {
      assert.equal(r.status, 1, r.out);
      assert.match(r.out, pattern);
      // Nichts ausserhalb des neuen Ordners und nichts neben dem Bundle.
      assert.deepEqual(readdirSync(r.root).filter((n) => !["in.zip", "out"].includes(n)), []);
    } finally { rmSync(r.root, { recursive: true, force: true }); }
  });
}

test("ein gutes Bundle wird ausgepackt, Ausführbarkeit bleibt, sonst keine Rechte", () => {
  const r = run(good);
  try {
    assert.equal(r.status, 0, r.out);
    assert.match(r.out, /extracted: 3 files/);
    assert.deepEqual(readdirSync(r.dest), [BUNDLE]);
    assert.equal(readFileSync(join(r.dest, BUNDLE, "Contents/Info.plist"), "utf8"), "<plist/>");
    assert.ok(lstatSync(join(r.dest, BUNDLE, "Contents/MacOS/probe")).mode & 0o100);
    assert.equal(lstatSync(join(r.dest, BUNDLE, "Contents/Resources/hinweis.txt")).mode & 0o111, 0);
  } finally { rmSync(r.root, { recursive: true, force: true }); }
});

rejected("Pfad nach oben", [...good, { name: `${BUNDLE}/../draussen.txt`, data: "x" }], /entry path/);
rejected("Pfad nach oben am Anfang", [{ name: "../draussen.txt", data: "x" }], /entry path/);
rejected("absoluter Pfad", [...good, { name: "/tmp/draussen.txt", data: "x" }], /entry name/);
rejected("Eintrag neben dem Bundle", [...good, { name: "zusatz.sh", data: "x" }], /outside the bundle/);
rejected("zweites Bundle", [...good, { name: "Anderes.app/Contents/x", data: "x" }], /outside the bundle/);
rejected("symbolischer Verweis", [...good, { name: `${BUNDLE}/Contents/verweis`, data: "/etc/hosts", kind: "link", mode: 0o777 }], /symbolic link/);
rejected("Verweis als Ordner des Bundles", [{ name: BUNDLE, data: "/tmp", kind: "link", mode: 0o777 }, { name: `${BUNDLE}/x`, data: "x" }], /symbolic link/);
rejected("FIFO", [...good, { name: `${BUNDLE}/Contents/rohr`, kind: "fifo" }], /entry type/);
rejected("Rückstrich im Namen", [...good, { name: `${BUNDLE}/Contents\\x`, data: "x" }], /entry name/);
rejected("leerer Pfadteil", [...good, { name: `${BUNDLE}//x`, data: "x" }], /entry path/);
rejected("Punkt als Pfadteil", [...good, { name: `${BUNDLE}/./x`, data: "x" }], /entry path/);
rejected("doppelter Name", [...good, { name: `${BUNDLE}/Contents/Info.plist`, data: "anders" }], /duplicate entry/);
rejected("gleicher Name in anderer Schreibweise", [...good, { name: `${BUNDLE}/contents/info.PLIST`, data: "anders" }], /duplicate entry/);
rejected("Datei, wo ein Ordner gebraucht wird", [{ name: `${BUNDLE}/a`, data: "x" }, { name: `${BUNDLE}/a/b`, data: "y" }], /cannot be written/);
rejected("leeres Archiv", [], /entry count/);
rejected("kein Zip", null, /not a zip archive/, { prepare: ({ zip }) => writeFileSync(zip, "kein archiv") });
rejected("Zielordner besteht schon", good, /destination must be new/, { prepare: ({ dest }) => mkdirSync(dest) });

test("Aufruf ohne Bundle-Namen oder mit Pfad als Namen: 64", () => {
  for (const args of [[], ["a.zip", "out"], ["a.zip", "out", "a/b.app"], ["a.zip", "out", ".."]]) {
    assert.equal(spawnSync("python3", ["-I", SCRIPT, ...args], { encoding: "utf8" }).status, 64, JSON.stringify(args));
  }
  assert.ok(!existsSync("out"));
});
