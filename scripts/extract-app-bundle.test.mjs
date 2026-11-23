import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, readlinkSync, rmSync, writeFileSync } from "node:fs";
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
        z.writestr(info, bytes.fromhex(e["hex"]) if "hex" in e else e.get("data", ""))
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

rejected("Pfad nach oben", [...good, { name: `${BUNDLE}/../draussen.txt`, data: "x" }], /^rejected: entry path\n$/);
rejected("Pfad nach oben am Anfang", [{ name: "../draussen.txt", data: "x" }], /^rejected: entry path\n$/);
rejected("absoluter Pfad", [...good, { name: "/tmp/draussen.txt", data: "x" }], /^rejected: entry name\n$/);
rejected("Eintrag neben dem Bundle", [...good, { name: "zusatz.sh", data: "x" }], /^rejected: entry outside the bundle\n$/);
rejected("zweites Bundle", [...good, { name: "Anderes.app/Contents/x", data: "x" }], /^rejected: entry outside the bundle\n$/);
// Verweise: nur die Form eines Frameworks (relatives Ziel aus einfachen Namen, im Bundle vorhanden).
const link = (name, data) => ({ name: `${BUNDLE}/${name}`, data, kind: "link", mode: 0o777 });
const FW = "Contents/Resources/x/Probe.framework";
const framework = [
  ...good,
  { name: `${BUNDLE}/${FW}/Versions/A/Probe`, data: "bin", mode: 0o755 },
  { name: `${BUNDLE}/${FW}/Versions/A/Resources/Info.plist`, data: "<plist/>" },
  link(`${FW}/Versions/Current`, "A"),
  link(`${FW}/Probe`, "Versions/Current/Probe"),
  link(`${FW}/Resources`, "Versions/Current/Resources"),
];

test("die Verweise eines Frameworks bleiben Verweise und zeigen ins Bundle", () => {
  const r = run(framework);
  try {
    assert.equal(r.status, 0, r.out);
    assert.match(r.out, /extracted: 5 files, 3 links/);
    const fw = join(r.dest, BUNDLE, FW);
    assert.equal(readlinkSync(join(fw, "Versions/Current")), "A");
    assert.equal(readlinkSync(join(fw, "Probe")), "Versions/Current/Probe");
    assert.equal(readlinkSync(join(fw, "Resources")), "Versions/Current/Resources");
    assert.equal(readFileSync(join(fw, "Probe"), "utf8"), "bin");
    assert.ok(!lstatSync(join(fw, "Versions/A/Probe")).isSymbolicLink());
  } finally { rmSync(r.root, { recursive: true, force: true }); }
});

rejected("Verweis mit absolutem Ziel", [...good, link("Contents/verweis", "/etc/hosts")], /^rejected: link target\n$/);
rejected("Verweis nach oben", [...good, link("Contents/verweis", "../../draussen")], /^rejected: link target\n$/);
rejected("Verweis nach oben in der Mitte", [...good, link("Contents/verweis", "MacOS/../../../draussen")], /^rejected: link target\n$/);
rejected("Verweis mit Punkt", [...good, link("Contents/verweis", "./MacOS/probe")], /^rejected: link target\n$/);
rejected("Verweis mit leerem Ziel", [...good, link("Contents/verweis", "")], /^rejected: link target\n$/);
rejected("Verweis mit Rückstrich", [...good, link("Contents/verweis", "MacOS\\probe")], /^rejected: link target\n$/);
rejected("Verweis mit Ziel, das kein Text ist", [...good, { ...link("Contents/verweis", ""), hex: "fffe41" }], /^rejected: link target\n$/);
rejected("Verweis mit Nullzeichen im Ziel", [...good, { ...link("Contents/verweis", ""), hex: "4d61634f530070726f6265" }], /^rejected: link target\n$/);
rejected("Verweis mit überlangem Ziel", [...good, link("Contents/verweis", "a".repeat(256))], /^rejected: symbolic link\n$/);
rejected("Verweis ins Leere", [...good, link("Contents/verweis", "MacOS/fehlt")], /^rejected: link target missing\n$/);
rejected("Verweise im Kreis", [...good, link("Contents/a", "b"), link("Contents/b", "a")], /^rejected: link target missing\n$/);
rejected("Eintrag unter einem Verweis", [...good, link("Contents/verweis", "MacOS"), { name: `${BUNDLE}/Contents/verweis/neu`, data: "x" }], /^rejected: entry below a link\n$/);
rejected("Eintrag unter einem Verweis in anderer Schreibweise", [...good, link("Contents/Verweis", "MacOS"), { name: `${BUNDLE}/Contents/verweis/neu`, data: "x" }], /^rejected: entry below a link\n$/);
rejected("Verweis und Datei mit demselben Namen", [...good, link("Contents/Info.plist", "MacOS/probe")], /^rejected: duplicate entry\n$/);
rejected("Verweis als Ordner des Bundles", [{ name: BUNDLE, data: "/tmp", kind: "link", mode: 0o777 }, { name: `${BUNDLE}/x`, data: "x" }], /^rejected: symbolic link\n$/);
rejected("Verweis mit Ordner-Namen", [...good, { name: `${BUNDLE}/Contents/verweis/`, data: "MacOS", kind: "link", mode: 0o777 }], /^rejected: symbolic link\n$/);
rejected("FIFO", [...good, { name: `${BUNDLE}/Contents/rohr`, kind: "fifo" }], /^rejected: entry type\n$/);
rejected("Rückstrich im Namen", [...good, { name: `${BUNDLE}/Contents\\x`, data: "x" }], /^rejected: entry name\n$/);
rejected("leerer Pfadteil", [...good, { name: `${BUNDLE}//x`, data: "x" }], /^rejected: entry path\n$/);
rejected("Punkt als Pfadteil", [...good, { name: `${BUNDLE}/./x`, data: "x" }], /^rejected: entry path\n$/);
rejected("doppelter Name", [...good, { name: `${BUNDLE}/Contents/Info.plist`, data: "anders" }], /^rejected: duplicate entry\n$/);
rejected("gleicher Name in anderer Schreibweise", [...good, { name: `${BUNDLE}/contents/info.PLIST`, data: "anders" }], /^rejected: duplicate entry\n$/);
rejected("Datei, wo ein Ordner gebraucht wird", [{ name: `${BUNDLE}/a`, data: "x" }, { name: `${BUNDLE}/a/b`, data: "y" }], /^rejected: entry cannot be written\n$/);
// Felder im Inhaltsverzeichnis des Archivs nachträglich ändern (das schreibt keine Bibliothek so).
function central(zip, entryName, change) {
  const data = readFileSync(zip);
  let at = -1;
  for (let i = data.indexOf("PK\u0001\u0002", 0, "latin1"); i >= 0; i = data.indexOf("PK\u0001\u0002", i + 4, "latin1")) {
    const length = data.readUInt16LE(i + 28);
    if (data.subarray(i + 46, i + 46 + length).toString("utf8") === entryName) at = i;
  }
  assert.ok(at >= 0, "Eintrag im Inhaltsverzeichnis gefunden");
  change(data, at);
  writeFileSync(zip, data);
}
rejected("verschlüsselter Eintrag", good, /^rejected: encrypted entry\n$/, {
  prepare: ({ zip }) => central(zip, `${BUNDLE}/Contents/Info.plist`, (data, at) => data.writeUInt16LE(data.readUInt16LE(at + 8) | 1, at + 8)),
});
rejected("angegebene Größe über der Grenze", good, /^rejected: archive size\n$/, {
  prepare: ({ zip }) => central(zip, `${BUNDLE}/Contents/Info.plist`, (data, at) => data.writeUInt32LE(0x7fffffff, at + 24)),
});
rejected("Verweis mit falscher Prüfsumme", [...good, link("Contents/verweis", "MacOS/probe")], /^rejected: entry cannot be written\n$/, {
  prepare: ({ zip }) => central(zip, `${BUNDLE}/Contents/verweis`, (data, at) => data.writeUInt32LE((data.readUInt32LE(at + 16) ^ 1) >>> 0, at + 16)),
});
rejected("Name im Archiv ist kein gültiger Text", good, /^rejected: (archive cannot be read|not a zip archive|entry [a-z ]+)\n$/, {
  // Kennzeichen für UTF-8 gesetzt, der Name selbst ist es nicht: Die Bibliothek scheitert schon beim Öffnen.
  prepare: ({ zip }) => central(zip, `${BUNDLE}/Contents/Info.plist`, (data, at) => { data.writeUInt16LE(data.readUInt16LE(at + 8) | 0x800, at + 8); data[at + 46] = 0xff; }),
});
rejected("das Bundle ist eine Datei", [{ name: BUNDLE, data: "x" }], /^rejected: archive does not hold exactly the bundle\n$/);
rejected("leeres Archiv", [], /^rejected: entry count\n$/);
rejected("kein Zip", null, /^rejected: not a zip archive\n$/, { prepare: ({ zip }) => writeFileSync(zip, "kein archiv") });
rejected("Zielordner besteht schon", good, /^rejected: destination must be new\n$/, { prepare: ({ dest }) => mkdirSync(dest) });

test("Aufruf ohne Bundle-Namen oder mit Pfad als Namen: 64", () => {
  for (const args of [[], ["a.zip", "out"], ["a.zip", "out", "a/b.app"], ["a.zip", "out", ".."]]) {
    assert.equal(spawnSync("python3", ["-I", SCRIPT, ...args], { encoding: "utf8" }).status, 64, JSON.stringify(args));
  }
  assert.ok(!existsSync("out"));
});
