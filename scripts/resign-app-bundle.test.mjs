import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const SCRIPT = join(HERE, "resign-app-bundle.py");
const IDENTITY = "Developer ID Application: Probe (ABCDE12345)";
const TEAM = "ABCDE12345";
const THIN = Buffer.from("cffaedfe0c00000100000000", "hex");
const FAT = Buffer.from("cafebabe0000000200000000", "hex");
const JAVA = Buffer.from("cafebabe0000003400000000", "hex");
const CAMERA = "com.apple.security.device.camera";
const AUDIO = "com.apple.security.device.audio-input";
const plist = (identifier, executable) => `<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict><key>CFBundleIdentifier</key><string>${identifier}</string><key>CFBundleExecutable</key><string>${executable}</string></dict></plist>\n`;

// Steht an der Stelle von codesign: merkt sich, was signiert wurde, und beschreibt es danach so.
const FAKE = `#!/usr/bin/env python3
import json, os, plistlib, re, sys
here = os.path.dirname(os.path.abspath(__file__))
config = json.load(open(os.path.join(here, "config.json")))
state_path = os.path.join(here, "state.json")
state = json.load(open(state_path)) if os.path.exists(state_path) else dict(config.get("presigned", {}))
args = sys.argv[1:]
rel = os.path.relpath(args[-1], config["root"])
def log(line):
    with open(config["log"], "a") as handle:
        handle.write(line + "\\n")
if args[0] == "--force":
    log("sign " + rel + " | " + " ".join(args[:-1]))
    if rel in config.get("failSign", []):
        sys.exit(1)
    entry = {"identifier": args[args.index("--identifier") + 1], "runtime": args[1:3] == ["--options", "runtime"], "stamp": "--timestamp" in args, "entitlements": {},
             "developer": args[args.index("--sign") + 1].startswith("Developer ID Application:")}
    if "--entitlements" in args:
        entry["entitlements"] = plistlib.load(open(args[args.index("--entitlements") + 1], "rb"))
    state[rel] = entry
    json.dump(state, open(state_path, "w"))
    sys.exit(0)
# Die Datei des Programms trägt die Signatur ihres Bundles, solange nichts anderes eingestellt ist.
entry = {**state.get(config.get("binaries", {}).get(rel, rel), {}), **config.get("tamper", {}).get(rel, {})}
if args[0] == "--verify" and args[1:3] == ["--strict", "--deep"]:
    log("verify " + rel + " | " + " ".join(args[:-1]))
    sys.exit(config.get("verifyExit", 0))
if args[0] == "--verify":
    # Anforderung an die Signatur: nur die beiden Formen, die das Werkzeug stellt.
    assert args[1] == "--strict" and len(args) == 4 and args[2].startswith("-R="), args
    text = args[2][3:]
    log("require " + rel + " | " + text)
    full = re.fullmatch(r'anchor apple generic and identifier "([^"]+)" and certificate leaf\\[subject\\.OU\\] = "([A-Z0-9]{10})"( and certificate 1\\[field\\.1\\.2\\.840\\.113635\\.100\\.6\\.2\\.6\\] and certificate leaf\\[field\\.1\\.2\\.840\\.113635\\.100\\.6\\.1\\.13\\])?', text)
    short = re.fullmatch(r'identifier "([^"]+)"', text)
    if not (full or short):
        sys.exit(9)
    if not entry:
        sys.exit(1)
    if full:
        ours = (entry["identifier"], entry.get("team", config["team"]), entry.get("adhoc", False)) == (full.group(1), full.group(2), False)
        sys.exit(0 if ours and (full.group(3) is None or entry.get("developer", True)) else 1)
    sys.exit(0 if entry["identifier"] == short.group(1) else 1)
if args[0] == "-dvvv":
    log("describe " + rel)
    if not entry or rel in config.get("undescribable", []):
        sys.exit(1)
    entry = {**entry, **config.get("describeTamper", {}).get(rel, {})}
    executable = os.path.normpath(os.path.join(config["root"], config.get("executables", {}).get(rel, rel)))
    sys.stderr.write("Executable=%s\\nIdentifier=%s\\nFormat=x\\nCodeDirectory v=20500 size=1 flags=0x%s hashes=1+1 location=embedded\\nTeamIdentifier=%s\\n%s%s" % (
        executable, entry["identifier"], "10000(runtime)" if entry["runtime"] else "2(adhoc)", entry.get("team", config["team"]),
        "Timestamp=1 Jan 2026 at 00:00:00\\n" if entry["stamp"] else "Signed Time=1 Jan 2026\\n", config.get("describeExtra", {}).get(rel, "")))
    sys.exit(0)
if args[:4] == ["-d", "--entitlements", "-", "--xml"]:
    log("rights " + rel)
    if not entry or rel in config.get("rightsUnreadable", []):
        sys.exit(1)
    if rel in config.get("garbage", []):
        sys.stdout.write("kein plist"); sys.exit(0)
    if rel in config.get("rightsList", []):
        sys.stdout.buffer.write(plistlib.dumps(["com.apple.security.device.camera"])); sys.exit(0)
    if entry["entitlements"]:
        sys.stdout.buffer.write(plistlib.dumps(entry["entitlements"]))
    sys.exit(0)
sys.exit(9)
`;

const FRAMEWORK = "Contents/Resources/x/F.framework";
const HELPER = "Contents/Helpers/Helfer";
const INNER = "Contents/Applications/Innen.app";
const MANIFEST = {
  bundle: "Probe.app",
  executable: "Probe",
  identifier: "test.probe",
  entitlements: [CAMERA, AUDIO],
  code: [
    { path: FRAMEWORK, identifier: "test.probe.framework", binary: "Versions/A/F" },
    { path: HELPER, identifier: "test.probe.helfer" },
    { path: INNER, identifier: "test.probe.innen", binary: "Contents/MacOS/Innen", when: "innen" },
  ],
};
const DEVELOPER_ID = " and certificate 1[field.1.2.840.113635.100.6.2.6] and certificate leaf[field.1.2.840.113635.100.6.1.13]";
// Zu welchem Bundle die Datei eines Programms gehört.
const BINARIES = { "Contents/MacOS/Probe": ".", [`${FRAMEWORK}/Versions/A/F`]: FRAMEWORK, [`${INNER}/Contents/MacOS/Innen`]: INNER };
// Welches Programm die Signatur eines Bundles trägt; beim Framework über den Verweis auf die aktuelle Fassung.
const EXECUTABLES = { ".": "Contents/MacOS/Probe", [FRAMEWORK]: `${FRAMEWORK}/Versions/Current/F`, [INNER]: `${INNER}/Contents/MacOS/Innen` };
const LAYOUT = {
  "Contents/MacOS/Probe": THIN,
  [HELPER]: THIN,
  "Contents/Info.plist": plist("test.probe", "Probe"),
  "Contents/Resources/hinweis.txt": "feedface ist nur Text",
  [`${FRAMEWORK}/Versions/A/F`]: FAT,
  [`${FRAMEWORK}/Versions/A/Resources/Info.plist`]: plist("test.probe.framework", "F"),
};
const WITH_INNER = { ...LAYOUT, [`${INNER}/Contents/MacOS/Innen`]: THIN, [`${INNER}/Contents/Info.plist`]: plist("test.probe.innen", "Innen") };
const LINKS = {
  [`${FRAMEWORK}/Versions/Current`]: "A",
  [`${FRAMEWORK}/F`]: "Versions/Current/F",
  [`${FRAMEWORK}/Resources`]: "Versions/Current/Resources",
};
const SIGNED = (identifier, entitlements = {}) => ({ identifier, runtime: true, stamp: true, entitlements, developer: true });
const RIGHTS = { [CAMERA]: true, [AUDIO]: true };
const PRESIGNED = { [FRAMEWORK]: SIGNED("test.probe.framework"), [HELPER]: SIGNED("test.probe.helfer"), ".": SIGNED("test.probe", RIGHTS) };

function run(config = {}, { args, identity = IDENTITY, layout = LAYOUT, links = LINKS, appName = "Probe.app", manifest = MANIFEST, timestamp = "secure", extra = [], prepare } = {}) {
  const root = mkdtempSync(join(tmpdir(), "resign-app-"));
  try {
    const app = join(root, appName);
    for (const [name, data] of Object.entries(layout)) {
      mkdirSync(dirname(join(app, name)), { recursive: true });
      writeFileSync(join(app, name), data);
    }
    for (const [name, target] of Object.entries(links)) symlinkSync(target, join(app, name));
    const fake = join(root, "codesign");
    writeFileSync(fake, FAKE);
    chmodSync(fake, 0o755);
    const log = join(root, "aufrufe.log");
    const list = join(root, "liste.json");
    writeFileSync(list, typeof manifest === "string" ? manifest : JSON.stringify(manifest));
    writeFileSync(join(root, "config.json"), JSON.stringify({ root: app, log, team: TEAM, executables: EXECUTABLES, binaries: BINARIES, ...config }));
    prepare?.({ root, app });
    const standard = [app, "--manifest", list, "--expect-team", TEAM, "--timestamp", timestamp, "--codesign", fake, ...extra];
    const result = spawnSync("python3", ["-I", SCRIPT, ...(args ? args({ app, list, fake }) : standard)], {
      encoding: "utf8",
      env: { PATH: process.env.PATH, ...(identity === null ? {} : { APPLE_SIGNING_IDENTITY: identity }) },
    });
    const lines = existsSync(log) ? readFileSync(log, "utf8").trim().split("\n").filter(Boolean) : [];
    const state = existsSync(join(root, "state.json")) ? JSON.parse(readFileSync(join(root, "state.json"), "utf8")) : {};
    return { status: result.status, out: result.stdout + result.stderr, lines, state, root };
  } finally { rmSync(root, { recursive: true, force: true }); }
}
const of = (lines, kind) => lines.filter((l) => l.startsWith(`${kind} `)).map((l) => l.slice(kind.length + 1).split(" | ")[0]);
const NAMES = /Contents|Helfer|Innen|Probe\.app|test\.probe|FREMD|com\.apple|hinweis/;

test("signiert genau die Teile der Liste in ihrer Reihenfolge, die App zuletzt; Kennung und Rechte kommen aus der Liste", () => {
  const r = run({}, { layout: WITH_INNER, extra: ["--with", "innen"] });
  assert.equal(r.status, 0, r.out);
  assert.equal(r.out.trim(), "resigned and verified: 4 parts");
  assert.deepEqual(of(r.lines, "sign"), [FRAMEWORK, HELPER, INNER, "."]);
  const base = "--force --options runtime --timestamp --identifier";
  const signs = r.lines.filter((l) => l.startsWith("sign ")).map((l) => l.split(" | ")[1]);
  assert.equal(signs[0], `${base} test.probe.framework --sign ${IDENTITY}`);
  assert.equal(signs[1], `${base} test.probe.helfer --sign ${IDENTITY}`);
  assert.equal(signs[2], `${base} test.probe.innen --sign ${IDENTITY}`);
  assert.match(signs[3], new RegExp(`^${base} test\\.probe --entitlements \\S+/app\\.entitlements --sign ${IDENTITY.replace(/[()]/g, "\\$&")}$`));
  // Nichts wird aus einer vorhandenen Signatur gelesen, bevor signiert ist.
  assert.equal(r.lines[0].split(" ")[0], "sign");
  assert.doesNotMatch(r.lines.filter((l) => l.startsWith("sign ")).join("\n"), /preserve-metadata|--deep/);
  assert.deepEqual(r.state["."].entitlements, RIGHTS);
  for (const part of [FRAMEWORK, HELPER, INNER]) assert.deepEqual(r.state[part].entitlements, {});
  // Danach die Prüfung: ganze Signatur, dann je Teil erst die Anforderung an das Teil und an die Datei seines
  // Programms, dann Beschreibung und Rechte.
  assert.equal(r.lines.find((l) => l.startsWith("verify ")).split(" | ")[1], "--verify --strict --deep");
  const checked = [FRAMEWORK, HELPER, INNER, "."];
  assert.deepEqual(of(r.lines, "describe"), checked);
  assert.deepEqual(of(r.lines, "rights"), checked);
  assert.deepEqual(r.lines.filter((l) => l.startsWith("require ")).map((l) => l.slice("require ".length)), [
    [FRAMEWORK, "test.probe.framework"], [`${FRAMEWORK}/Versions/A/F`, "test.probe.framework"], [HELPER, "test.probe.helfer"],
    [INNER, "test.probe.innen"], [`${INNER}/Contents/MacOS/Innen`, "test.probe.innen"], [".", "test.probe"], ["Contents/MacOS/Probe", "test.probe"],
  ].map(([path, id]) => `${path} | anchor apple generic and identifier "${id}" and certificate leaf[subject.OU] = "${TEAM}"${DEVELOPER_ID}`));
  assert.match(r.lines.map((l) => l.split(" ")[0]).join(" "), /^(sign )+verify( require( require)? describe rights)+$/);
});

test("ohne sicheren Zeitstempel, wenn so verlangt", () => {
  const r = run({}, { timestamp: "none" });
  assert.equal(r.status, 0, r.out);
  assert.equal(r.out.trim(), "resigned and verified: 3 parts");
  for (const line of r.lines.filter((l) => l.startsWith("sign "))) assert.match(line, / --timestamp=none /);
  // Ohne Auslieferung genügt jedes Zertifikat des Teams.
  for (const line of r.lines.filter((l) => l.startsWith("require "))) assert.match(line, / = "ABCDE12345"$/);
  assert.equal(run({ tamper: { [HELPER]: { developer: false } } }, { timestamp: "none" }).status, 0);
});

test("Verweise werden nicht verfolgt und nicht signiert; Text mit passendem Wort ist kein Code", () => {
  const r = run({}, {
    prepare: ({ root, app }) => {
      writeFileSync(join(root, "aussen"), THIN);
      mkdirSync(join(root, "Aussen.framework"));
      symlinkSync(join(root, "aussen"), join(app, "Contents/Resources/verweis"));
      symlinkSync(join(root, "Aussen.framework"), join(app, "Contents/Resources/Aussen.framework"));
    },
  });
  assert.equal(r.status, 0, r.out);
  assert.deepEqual(of(r.lines, "sign"), [FRAMEWORK, HELPER, "."]);
});

function refused(name, options, pattern, config = {}) {
  test(`abgewiesen, nichts signiert: ${name}`, () => {
    const r = run(config, options);
    assert.equal(r.status, 1, r.out);
    assert.match(r.out, pattern);
    assert.deepEqual(r.lines, [], "codesign wird nicht aufgerufen");
    assert.doesNotMatch(r.out, NAMES);
  });
}
const plus = (extra) => ({ layout: { ...LAYOUT, ...extra } });
refused("Programm, das nicht in der Liste steht", plus({ "Contents/MacOS/Zweites": THIN }), /unexpected code in the bundle/);
refused("Programm für mehrere Architekturen tief in den Ressourcen", plus({ "Contents/Resources/a/b/c/werkzeug": FAT }), /unexpected code in the bundle/);
refused("Datei mit der Kennzahl einer Java-Klasse", plus({ "Contents/Resources/Klasse.class": JAVA }), /unexpected code in the bundle/);
refused("Programm in einem Bundle der Liste, das dort nicht steht", plus({ [`${FRAMEWORK}/Versions/A/Helfer`]: THIN }), /unexpected code in the bundle/);
refused("eingebettetes Bundle, das nicht in der Liste steht", plus({ "Contents/PlugIns/Fremd.plugin/Contents/Info.plist": "x" }), /unexpected code in the bundle/);
refused("eingebettetes Bundle mit unbekannter Endung", plus({ "Contents/PlugIns/Fremd.saver/Contents/Info.plist": "x", "Contents/PlugIns/Fremd.saver/Contents/MacOS/skript": "#!/bin/sh\n" }), /unexpected code in the bundle/);
refused("Signatur-Ordner an fremder Stelle", plus({ "Contents/Resources/y/_CodeSignature/CodeResources": "x" }), /unexpected code in the bundle/);
refused("Bundle-Beschreibung an fremder Stelle", plus({ "Contents/Resources/y/Info.plist": "x" }), /unexpected code in the bundle/);
refused("Bundle-Beschreibung in anderer Schreibweise", plus({ "Contents/Resources/y/info.PLIST": "x" }), /unexpected code in the bundle/);
refused("zweite Fassung im Framework der Liste", plus({ [`${FRAMEWORK}/Versions/B/Resources/Info.plist`]: "x" }), /unexpected code in the bundle/);
refused("Bundle-Beschreibung eines Teils ist ein Verweis", {
  layout: Object.fromEntries(Object.entries(LAYOUT).filter(([name]) => name !== `${FRAMEWORK}/Versions/A/Resources/Info.plist`)),
  prepare: ({ app }) => { mkdirSync(join(app, FRAMEWORK, "Versions/A/Resources"), { recursive: true }); symlinkSync("../../../../hinweis.txt", join(app, FRAMEWORK, "Versions/A/Resources/Info.plist")); },
}, /unexpected code in the bundle/);
refused("Framework mit einem Ordner wie in einer App", plus({ [`${FRAMEWORK}/Contents/MacOS/F`]: "#!/bin/sh\n" }), /^rejected: bundle description does not match\n$/);
refused("Framework mit einem Ordner für Hilfsdateien", plus({ [`${FRAMEWORK}/Support Files/F`]: "#!/bin/sh\n" }), /^rejected: bundle description does not match\n$/);
refused("Framework mit einem Verweis namens Contents", { links: { ...LINKS, [`${FRAMEWORK}/Contents`]: "Versions/A" } }, /^rejected: bundle description does not match\n$/);
refused("Dateiname mit Zeilenumbruch", plus({ "Contents/Resources/a\nb": "x" }), /^rejected: unexpected name in the bundle\n$/);
refused("Ordnername mit Steuerzeichen", plus({ "Contents/Resources/a\u0007/b": "x" }), /^rejected: unexpected name in the bundle\n$/);
refused("Verweis mit Zeilenumbruch im Namen", { prepare: ({ app }) => symlinkSync("hinweis.txt", join(app, "Contents/Resources/a\rb")) }, /^rejected: unexpected name in the bundle\n$/);
refused("Programm mit Zeilenumbruch neben dem Programm der Liste", plus({
  [`${FRAMEWORK}/Versions/A/Resources/Info.plist`]: plist("test.probe.framework", "F\nx"), [`${FRAMEWORK}/Versions/A/F\nx`]: "#!/bin/sh\n",
}), /^rejected: unexpected name in the bundle\n$/);
refused("Beschreibung in der Fassung für eine Plattform neben der des Frameworks", plus({
  [`${FRAMEWORK}/Versions/A/Resources/Info-macos.plist`]: plist("test.probe.framework", "skript"), [`${FRAMEWORK}/Versions/A/skript`]: "#!/bin/sh\n",
}), /^rejected: unexpected code in the bundle\n$/);
refused("Beschreibung in der Fassung für eine Plattform neben der der App, andere Schreibweise", plus({ "Contents/INFO~Mac.PLIST": "x" }), /^rejected: unexpected code in the bundle\n$/);
refused("Framework nennt nur für eine Plattform ein anderes Programm", plus({
  [`${FRAMEWORK}/Versions/A/Resources/Info.plist`]: plist("test.probe.framework", "F").replace("</dict>", "<key>CFBundleExecutable-macos</key><string>skript</string></dict>"), [`${FRAMEWORK}/Versions/A/skript`]: "#!/bin/sh\n",
}), /^rejected: bundle description does not match\n$/);
refused("App nennt nur für eine Plattform ein anderes Programm", plus({ "Contents/Info.plist": plist("test.probe", "Probe").replace("</dict>", "<key>CFBundleExecutable-macos</key><string>skript</string></dict>") }), /^rejected: bundle description does not match\n$/);
refused("App nennt nur für eine Plattform eine andere Kennung", plus({
  "Contents/Info.plist": plist("test.probe", "Probe").replace("</dict>", "<key>cfbundleidentifier~mac</key><string>test.fremd</string></dict>"),
}), /^rejected: bundle description does not match\n$/);
refused("Framework nennt ein anderes Programm", plus({
  [`${FRAMEWORK}/Versions/A/Resources/Info.plist`]: plist("test.probe.framework", "skript"), [`${FRAMEWORK}/Versions/A/skript`]: "#!/bin/sh\n",
}), /^rejected: bundle description does not match\n$/);
refused("Framework nennt ein Programm mit Zeilenumbruch", plus({ [`${FRAMEWORK}/Versions/A/Resources/Info.plist`]: plist("test.probe.framework", "F\nx") }), /^rejected: bundle description does not match\n$/);
refused("Framework ohne Beschreibung", {
  layout: Object.fromEntries(Object.entries(LAYOUT).filter(([name]) => name !== `${FRAMEWORK}/Versions/A/Resources/Info.plist`)),
}, /^rejected: bundle description cannot be read\n$/);
refused("Beschreibung des Frameworks ist nur über einen Verweis erreichbar", {
  layout: Object.fromEntries(Object.entries(LAYOUT).filter(([name]) => name !== `${FRAMEWORK}/Versions/A/Resources/Info.plist`)),
  prepare: ({ root, app }) => {
    mkdirSync(join(root, "aussen"));
    writeFileSync(join(root, "aussen/Info.plist"), plist("test.probe.framework", "F"));
    symlinkSync(join(root, "aussen"), join(app, FRAMEWORK, "Versions/A/Resources"));
  },
}, /^rejected: bundle description cannot be read\n$/);
refused("Beschreibung des Frameworks ist nicht lesbar", plus({ [`${FRAMEWORK}/Versions/A/Resources/Info.plist`]: "kein plist" }), /^rejected: bundle description cannot be read\n$/);
refused("eingebettete App nennt ein anderes Programm", {
  layout: { ...WITH_INNER, [`${INNER}/Contents/Info.plist`]: plist("test.probe.innen", "Anderes") }, extra: ["--with", "innen"],
}, /^rejected: bundle description does not match\n$/);
refused("aktuelle Fassung des Frameworks zeigt woandershin", { links: { ...LINKS, [`${FRAMEWORK}/Versions/Current`]: "B" } }, /^rejected: bundle description does not match\n$/);
refused("aktuelle Fassung des Frameworks zeigt über einen Umweg auf dieselbe", { links: { ...LINKS, [`${FRAMEWORK}/Versions/Current`]: "../Versions/A" } }, /^rejected: bundle description does not match\n$/);
refused("Framework ohne Verweis auf die aktuelle Fassung", { links: {} }, /^rejected: bundle description does not match\n$/);
refused("aktuelle Fassung des Frameworks ist ein Ordner", { links: {}, prepare: ({ app }) => mkdirSync(join(app, FRAMEWORK, "Versions/Current")) }, /^rejected: bundle description does not match\n$/);
refused("Beschreibung der App fehlt", { layout: Object.fromEntries(Object.entries(LAYOUT).filter(([name]) => name !== "Contents/Info.plist")) }, /^rejected: bundle description cannot be read\n$/);
refused("eingebettete App ohne ihr Kennwort im Aufruf", { layout: WITH_INNER }, /unexpected code in the bundle/);
refused("eingebettete App verlangt, aber nicht im Bundle", { extra: ["--with", "innen"] }, /expected code missing/);
refused("ein Teil der Liste fehlt", { layout: Object.fromEntries(Object.entries(LAYOUT).filter(([name]) => name !== HELPER)) }, /expected code missing/);
refused("ein Teil der Liste ist kein Programm", plus({ [HELPER]: "#!/bin/sh\n" }), /expected code missing/);
refused("ein Teil der Liste ist nur ein Verweis", {
  layout: Object.fromEntries(Object.entries(LAYOUT).filter(([name]) => name !== HELPER)),
  prepare: ({ root, app }) => { writeFileSync(join(root, "aussen"), THIN); mkdirSync(join(app, "Contents/Helpers")); symlinkSync(join(root, "aussen"), join(app, HELPER)); },
}, /expected code missing/);
refused("Bundle heißt anders als in der Liste", { appName: "Andere.app" }, /not the expected bundle/);
refused("Kennung im Bundle weicht ab", plus({ "Contents/Info.plist": plist("test.fremd", "Probe") }), /bundle description does not match/);
refused("Hauptprogramm im Bundle weicht ab", plus({ "Contents/Info.plist": plist("test.probe", "Helfer") }), /bundle description does not match/);
refused("Beschreibung des Bundles ist nicht lesbar", plus({ "Contents/Info.plist": "kein plist" }), /bundle description cannot be read/);

test("abgewiesen, nichts signiert: eine Datei im Bundle ist nicht lesbar", { skip: process.getuid?.() === 0 }, () => {
  const r = run({}, { prepare: ({ app }) => chmodSync(join(app, "Contents/Resources/hinweis.txt"), 0o000) });
  assert.equal(r.status, 1, r.out);
  assert.match(r.out, /^rejected: bundle cannot be read\n$/);
  assert.deepEqual(r.lines, []);
});

test("abgewiesen, nichts signiert: mehr Dateien als die Grenze", () => {
  const r = run({}, {
    prepare: ({ app }) => {
      mkdirSync(join(app, "Contents/Resources/viele"));
      for (let i = 0; i < 20000; i += 1) writeFileSync(join(app, "Contents/Resources/viele", `d${i}`), "");
    },
  });
  assert.equal(r.status, 1, r.out);
  assert.match(r.out, /^rejected: too many files\n$/);
  assert.deepEqual(r.lines, []);
});

test("abgewiesen: das Bundle selbst ist ein Verweis", () => {
  const r = run({}, { layout: {}, links: {}, appName: "Echt.app", args: ({ list, fake }) => ["Probe.app", "--manifest", list, "--expect-team", TEAM, "--timestamp", "secure", "--codesign", fake], prepare: ({ root }) => symlinkSync(join(root, "Echt.app"), join(root, "Probe.app")) });
  assert.equal(r.status, 1, r.out);
  assert.match(r.out, /not the expected bundle/);
});

function unverified(name, config, pattern) {
  test(`rot nach dem Signieren: ${name}`, () => {
    const r = run(config);
    assert.equal(r.status, 1, r.out);
    assert.match(r.out, pattern);
    assert.doesNotMatch(r.out, NAMES);
  });
}
unverified("die Signatur des Bundles gilt nicht", { verifyExit: 1 }, /signature does not verify/);
unverified("ein Teil trägt eine andere Kennung", { tamper: { [HELPER]: { identifier: "test.fremd" } } }, /unexpected identifier/);
unverified("die Kennung steht nur als Teil einer längeren da", { tamper: { [HELPER]: { identifier: "test.probe.helfer.zwei" } } }, /unexpected identifier/);
unverified("ein Teil trägt ein anderes Team", { tamper: { [HELPER]: { team: "FREMDES123" } } }, /unexpected team/);
unverified("ein Teil ohne Hardened Runtime", { tamper: { [FRAMEWORK]: { runtime: false } } }, /hardened runtime missing/);
unverified("ein Teil ist nur ad hoc signiert", { tamper: { [HELPER]: { adhoc: true } } }, /^rejected: unexpected team\n$/);
unverified("Kennung mit eingeschleuster Team-Zeile", { tamper: { [HELPER]: { identifier: `test.probe.helfer\nTeamIdentifier=${TEAM}`, team: "not set", adhoc: true } } }, /^rejected: unexpected identifier\n$/);
unverified("die Datei im Framework trägt nur die Signatur des Baus", { tamper: { [`${FRAMEWORK}/Versions/A/F`]: { adhoc: true } } }, /^rejected: unexpected team\n$/);
unverified("die Datei im Framework trägt eine andere Kennung", { tamper: { [`${FRAMEWORK}/Versions/A/F`]: { identifier: "test.fremd" } } }, /^rejected: unexpected identifier\n$/);
unverified("das Hauptprogramm der App trägt nur die Signatur des Baus", { tamper: { "Contents/MacOS/Probe": { adhoc: true } } }, /^rejected: unexpected team\n$/);
unverified("ein Teil trägt ein anderes Zertifikat des Teams als eine Developer ID", { tamper: { [HELPER]: { developer: false } } }, /^rejected: unexpected certificate\n$/);
unverified("die Datei im Framework trägt ein anderes Zertifikat des Teams", { tamper: { [`${FRAMEWORK}/Versions/A/F`]: { developer: false } } }, /^rejected: unexpected certificate\n$/);
unverified("Beschreibung nennt eine andere Kennung als die Anforderung", { describeTamper: { [HELPER]: { identifier: "test.fremd" } } }, /^rejected: unexpected identifier\n$/);
unverified("Beschreibung nennt ein anderes Team als die Anforderung", { describeTamper: { ".": { team: "FREMDES123" } } }, /^rejected: unexpected team\n$/);
unverified("ein Feld der Beschreibung steht zweimal da", { describeExtra: { [HELPER]: `TeamIdentifier=${TEAM}\n` } }, /^rejected: signature cannot be read\n$/);
unverified("zweite Zeile mit Kennung in der Beschreibung", { describeExtra: { ".": "Identifier=test.probe\n" } }, /^rejected: signature cannot be read\n$/);
unverified("die Signatur eines Bundles der Liste trägt ein anderes Programm", { executables: { ...EXECUTABLES, [FRAMEWORK]: `${FRAMEWORK}/Versions/A/skript` } }, /^rejected: unexpected executable\n$/);
unverified("die Signatur der App trägt ein anderes Programm", { executables: { ...EXECUTABLES, ".": HELPER } }, /^rejected: unexpected executable\n$/);
unverified("die Signatur einer Datei der Liste gehört zu einer anderen Datei", { executables: { ...EXECUTABLES, [HELPER]: "Contents/MacOS/Probe" } }, /^rejected: unexpected executable\n$/);
unverified("ein Teil ohne sicheren Zeitstempel", { tamper: { [HELPER]: { stamp: false } } }, /secure timestamp missing/);
unverified("die App ohne sicheren Zeitstempel", { tamper: { ".": { stamp: false } } }, /secure timestamp missing/);
unverified("ein Teil trägt Rechte", { tamper: { [HELPER]: { entitlements: { [CAMERA]: true } } } }, /unexpected entitlements/);
unverified("die App trägt ein Recht mehr", { tamper: { ".": { entitlements: { ...RIGHTS, "com.apple.security.get-task-allow": true } } } }, /unexpected entitlements/);
unverified("der App fehlt ein Recht", { tamper: { ".": { entitlements: { [CAMERA]: true } } } }, /unexpected entitlements/);
unverified("ein Recht der App hat einen anderen Wert", { tamper: { ".": { entitlements: { [CAMERA]: true, [AUDIO]: "ja" } } } }, /unexpected entitlements/);
unverified("Rechte sind nicht lesbar", { garbage: [HELPER] }, /^rejected: entitlements cannot be read\n$/);
unverified("Rechte sind eine Liste statt einer Zuordnung", { rightsList: [HELPER] }, /^rejected: entitlements cannot be read\n$/);
unverified("codesign liest die Rechte eines Teils nicht", { rightsUnreadable: [HELPER] }, /^rejected: signature cannot be read\n$/);
unverified("codesign liest die Rechte der App nicht", { rightsUnreadable: ["."] }, /^rejected: signature cannot be read\n$/);
unverified("codesign beschreibt ein Teil nicht", { undescribable: [HELPER] }, /^rejected: signature cannot be read\n$/);
unverified("codesign beschreibt die App nicht", { undescribable: ["."] }, /^rejected: signature cannot be read\n$/);

test("Signieren scheitert: Abbruch an dieser Stelle, das Äußere bleibt unsigniert", () => {
  const r = run({ failSign: [HELPER] });
  assert.equal(r.status, 1, r.out);
  assert.match(r.out, /signing failed/);
  assert.deepEqual(of(r.lines, "sign"), [FRAMEWORK, HELPER]);
});

test("codesign lässt sich nicht starten", () => {
  const r = run({}, { args: ({ app, list }) => [app, "--manifest", list, "--expect-team", TEAM, "--timestamp", "secure", "--codesign", "/nicht/vorhanden"] });
  assert.equal(r.status, 1, r.out);
  assert.match(r.out, /codesign cannot be run/);
});

test("nur prüfen: ohne Identität, ohne Signieren; dieselben Regeln", () => {
  const only = (config) => run({ presigned: PRESIGNED, ...config }, { identity: null, extra: ["--verify-only"] });
  const good = only({});
  assert.equal(good.status, 0, good.out);
  assert.equal(good.out.trim(), "verified: 3 parts");
  assert.deepEqual(of(good.lines, "sign"), []);
  assert.equal(only({ tamper: { [HELPER]: { identifier: "test.fremd" } } }).status, 1);
  assert.equal(only({ tamper: { [HELPER]: { entitlements: { [CAMERA]: true } } } }).status, 1);
  assert.equal(only({ tamper: { ".": { team: "FREMDES123" } } }).status, 1);
  assert.equal(only({ verifyExit: 1 }).status, 1);
  const unsigned = only({ presigned: { ".": PRESIGNED["."] } });
  assert.equal(unsigned.status, 1);
  assert.match(unsigned.out, /^rejected: unexpected identifier\n$/);
  assert.equal(only({ tamper: { [FRAMEWORK]: { adhoc: true } } }).status, 1);
  assert.equal(only({ executables: { ...EXECUTABLES, [FRAMEWORK]: HELPER } }).status, 1);
  const extra = run({ presigned: PRESIGNED }, { identity: null, extra: ["--verify-only"], layout: { ...LAYOUT, "Contents/MacOS/Zweites": THIN } });
  assert.equal(extra.status, 1);
  assert.match(extra.out, /unexpected code in the bundle/);
});

test("Aufruf: Liste, Identität, Team, Zeitstempel und genau ein Bundle sind Pflicht; ad hoc gilt nicht", () => {
  const usage = (make, identity) => run({}, { args: make, identity }).status;
  const full = ({ app, list }) => [app, "--manifest", list, "--expect-team", TEAM, "--timestamp", "secure"];
  const without = (flag) => (ctx) => { const a = full(ctx); a.splice(a.indexOf(flag), 2); return a; };
  assert.equal(usage(without("--manifest")), 64);
  assert.equal(usage(without("--expect-team")), 64);
  assert.equal(usage(without("--timestamp")), 64);
  assert.equal(usage((ctx) => full(ctx).slice(1)), 64);
  assert.equal(usage((ctx) => [...full(ctx), "Zweite.app"]), 64);
  assert.equal(usage((ctx) => [...full(ctx).slice(0, -1), "vielleicht"]), 64);
  assert.equal(usage((ctx) => [...full(ctx), "--timestamp"]), 64);
  assert.equal(usage((ctx) => [...full(ctx), "--unbekannt"]), 64);
  assert.equal(usage((ctx) => [...full(ctx), "--with", "unbekannt"]), 64);
  assert.equal(usage((ctx) => [...full(ctx), "--allow-entitlement", CAMERA]), 64);
  assert.equal(usage(({ app, list }) => [app, "--manifest", list, "--expect-team", "kurz", "--timestamp", "secure"]), 64);
  assert.equal(usage(({ app, list }) => [app, "--manifest", list, "--expect-team", "abcde12345", "--timestamp", "secure"]), 64);
  assert.equal(usage(({ app }) => [app, "--manifest", "/nicht/vorhanden.json", "--expect-team", TEAM, "--timestamp", "secure"]), 64);
  assert.equal(usage(full, null), 64);
  assert.equal(usage(full, ""), 64);
  assert.equal(usage(full, "-"), 64);
  assert.equal(usage(full, "--force"), 64);
});

test("Liste: nur schlichte Pfade im Bundle, eindeutige Teile, Rechte nur von Apple", () => {
  const broken = (change) => {
    const manifest = structuredClone(MANIFEST);
    change(manifest);
    const r = run({}, { manifest });
    assert.equal(r.status, 64, JSON.stringify(manifest));
    assert.deepEqual(r.lines, []);
  };
  broken((m) => { m.code[1].path = "../Helfer"; });
  broken((m) => { m.code[1].path = "/usr/bin/true"; });
  broken((m) => { m.code[1].path = "Contents/./Helfer"; });
  broken((m) => { m.code[1].path = "Contents//Helfer"; });
  broken((m) => { m.code[1].path = "Contents/Helpers/-rf"; });
  broken((m) => { m.code[0].binary = "../../MacOS/Probe"; });
  broken((m) => { delete m.code[0].binary; });
  broken((m) => { m.code[1].binary = "Helfer"; });
  broken((m) => { m.code[0].binary = "F"; });
  broken((m) => { m.code[0].binary = "Versions/A/x/F"; });
  broken((m) => { m.code[2].binary = "Contents/Helpers/Innen"; });
  broken((m) => { m.code[1].identifier = "--sign"; });
  broken((m) => { m.code[1].identifier = ""; });
  broken((m) => { m.code[1].extra = true; });
  broken((m) => { m.code.push({ ...m.code[1] }); });
  broken((m) => { m.code.push({ path: "Contents/MacOS/Probe", identifier: "test.zwei" }); });
  broken((m) => { m.code = "alles"; });
  broken((m) => { m.code[1] = "Contents/Helpers/Helfer"; });
  broken((m) => { m.bundle = "Probe"; });
  broken((m) => { m.bundle = "../Probe.app"; });
  broken((m) => { m.executable = "../Probe"; });
  broken((m) => { m.identifier = "test probe"; });
  broken((m) => { m.entitlements = [CAMERA, CAMERA]; });
  broken((m) => { m.entitlements = ["keychain-access-groups"]; });
  broken((m) => { m.entitlements = { [CAMERA]: true }; });
  broken((m) => { delete m.entitlements; });
  assert.equal(run({}, { manifest: "kein json" }).status, 64);
  assert.equal(run({}, { manifest: "[]" }).status, 64);
});

// Die Listen dieses Repos: genau diese Teile, Kennungen und Rechte.
const REAL = {
  "notch.json": {
    main: ["SubunitNotch.app", "SubunitNotch", "co.subunit.notch"],
    rights: ["com.apple.security.automation.apple-events", "com.apple.security.device.audio-input", "com.apple.security.device.camera"],
    parts: [
      ["Contents/Resources/mediaremote-adapter/MediaRemoteAdapter.framework", "com.vandenbe.MediaRemoteAdapter", "Versions/A/MediaRemoteAdapter"],
      ["Contents/Helpers/SubunitAgentBridge", "co.subunit.notch.agent-bridge"],
    ],
    tagged: { zentrale: [["Contents/Applications/Notch-Zentrale.app", "co.subunit.notch.zentrale", "Contents/MacOS/NotchZentrale"]] },
  },
  "charge.json": {
    main: ["Subunit Charge.app", "SubunitCharge", "co.subunit.charge"],
    rights: [],
    parts: [["Contents/MacOS/SubunitChargeHelper", "co.subunit.charge.helper"]],
    tagged: {},
  },
};
for (const [file, expected] of Object.entries(REAL)) {
  const tags = Object.keys(expected.tagged);
  for (const chosen of [[], ...tags.map((t) => [t])]) {
    test(`Liste ${file}${chosen.length ? ` mit ${chosen.join(", ")}` : ""}: genau die erwarteten Teile, Kennungen und Rechte`, () => {
      const manifest = readFileSync(join(HERE, "..", "config", "signing", file), "utf8");
      const [bundle, executable, identifier] = expected.main;
      const parts = [...expected.parts, ...chosen.flatMap((t) => expected.tagged[t])];
      const layout = { "Contents/Info.plist": plist(identifier, executable), [`Contents/MacOS/${executable}`]: THIN };
      const executables = { ".": `Contents/MacOS/${executable}` };
      const binaries = { [`Contents/MacOS/${executable}`]: "." };
      const links = {};
      for (const [path, id, binary] of parts) {
        layout[binary ? `${path}/${binary}` : path] = THIN;
        if (!binary) continue;
        executables[path] = `${path}/${binary}`;
        binaries[`${path}/${binary}`] = path;
        const [first, version, program] = binary.split("/");
        if (first === "Versions") {
          layout[`${path}/Versions/${version}/Resources/Info.plist`] = plist(id, program);
          links[`${path}/Versions/Current`] = version;
        } else layout[`${path}/Contents/Info.plist`] = plist(id, program);
      }
      const r = run({ executables, binaries }, { manifest, layout, links, appName: bundle, extra: chosen.flatMap((t) => ["--with", t]) });
      assert.equal(r.status, 0, r.out);
      assert.deepEqual(of(r.lines, "sign"), [...parts.map(([path]) => path), "."]);
      for (const [path, id] of parts) assert.deepEqual(r.state[path], SIGNED(id));
      assert.deepEqual(r.state["."], SIGNED(identifier, Object.fromEntries(expected.rights.map((key) => [key, true]))));
      assert.deepEqual(Object.keys(JSON.parse(manifest)).sort(), ["bundle", "code", "entitlements", "executable", "identifier"]);
    });
  }
}
