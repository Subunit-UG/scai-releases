// Dieselben Regeln wie in resign-app-bundle.test.mjs, hier mit dem echten codesign: Nur so zeigt sich, welches
// Programm codesign in einem Bundle wirklich signiert und wie es eine Signatur beschreibt.
// Läuft nur auf macOS mit Compiler. Mit REQUIRE_CODESIGN=1 ist ein Lauf ohne beides ein Fehler.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test, { after } from "node:test";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const CODESIGN = "/usr/bin/codesign";
const TEAM = "ABCDE12345";
const IDENTITY = `Apple Development: Probe (${TEAM})`;
const CAMERA = "com.apple.security.device.camera";
const AUDIO = "com.apple.security.device.audio-input";
const available = process.platform === "darwin" && existsSync(CODESIGN) && spawnSync("cc", ["--version"]).status === 0;
if (!available && process.env.REQUIRE_CODESIGN === "1") throw new Error("codesign und ein Compiler sind hier Pflicht");
const options = { skip: available ? false : "nur auf macOS mit codesign und Compiler" };

// Steht vor dem echten codesign. Ohne Zertifikat lässt sich nur ad hoc signieren, also gilt hier: "vom Team
// signiert" heißt "über diese Hülle signiert", festgehalten am Hash der Signatur. Kennung, signiertes Programm,
// Rechte, Hardened Runtime und die Gültigkeit der Signatur prüft das echte codesign.
const WRAPPER = `#!/usr/bin/env python3
import json, os, re, subprocess, sys
REAL, TEAM = "${CODESIGN}", "${TEAM}"
book = os.path.join(os.path.dirname(os.path.abspath(__file__)), "signed.json")
def known():
    return json.load(open(book)) if os.path.exists(book) else []
def cdhash(path):
    found = re.search(rb"^CDHash=([0-9a-f]+)$", subprocess.run([REAL, "-dvvv", path], capture_output=True).stderr, re.M)
    return found.group(1).decode() if found else None
def ours(path):
    return cdhash(path) in known()
args = sys.argv[1:]
if "--sign" in args:
    args[args.index("--sign") + 1] = "-"
    done = subprocess.run([REAL, *args], capture_output=True)
    if done.returncode == 0 and cdhash(args[-1]):
        json.dump([*known(), cdhash(args[-1])], open(book, "w"))
    sys.exit(done.returncode)
team = None
if args[:2] == ["--verify", "--strict"] and len(args) == 4:
    team = re.fullmatch(r'-R=anchor apple generic and (identifier "[^"]+") and certificate leaf\\[subject\\.OU\\] = "([A-Z0-9]{10})"', args[2])
if team:
    named = subprocess.run([REAL, "--verify", "--strict", "-R=" + team.group(1), args[3]], capture_output=True).returncode
    sys.exit(named or (0 if team.group(2) == TEAM and ours(args[3]) else 3))
done = subprocess.run([REAL, *args], capture_output=True)
described = done.stderr
if args[:1] == ["-dvvv"] and ours(args[-1]):
    described = described.replace(b"TeamIdentifier=not set", b"TeamIdentifier=" + TEAM.encode())
sys.stdout.buffer.write(done.stdout)
sys.stderr.buffer.write(described)
sys.exit(done.returncode)
`;

const MANIFEST = {
  bundle: "Probe.app",
  executable: "Probe",
  identifier: "test.probe",
  entitlements: [CAMERA, AUDIO],
  code: [
    { path: "Contents/Resources/x/F.framework", identifier: "test.probe.framework", binary: "Versions/A/F" },
    { path: "Contents/Helpers/Helfer", identifier: "test.probe.helfer" },
    { path: "Contents/Applications/Innen.app", identifier: "test.probe.innen", binary: "Contents/MacOS/Innen", when: "innen" },
  ],
};
const FRAMEWORK = "Contents/Resources/x/F.framework";
const HELPER = "Contents/Helpers/Helfer";
const INNER = "Contents/Applications/Innen.app";
const plist = (program, identifier, kind, rights) => `<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict>${
  rights ? rights.map((key) => `<key>${key}</key><true/>`).join("") : `<key>CFBundleExecutable</key><string>${program}</string><key>CFBundleIdentifier</key><string>${identifier}</string><key>CFBundlePackageType</key><string>${kind}</string>`
}</dict></plist>\n`;
const SCRIPT = "#!/bin/sh\nexit 0\n";

const roots = [];
after(() => { for (const root of roots) rmSync(root, { recursive: true, force: true }); });
function scratch() {
  const root = mkdtempSync(join(tmpdir(), "resign-real-"));
  roots.push(root);
  return root;
}
const real = (...args) => spawnSync(CODESIGN, args, { encoding: "utf8" });
const py = (script, ...args) => spawnSync("python3", ["-I", join(HERE, script), ...args], { encoding: "utf8", env: { PATH: process.env.PATH } });

let compiled;
function program() {
  if (!compiled) {
    const root = scratch();
    writeFileSync(join(root, "m.c"), "int main(void){return 0;}\n");
    assert.equal(spawnSync("cc", ["-o", join(root, "tool"), join(root, "m.c")]).status, 0, "Compiler");
    compiled = join(root, "tool");
  }
  return compiled;
}

// Ein Bau, wie ihn ein fremder Bau-Schritt liefern könnte: alles ad hoc, mit fremden Kennungen und Rechten.
function build({ frameworkProgram = "F", extra } = {}) {
  const root = scratch();
  const app = join(root, "Probe.app");
  const at = (relative) => join(app, relative);
  for (const dir of ["Contents/MacOS", "Contents/Helpers", "Contents/Resources", `${FRAMEWORK}/Versions/A/Resources`, `${INNER}/Contents/MacOS`]) mkdirSync(at(dir), { recursive: true });
  for (const file of ["Contents/MacOS/Probe", HELPER, `${FRAMEWORK}/Versions/A/F`, `${INNER}/Contents/MacOS/Innen`]) copyFileSync(program(), at(file));
  symlinkSync("A", at(`${FRAMEWORK}/Versions/Current`));
  symlinkSync("Versions/Current/F", at(`${FRAMEWORK}/F`));
  symlinkSync("Versions/Current/Resources", at(`${FRAMEWORK}/Resources`));
  writeFileSync(at("Contents/Info.plist"), plist("Probe", "test.probe", "APPL"));
  writeFileSync(at(`${FRAMEWORK}/Versions/A/Resources/Info.plist`), plist(frameworkProgram, "test.probe.framework", "FMWK"));
  writeFileSync(at(`${INNER}/Contents/Info.plist`), plist("Innen", "test.probe.innen", "APPL"));
  writeFileSync(at("Contents/Resources/hinweis.txt"), "nur Text\n");
  extra?.(at);
  const hostile = join(root, "fremd.plist");
  writeFileSync(hostile, plist("", "", "", ["com.apple.security.get-task-allow", "com.apple.security.cs.disable-library-validation", CAMERA]));
  real("--force", "--options", "runtime", "--identifier", "fremd.framework", "--sign", "-", at(FRAMEWORK));
  real("--force", "--options", "runtime", "--identifier", "fremd.helfer", "--entitlements", hostile, "--sign", "-", at(HELPER));
  real("--force", "--options", "runtime", "--entitlements", hostile, "--sign", "-", at(INNER));
  real("--force", "--options", "runtime", "--entitlements", hostile, "--sign", "-", app);
  writeFileSync(join(root, "cs"), WRAPPER);
  chmodSync(join(root, "cs"), 0o755);
  writeFileSync(join(root, "liste.json"), JSON.stringify(MANIFEST));
  return { root, app, at, cs: join(root, "cs") };
}
function tool({ root, app, cs }, { team = TEAM, timestamp = "none", extra = [] } = {}) {
  const result = spawnSync("python3", ["-I", join(HERE, "resign-app-bundle.py"), app, "--manifest", join(root, "liste.json"),
    "--expect-team", team, "--timestamp", timestamp, "--with", "innen", "--codesign", cs, ...extra], {
    encoding: "utf8", env: { PATH: process.env.PATH, APPLE_SIGNING_IDENTITY: IDENTITY },
  });
  return { status: result.status, out: result.stdout + result.stderr };
}
function signed(change) {
  const made = build(change);
  const result = tool(made);
  assert.equal(result.out, "resigned and verified: 4 parts\n");
  return made;
}
const viaWrapper = ({ cs }, ...args) => assert.equal(spawnSync(cs, args, { encoding: "utf8" }).status, 0, "Signieren über die Hülle");
function rights(path) {
  const xml = real("-d", "--entitlements", "-", "--xml", path).stdout;
  return [...xml.matchAll(/<key>([^<]+)<\/key>/g)].map((found) => found[1]).sort();
}
const identifier = (path) => /^Identifier=(.*)$/m.exec(real("-dv", path).stderr)?.[1];
const rejected = (result, reason) => assert.deepEqual(result, { status: 1, out: `rejected: ${reason}\n` });

test("gepackt, ausgepackt und neu signiert: Kennungen und Rechte kommen aus der Liste, nichts vom Bau überlebt", options, () => {
  const made = build();
  assert.equal(real("--verify", "--strict", "--deep", made.app).status, 0, "der Bau ist in sich gültig signiert");
  const archive = join(made.root, "unsigned.zip");
  assert.equal(py("pack-app-bundle.py", made.app, archive).status, 0);
  rmSync(made.app, { recursive: true });
  assert.equal(py("extract-app-bundle.py", archive, join(made.root, "aus"), "Probe.app").status, 0);
  const out = { ...made, app: join(made.root, "aus", "Probe.app"), at: (relative) => join(made.root, "aus", "Probe.app", relative) };
  assert.equal(real("--verify", "--strict", "--deep", out.app).status, 0, "Packen und Auspacken ändern nichts am Bundle");
  rejected(tool(out, { extra: ["--verify-only"] }), "unexpected identifier");
  assert.deepEqual(tool(out), { status: 0, out: "resigned and verified: 4 parts\n" });
  assert.deepEqual(tool(out, { extra: ["--verify-only"] }), { status: 0, out: "verified: 4 parts\n" });
  assert.equal(real("--verify", "--strict", "--deep", out.app).status, 0);
  assert.deepEqual([out.app, out.at(FRAMEWORK), out.at(`${FRAMEWORK}/Versions/A/F`), out.at(HELPER), out.at(INNER)].map(identifier),
    ["test.probe", "test.probe.framework", "test.probe.framework", "test.probe.helfer", "test.probe.innen"]);
  assert.deepEqual(rights(out.app), [AUDIO, CAMERA]);
  for (const part of [FRAMEWORK, HELPER, INNER]) assert.deepEqual(rights(out.at(part)), []);
  for (const part of [out.app, out.at(FRAMEWORK), out.at(HELPER), out.at(INNER)]) assert.match(real("-dv", part).stderr, /flags=0x[0-9a-f]+\([^)]*runtime/);
});

test("Programmname mit Zeilenumbruch neben dem Programm der Liste: abgewiesen beim Auspacken und vor dem Signieren", options, () => {
  const made = build({
    frameworkProgram: "F\nx",
    extra: (at) => { writeFileSync(at(`${FRAMEWORK}/Versions/A/F\nx`), SCRIPT); chmodSync(at(`${FRAMEWORK}/Versions/A/F\nx`), 0o755); },
  });
  const archive = join(made.root, "unsigned.zip");
  assert.equal(py("pack-app-bundle.py", made.app, archive).status, 0);
  const unpacked = py("extract-app-bundle.py", archive, join(made.root, "aus"), "Probe.app");
  assert.deepEqual([unpacked.status, unpacked.stderr], [1, "rejected: entry name\n"]);
  rejected(tool(made), "unexpected name in the bundle");
});

test("Framework nennt ein Skript als sein Programm: abgewiesen, bevor signiert wird", options, () => {
  const made = build({
    frameworkProgram: "skript",
    extra: (at) => { writeFileSync(at(`${FRAMEWORK}/Versions/A/skript`), SCRIPT); chmodSync(at(`${FRAMEWORK}/Versions/A/skript`), 0o755); },
  });
  rejected(tool(made), "bundle description does not match");
});

test("eingebettetes Bundle mit unbekannter Endung, vom Bau signiert: abgewiesen", options, () => {
  const made = build({
    extra: (at) => {
      mkdirSync(at("Contents/PlugIns/Fremd.saver/Contents/MacOS"), { recursive: true });
      writeFileSync(at("Contents/PlugIns/Fremd.saver/Contents/Info.plist"), plist("skript", "test.fremd", "BNDL"));
      writeFileSync(at("Contents/PlugIns/Fremd.saver/Contents/MacOS/skript"), SCRIPT);
      chmodSync(at("Contents/PlugIns/Fremd.saver/Contents/MacOS/skript"), 0o755);
      real("--force", "--sign", "-", at("Contents/PlugIns/Fremd.saver"));
    },
  });
  rejected(tool(made), "unexpected code in the bundle");
});

test("nach dem Signieren verändert: jede Abweichung ist rot", options, async (t) => {
  const resignApp = (made) => {
    const granted = join(made.root, "gut.plist");
    writeFileSync(granted, plist("", "", "", [CAMERA, AUDIO]));
    viaWrapper(made, "--force", "--options", "runtime", "--identifier", "test.probe", "--entitlements", granted, "--sign", IDENTITY, made.app);
  };
  const only = (made, more = {}) => tool(made, { extra: ["--verify-only"], ...more });
  await t.test("Helfer von anderer Hand neu signiert, gleiche Kennung", () => {
    const made = signed();
    // Ein weiteres Flag, damit sich die Signatur von der über die Hülle unterscheidet: ad hoc ist sonst bytegleich.
    assert.equal(real("--force", "--options", "runtime,kill", "--identifier", "test.probe.helfer", "--sign", "-", made.at(HELPER)).status, 0);
    resignApp(made);
    rejected(only(made), "unexpected team");
  });
  await t.test("Kennung des Helfers mit Zeilenumbruch und eingeschleuster Team-Zeile", () => {
    const made = signed();
    viaWrapper(made, "--force", "--options", "runtime", "--identifier", `test.probe.helfer\nTeamIdentifier=${TEAM}`, "--sign", IDENTITY, made.at(HELPER));
    resignApp(made);
    assert.match(real("-dv", made.at(HELPER)).stderr, /^TeamIdentifier=ABCDE12345$/m, "die Beschreibung täuscht die Zeile wirklich vor");
    rejected(only(made), "unexpected identifier");
  });
  await t.test("Helfer mit Rechten", () => {
    const made = signed();
    const more = join(made.root, "mehr.plist");
    writeFileSync(more, plist("", "", "", [CAMERA]));
    viaWrapper(made, "--force", "--options", "runtime", "--identifier", "test.probe.helfer", "--entitlements", more, "--sign", IDENTITY, made.at(HELPER));
    resignApp(made);
    rejected(only(made), "unexpected entitlements");
  });
  await t.test("Helfer ohne Hardened Runtime", () => {
    const made = signed();
    viaWrapper(made, "--force", "--identifier", "test.probe.helfer", "--sign", IDENTITY, made.at(HELPER));
    resignApp(made);
    rejected(only(made), "hardened runtime missing");
  });
  await t.test("Ressource geändert", () => {
    const made = signed();
    writeFileSync(made.at("Contents/Resources/hinweis.txt"), "anderer Text\n");
    rejected(only(made), "signature does not verify");
  });
  await t.test("zusätzliches Programm", () => {
    const made = signed();
    copyFileSync(program(), made.at("Contents/MacOS/Zweites"));
    rejected(only(made), "unexpected code in the bundle");
  });
  await t.test("anderes Team erwartet", () => rejected(only(signed(), { team: "ZZZZZ99999" }), "unexpected team"));
  await t.test("Auslieferung verlangt, Signatur stammt von keinem Developer-ID-Zertifikat", () => rejected(only(signed(), { timestamp: "secure" }), "unexpected certificate"));
});
