import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), "load-signing-identity.sh");
const CERTIFICATE = Buffer.from([0x30, 0x82, 0x00, 0xff, 0x01, 0x02, 0x03, 0x0a, 0x00, 0x7f]);
const PASSWORD = "Zertifikat Kennwort 4711";
const NAME = "Developer ID Application: Geheimer Name (ABCDE12345)";

// Steht an der Stelle von `security`: schreibt jeden Aufruf mit und hält fest, wie die Zertifikatsdatei aussah.
const FAKE = `#!/usr/bin/env python3
import json, os, stat, sys
here = os.path.dirname(os.path.abspath(__file__))
config = json.load(open(os.path.join(here, "config.json")))
args = sys.argv[1:]
with open(os.path.join(here, "calls.jsonl"), "a") as handle:
    handle.write(json.dumps(args) + "\\n")
if args[0] == config.get("fail"):
    sys.exit(1)
if args[0] == "import":
    info = os.stat(args[1])
    json.dump({"mode": stat.S_IMODE(info.st_mode), "content": list(open(args[1], "rb").read()), "env": open(os.environ["GITHUB_ENV"]).read()}, open(os.path.join(here, "import.json"), "w"))
if args[:3] == ["list-keychains", "-d", "user"] and len(args) == 3:
    sys.stdout.write(config.get("existing", ""))
if args[0] in ("list-keychains", "find-identity"):
    with open(os.path.join(here, "left.jsonl"), "a") as handle:
        handle.write(json.dumps(sorted(os.listdir(os.environ["RUNNER_TEMP"]))) + "\\n")
if args[0] == "find-identity":
    count = config.get("identities", 1)
    sys.stdout.write(''.join('  %d) 0123456789ABCDEF "${NAME}"\\n' % (i + 1) for i in range(count)) + '     %d valid identities found\\n' % count)
`;

function load({ env = {}, args = [], config = {} } = {}) {
  const root = mkdtempSync(join(tmpdir(), "signing-identity-"));
  try {
    mkdirSync(join(root, "bin"));
    mkdirSync(join(root, "temp"));
    writeFileSync(join(root, "bin/security"), FAKE);
    chmodSync(join(root, "bin/security"), 0o755);
    writeFileSync(join(root, "bin/config.json"), JSON.stringify(config));
    writeFileSync(join(root, "github-env"), "");
    const result = spawnSync("bash", [SCRIPT, ...args], {
      encoding: "utf8",
      env: {
        PATH: `${join(root, "bin")}:${process.env.PATH}`, RUNNER_TEMP: join(root, "temp"), GITHUB_ENV: join(root, "github-env"),
        APPLE_CERTIFICATE: CERTIFICATE.toString("base64"), APPLE_CERTIFICATE_PASSWORD: PASSWORD, KEYCHAIN_ENV: "PROBE_KEYCHAIN", ...env,
      },
    });
    const read = (name) => (existsSync(join(root, name)) ? readFileSync(join(root, name), "utf8") : "");
    return {
      status: result.status,
      out: result.stdout + result.stderr,
      calls: read("bin/calls.jsonl").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line)),
      imported: existsSync(join(root, "bin/import.json")) ? JSON.parse(read("bin/import.json")) : null,
      githubEnv: read("github-env"),
      leftDuring: read("bin/left.jsonl").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line)),
      left: readdirSync(join(root, "temp")),
      temp: join(root, "temp"),
    };
  } finally { rmSync(root, { recursive: true, force: true }); }
}

test("lädt die Identität in einen eigenen Schlüsselbund und nennt nur dessen Pfad", () => {
  const r = load({ config: { existing: '    "/Users/x/Library/Keychains/login.keychain-db"\n    "/Users/x/Mein Bund/zweiter.keychain-db"\n' } });
  assert.equal(r.status, 0, r.out);
  const keychain = join(r.temp, "signing-identity.keychain-db");
  assert.equal(r.githubEnv, `PROBE_KEYCHAIN=${keychain}\n`);
  assert.deepEqual(r.calls.map((call) => call[0]), ["create-keychain", "set-keychain-settings", "unlock-keychain", "import", "set-key-partition-list", "list-keychains", "list-keychains", "find-identity"]);
  const [create, settings, unlock, imported, partition, , search] = r.calls;
  assert.match(create[2], /^[0-9a-f]{48}$/);
  assert.deepEqual(create, ["create-keychain", "-p", create[2], keychain]);
  assert.deepEqual(settings, ["set-keychain-settings", "-lut", "1800", keychain]);
  assert.deepEqual(unlock, ["unlock-keychain", "-p", create[2], keychain]);
  assert.deepEqual(imported, ["import", join(r.temp, "signing-identity.p12"), "-k", keychain, "-P", PASSWORD, "-T", "/usr/bin/codesign"]);
  assert.deepEqual(partition, ["set-key-partition-list", "-S", "apple-tool:,apple:,codesign:", "-s", "-k", create[2], keychain]);
  // Vorhandene Schlüsselbunde bleiben in der Suchliste, auch mit Leerzeichen im Pfad.
  assert.deepEqual(search, ["list-keychains", "-d", "user", "-s", keychain, "/Users/x/Library/Keychains/login.keychain-db", "/Users/x/Mein Bund/zweiter.keychain-db"]);
  // Die Zertifikatsdatei: genau der Inhalt, nur für den eigenen Benutzer, danach weg.
  assert.deepEqual(r.imported.content, [...CERTIFICATE]);
  assert.equal(r.imported.mode, 0o600);
  assert.deepEqual(r.left, []);
  // Sie ist schon weg, bevor die Suchliste geändert und die Identität gezählt wird, nicht erst am Ende.
  assert.equal(r.leftDuring.length, 3);
  for (const names of r.leftDuring) assert.ok(!names.includes("signing-identity.p12"), JSON.stringify(names));
  // Der Pfad stand schon fest, bevor das Zertifikat geschrieben wurde: das Aufräumen findet den Schlüsselbund immer.
  assert.equal(r.imported.env, `PROBE_KEYCHAIN=${keychain}\n`);
  // Weder Name noch Kennwörter im Protokoll.
  assert.equal(r.out, "PASS signing-identity-loaded\n");
  for (const secret of ["Geheimer Name", PASSWORD, create[2], CERTIFICATE.toString("base64")]) assert.ok(!r.out.includes(secret));
});

test("ohne vorhandene Schlüsselbunde steht nur der neue in der Suchliste", () => {
  const r = load();
  assert.equal(r.status, 0, r.out);
  assert.deepEqual(r.calls[6], ["list-keychains", "-d", "user", "-s", join(r.temp, "signing-identity.keychain-db")]);
});

for (const step of ["create-keychain", "unlock-keychain", "import", "set-key-partition-list", "find-identity"]) {
  test(`scheitert ${step}: Abbruch, Zertifikatsdatei weg, Pfad des Schlüsselbunds bekannt`, () => {
    const r = load({ config: { fail: step } });
    assert.notEqual(r.status, 0);
    assert.doesNotMatch(r.out, /PASS/);
    assert.deepEqual(r.left, []);
    assert.equal(r.githubEnv, `PROBE_KEYCHAIN=${join(r.temp, "signing-identity.keychain-db")}\n`);
    assert.equal(r.calls.at(-1)[0], step);
    assert.ok(!r.out.includes(PASSWORD));
  });
}

test("abgewiesen, bevor etwas geschrieben wird: kein Zertifikat, kaputter Variablenname, Argumente", () => {
  const nothing = (r, status) => {
    assert.equal(r.status, status, r.out);
    assert.deepEqual(r.calls, []);
    assert.equal(r.githubEnv, "");
    assert.deepEqual(r.left, []);
  };
  nothing(load({ env: { APPLE_CERTIFICATE: "" } }), 1);
  for (const name of ["", "keychain", "probe_KEYCHAIN", "PROBE_KEYCHAIN=x", "PROBE_KEYCHAIN\nPATH=/tmp", "PATH", "A1_KEYCHAIN"]) nothing(load({ env: { KEYCHAIN_ENV: name } }), 64);
  nothing(load({ args: ["zusatz"] }), 64);
});

test("ohne gültige Identität im Schlüsselbund: Abbruch", () => {
  const none = load({ config: { identities: 0 } });
  assert.equal(none.status, 1, none.out);
  assert.match(none.out, /^::error::[^\n]+\n$/);
  assert.equal(load({ config: { identities: 2 } }).status, 0);
});
