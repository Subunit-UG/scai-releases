import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const workflow = readFileSync(join(ROOT, ".github/workflows/os-build.yml"), "utf8");
const jobsAt = workflow.indexOf("\njobs:\n");
const signAt = workflow.indexOf("\n  sign:\n");
assert.ok(jobsAt > 0 && signAt > jobsAt, "os-build.yml: Jobs build und sign erwartet");
const head = workflow.slice(0, jobsAt);
const build = workflow.slice(jobsAt, signAt);
const sign = workflow.slice(signAt);
const secrets = (text) => [...new Set([...text.matchAll(/secrets\.([A-Z0-9_]+)/g)].map((m) => m[1]))].sort();

test("os-build: genau zwei Jobs, nur manuell auslösbar, nur lesende Rechte", () => {
  assert.deepEqual([...workflow.slice(jobsAt).matchAll(/^  ([a-z_-]+):$/gm)].map((m) => m[1]), ["build", "sign"]);
  assert.match(head, /^on:\n  workflow_dispatch:\n/m);
  assert.doesNotMatch(head, /^  (push|pull_request|pull_request_target|schedule|workflow_run|workflow_call):/m);
  assert.match(head, /^permissions:\n  contents: read\n/m);
  assert.doesNotMatch(workflow.slice(jobsAt), /^\s+permissions:/m);
  assert.deepEqual(secrets(head), []);
});

test("os-build: der Bau-Job kennt nur den Lese-Schlüssel und keine Umgebung", () => {
  assert.deepEqual(secrets(build), ["OS_SOURCE_DEPLOY_KEY"]);
  assert.doesNotMatch(build, /^\s+environment:/m);
  assert.doesNotMatch(build, /codesign|notarytool|security (create|unlock|import)/);
  assert.match(build, /run-confidential\.sh" os-build \.\/betrieb\/mac\/bauen\.sh bauen\n/);
  assert.match(build, /encrypt-confidential-log\.mjs" \\\n\s+"\$plain\/unsigned\.zip" "\$out\/unsigned\.zip\.envelope\.json" "\$HANDOVER_PUBLIC_KEY_BASE64"\n/);
  // Lese-Schlüssel nur im Checkout-Schritt; danach räumt die zweite Stufe in jedem Ausgang auf.
  assert.equal(build.split("secrets.OS_SOURCE_DEPLOY_KEY").length - 1, 1);
  assert.match(build, /checkout-private-source\.sh subunit-os git@github\.com:Subunit-UG\/os-app\.git "\$SOURCE_SHA"\n\n      - name: [^\n]+\n        if: always\(\)\n        shell: bash\n        run: bash gate\/scripts\/checkout-private-source\.sh --cleanup-credentials\n/);
  // Der Bau-Job meldet den Digest des Umschlags; im Archiv stehen keine Verweise und keine Zusatzdaten.
  assert.match(build, /\n    outputs:\n      handover_sha256: \$\{\{ steps\.handover\.outputs\.sha256 \}\}\n/);
  assert.match(build, /find "\$app" -type l -print -quit\)" \] \|\| \{[^\n]+exit 1; \}\n\s+ditto -c -k --norsrc --keepParent "\$app" "\$plain\/unsigned\.zip"\n/);
  assert.match(build, /echo "sha256=\$\(shasum -a 256 "\$out\/unsigned\.zip\.envelope\.json" \| cut -d' ' -f1\)" >> "\$GITHUB_OUTPUT"\n/);
});

test("os-build: der Signier-Job öffnet nur den gemeldeten Umschlag und packt ohne Geheimnisse streng aus", () => {
  const steps = sign.split(/\n      (?:# [^\n]*\n      )?- name: /).slice(1);
  const step = (name) => { const found = steps.filter((s) => s.startsWith(`${name}\n`)); assert.equal(found.length, 1, name); return found[0]; };
  const open = step("Umschlag pruefen und oeffnen");
  assert.deepEqual(secrets(open), ["OS_HANDOVER_PRIVATE_KEY"]);
  assert.match(open, /HANDOVER_SHA256: \$\{\{ needs\.build\.outputs\.handover_sha256 \}\}\n/);
  const digestCheck = open.indexOf('[ "$(shasum -a 256 "$envelope" | cut -d\' \' -f1)" = "$HANDOVER_SHA256" ] || {');
  const formatCheck = open.indexOf("printf '%s' \"$HANDOVER_SHA256\" | grep -Eq '^[0-9a-f]{64}$' || {");
  const decrypt = open.indexOf("decrypt-confidential-envelope.mjs");
  assert.ok(formatCheck > 0 && digestCheck > formatCheck && decrypt > digestCheck, "Digest wird vor dem Entschlüsseln geprüft");
  const unpack = step("Bundle auspacken und pruefen");
  assert.deepEqual(secrets(unpack), []);
  assert.doesNotMatch(unpack, /\n        env:/);
  assert.match(unpack, /python3 -I gate\/scripts\/extract-app-bundle\.py "\$work\/unsigned\.zip" "\$work\/app" "\$APP_NAME\.app"\n/);
  assert.doesNotMatch(sign, /ditto -x|unzip|tar -x/);
  // Was aus dem Bundle gelesen wird, steht nie im Protokoll; der Name des Hauptprogramms ist ein einfacher Dateiname.
  assert.doesNotMatch(workflow, /echo "[^"\n]*\$(version|exe|main|archs|team|info)\b/);
  assert.match(unpack, /printf '%s' "\$exe" \| grep -Eq '\^\[A-Za-z0-9\]\[A-Za-z0-9\._-\]\{0,63\}\$' \|\| \{[^\n]+exit 1; \}\n\s+main="\$app\/Contents\/MacOS\/\$exe"\n/);
  // Die Zertifikatsdatei entsteht mit engen Rechten und verschwindet in jedem Ausgang des Schritts.
  const keychain = step("Signier-Identitaet in temporaeren Schluesselbund laden");
  const umask = keychain.indexOf("          umask 077\n");
  const trap = keychain.indexOf("          trap 'rm -f \"$p12\"' EXIT\n");
  const known = keychain.indexOf('          echo "OS_KEYCHAIN=$kc" >> "$GITHUB_ENV"\n');
  const write = keychain.indexOf("base64 --decode > \"$p12\"");
  assert.ok(umask > 0 && trap > umask && known > trap && write > known, "umask, trap und Vermerk des Schlüsselbunds stehen vor dem Schreiben");
  assert.ok(steps.findIndex((s) => s.startsWith("Bundle auspacken und pruefen\n")) < steps.findIndex((s) => s.startsWith("Signier-Identitaet in temporaeren Schluesselbund laden\n")));
});

test("os-build: der Signier-Job läuft nach dem Bau in der Umgebung release und führt keinen Baucode aus", () => {
  assert.match(sign, /\n    needs: build\n    environment: release\n/);
  assert.deepEqual(secrets(sign), [
    "APPLE_DEVID_CERTIFICATE", "APPLE_DEVID_CERTIFICATE_PASSWORD", "APPLE_DEVID_SIGNING_IDENTITY",
    "APPLE_NOTARY_ISSUER_ID", "APPLE_NOTARY_KEY", "APPLE_NOTARY_KEY_ID", "OS_HANDOVER_PRIVATE_KEY",
  ]);
  assert.doesNotMatch(sign, /checkout-private-source|bauen\.sh|run-confidential|npm |npx |cargo |rustup|tauri/);
  assert.doesNotMatch(sign, /private\//);
});

test("os-build: nur Umschläge und der Beleg verlassen die Runner", () => {
  const uploads = [...workflow.matchAll(/uses: actions\/upload-artifact@[0-9a-f]{40}[^\n]*\n\s+with:\n\s+name: [^\n]+\n\s+path: ([^\n]+)\n/g)].map((m) => m[1]);
  assert.deepEqual(uploads, [
    "${{ runner.temp }}/os-build-diagnostic.json",
    "${{ runner.temp }}/os-handover/",
    "${{ runner.temp }}/os-out/",
  ]);
  for (const [, action, pin] of workflow.matchAll(/uses: ([^@\s]+)@(\S+)/g)) assert.match(pin, /^[0-9a-f]{40}$/, `${action} ist nicht auf einen Commit gepinnt`);
  assert.doesNotMatch(workflow, /actions\/cache|gh release|softprops/);
});
