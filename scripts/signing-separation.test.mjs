import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { jobViolations, jobsOf, signedBuildErrors, SIGNED_BUILDS } from "./signing-separation-policy.mjs";

const WORKFLOWS = join(dirname(fileURLToPath(import.meta.url)), "..", ".github", "workflows");
const read = (name) => readFileSync(join(WORKFLOWS, name), "utf8");

// Workflows in der frueheren einstufigen Form, mit genau diesen Stellen. Die Liste waechst nicht:
// Ein neuer Workflow oder Job besteht die Regeln, und wer einen dieser Workflows umbaut, streicht ihn hier.
const SINGLE_STAGE = {
  "build-all.yml": [
    "build: private source inside the release environment",
    "build: signing secret next to private source",
    "manifest: private source inside the release environment",
    "release: private source inside the release environment",
    "release: signing secret next to private source",
  ],
  "pr-check.yml": [
    "trace-standalone: private source inside the release environment",
    "trace-standalone: signing secret next to private source",
  ],
  "publish-approved.yml": ["publish: private source inside the release environment"],
  "sonar-build.yml": [
    "build: private source inside the release environment",
    "build: signing secret next to private source",
    "preflight: private source inside the release environment",
    "publish: private source inside the release environment",
  ],
  "windows-arm-smoke.yml": [
    "smoke: private source inside the release environment",
    "smoke: signing secret next to private source",
  ],
};

test("jeder Workflow: Signier-Geheimnisse nur in der Umgebung release und nie neben privatem Quelltext", () => {
  const files = readdirSync(WORKFLOWS).filter((name) => /\.ya?ml$/.test(name)).sort();
  assert.ok(files.length >= 20, "die Workflows werden gefunden");
  for (const name of files) assert.deepEqual(jobViolations(read(name)), SINGLE_STAGE[name] ?? [], name);
  for (const name of Object.keys(SINGLE_STAGE)) assert.ok(files.includes(name), `${name} gibt es noch`);
  for (const name of Object.keys(SIGNED_BUILDS)) assert.ok(!(name in SINGLE_STAGE), `${name} ist zweistufig`);
});

test("die Regeln greifen an einem Job mit Geheimnissen, nicht am Namen", () => {
  const workflow = (jobs) => `name: x\non:\n  workflow_dispatch:\n\njobs:\n${jobs}`;
  const job = (name, lines) => `  ${name}:\n    runs-on: macos-latest\n${lines.map((line) => `    ${line}\n`).join("")}`;
  const cert = "steps: [{ env: { C: '${{ secrets.APPLE_CERTIFICATE }}' } }]";
  const source = "steps: [{ env: { K: '${{ secrets.NOTCH_SOURCE_DEPLOY_KEY }}' } }]";
  assert.deepEqual(jobViolations(workflow(job("a", ["environment: release", cert]) + job("b", [source]))), []);
  assert.deepEqual(jobViolations(workflow(job("a", [cert]))), ["a: signing secret outside the release environment"]);
  assert.deepEqual(jobViolations(workflow(job("a", ["environment: staging", cert]))), ["a: signing secret outside the release environment"]);
  assert.deepEqual(jobViolations(workflow(job("a", ["environment: release", source]))), ["a: private source inside the release environment"]);
  assert.deepEqual(jobViolations(workflow(job("a", ["environment: release", cert, source]))), [
    "a: private source inside the release environment", "a: signing secret next to private source",
  ]);
  // Ein sauberer Job daneben entlastet den anderen nicht.
  assert.deepEqual(jobViolations(workflow(job("gut", ["environment: release", cert]) + job("schlecht", [cert, source]))), [
    "schlecht: signing secret next to private source", "schlecht: signing secret outside the release environment",
  ]);
  for (const secret of ["APPLE_DEVID_CERTIFICATE", "APPLE_NOTARY_KEY", "APPLE_API_PRIVATE_KEY", "APPLE_PASSWORD", "WINDOWS_CERTIFICATE", "AZURE_CLIENT_ID",
    "TAURI_SIGNING_PRIVATE_KEY", "SONAR_TAURI_SIGNING_PRIVATE_KEY_PASSWORD", "RELEASE_HANDOVER_PRIVATE_KEY"]) {
    assert.equal(jobViolations(workflow(job("a", [`steps: [{ env: { S: '\${{ secrets.${secret} }}' } }]`]))).length, 1, secret);
  }
  for (const all of ["secrets: inherit", "steps: [{ env: { S: '${{ toJSON(secrets) }}' } }]", "steps: [{ env: { S: \"${{ secrets['APPLE_CERTIFICATE'] }}\" } }]"]) {
    assert.equal(jobViolations(workflow(job("a", [all]))).length, 1, all);
  }
  for (const access of ["steps: [{ run: bash gate/scripts/checkout-private-source.sh x y z }]", "steps: [{ run: bash gate/scripts/run-confidential.sh x ./build.sh }]",
    "steps: [{ working-directory: private/x, run: make }]", "steps: [{ env: { K: '${{ secrets.CHARGE_READ_APP_PRIVATE_KEY }}' } }]"]) {
    assert.deepEqual(jobViolations(workflow(job("a", ["environment: release", access]))), ["a: private source inside the release environment"], access);
  }
  // Das Aufräumen der Checkout-Zugänge ist kein Quellzugang.
  assert.deepEqual(jobViolations(workflow(job("a", ["environment: release", "steps: [{ run: bash gate/scripts/checkout-private-source.sh --cleanup-credentials }]"]))), []);
  assert.deepEqual(Object.keys(jobsOf(workflow(job("eins", []) + job("zwei", [])))), ["eins", "zwei"]);
});

for (const name of Object.keys(SIGNED_BUILDS)) {
  test(`${name}: Bauen und Signieren in zwei Jobs, genau in der erwarteten Form`, () => {
    assert.deepEqual(signedBuildErrors(name, read(name)), []);
  });
}

// Gegenproben: Jede dieser Änderungen muss auffallen. `swap` bricht ab, wenn die Stelle fehlt.
function swap(text, from, to) {
  assert.ok(typeof from === "string" ? text.includes(from) : from.test(text), `Stelle fehlt: ${from}`);
  return text.replace(from, to);
}
const intoSign = (text, addition) => swap(text, /(\n {2}sign:\n[\s\S]*?\n {4}steps:\n)/, `$1${addition}`);
const intoBuild = (text, addition) => swap(text, /(\n {2}build:\n[\s\S]*?\n {4}steps:\n)/, `$1${addition}`);
const stepOf = (title) => new RegExp(`( {6}(?:# [^\\n]*\\n {6})?- name: ${title}[^\\n]*\\n(?:(?! {6}- name: | {6}# )[^\\n]*\\n)*)`);
const MUTATIONS = {
  "Bau-Job in der Umgebung release": (t) => swap(t, /(\n {2}build:\n {4}name: [^\n]+\n)/, "$1    environment: release\n"),
  "Signier-Geheimnis im Bau-Job": (t) => intoBuild(t, "      - name: Zusatz\n        env:\n          X: ${{ secrets.APPLE_CERTIFICATE }}\n        run: true\n"),
  "Übergabe-Schlüssel im Bau-Job": (t) => intoBuild(t, "      - name: Zusatz\n        env:\n          X: ${{ secrets.RELEASE_HANDOVER_PRIVATE_KEY }}\n        run: true\n"),
  "Bau bekommt eine Signier-Identität": (t) => swap(t, /([A-Z]+_SIGN_ID)=- /, '$1="$APPLE_SIGNING_IDENTITY" '),
  "Bau-Job meldet keinen Digest": (t) => swap(t, "      handover_sha256: ${{ steps.handover.outputs.sha256 }}\n", "      other: x\n"),
  "Bau-Job packt selbst": (t) => swap(t, /bash "\$GITHUB_WORKSPACE\/gate\/scripts\/seal-build-handover\.sh" "\$app" "\$RUNNER_TEMP\/([a-z]+)-handover"/, 'mkdir -p "$RUNNER_TEMP/$1-handover"; ditto -c -k --keepParent "$app" "$RUNNER_TEMP/$1-handover/unsigned.zip"'),
  "Bau-Job ohne Eingabeprüfung": (t) => swap(t, /bash gate\/scripts\/check-signed-build-request\.sh [a-z]+\n/, "true\n"),
  "Signier-Job wartet nicht auf den Bau": (t) => swap(t, "    needs: build\n", ""),
  "Signier-Job ohne Umgebung": (t) => swap(t, "    needs: build\n    environment: release\n", "    needs: build\n"),
  "Signier-Job checkt privaten Quelltext aus": (t) => intoSign(t, "      - name: Zusatz\n        run: bash gate/scripts/checkout-private-source.sh x git@github.com:o/r.git \"$SOURCE_SHA\"\n"),
  "Signier-Job checkt ein anderes Repo aus": (t) => intoSign(t, "      - name: Zusatz\n        uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n        with:\n          repository: o/r\n"),
  "Signier-Job führt Baucode aus": (t) => intoSign(t, "      - name: Zusatz\n        run: bash gate/scripts/run-confidential.sh x ./build.sh release\n"),
  "Signier-Job bekommt ein weiteres Geheimnis": (t) => intoSign(t, "      - name: Zusatz\n        env:\n          X: ${{ secrets.TAURI_SIGNING_PRIVATE_KEY }}\n        run: true\n"),
  "Signier-Job bekommt einen Quellzugang": (t) => intoSign(t, "      - name: Zusatz\n        env:\n          X: ${{ secrets.NOTCH_SOURCE_DEPLOY_KEY }}\n        run: true\n"),
  "Digest kommt nicht vom Bau-Job": (t) => swap(t, "HANDOVER_SHA256: ${{ needs.build.outputs.handover_sha256 }}", "HANDOVER_SHA256: ${{ inputs.source_sha }}"),
  "Umschlag wird ohne das Werkzeug geöffnet": (t) => swap(t, /bash gate\/scripts\/open-build-handover\.sh "\$RUNNER_TEMP\/handover" /, "node gate/scripts/decrypt-confidential-envelope.mjs "),
  "Auspacken mit unzip": (t) => swap(t, /python3 -I gate\/scripts\/extract-app-bundle\.py "\$work\/unsigned\.zip" "\$work\/app" [^\n]+\n/, 'unzip -q "$work/unsigned.zip" -d "$work/app"\n'),
  "Auspacken mit Geheimnis in der Umgebung": (t) => swap(t, "      - name: Bundle auspacken und pruefen\n", "      - name: Bundle auspacken und pruefen\n        env:\n          X: ${{ secrets.APPLE_SIGNING_IDENTITY }}\n"),
  "Identität wird vor dem Auspacken geladen": (t) => {
    const unpack = t.match(stepOf("Bundle auspacken und pruefen"));
    const identity = t.match(stepOf("Signier-Identitaet in temporaeren Schluesselbund laden"));
    assert.ok(unpack && identity);
    return t.replace(identity[1], "").replace(unpack[1], identity[1] + unpack[1]);
  },
  "andere Liste beim Signieren": (t) => swap(t, /(resign-app-bundle\.py "\$[A-Z]+_APP" --manifest )gate\/config\/signing\/[a-z]+\.json/, "$1other.json"),
  "Signieren mit eigenem codesign": (t) => swap(t, /(resign-app-bundle\.py "\$[A-Z]+_APP" --manifest gate\/config\/signing\/[a-z]+\.json)/, "$1 --codesign ./cs"),
  "Schlüsselbund bleibt nach dem Signieren": (t) => swap(t, /          security delete-keychain "\$[A-Z]+_KEYCHAIN"\n/, ""),
  "Prüfung nach dem Signieren fehlt": (t) => swap(t, /          python3 -I gate\/scripts\/resign-app-bundle\.py "\$[A-Z]+_APP" --manifest gate\/config\/signing\/[a-z]+\.json --verify-only[^\n]*\n(?: {12}[^\n]*\n)?/, "          true\n"),
  "Prüfung erwartet ein anderes Team": (t) => swap(t, /(--verify-only[\s\S]*?)"\$(@|EXPECTED_TEAM)"/, '$1"ABCDE12345"'),
  "direkter Aufruf von codesign": (t) => intoSign(t, "      - name: Zusatz\n        run: codesign --force --sign - x\n"),
  "Action nur auf ein Tag gepinnt": (t) => swap(t, /actions\/download-artifact@[0-9a-f]{40}/, "actions/download-artifact@v4"),
  "fremde Action": (t) => intoSign(t, "      - name: Zusatz\n        uses: someone/action@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n"),
  "automatischer Auslöser": (t) => swap(t, "on:\n  workflow_dispatch:\n", "on:\n  pull_request:\n  workflow_dispatch:\n"),
  "Token mit Schreibrecht": (t) => swap(t, "permissions:\n  contents: read\n", "permissions:\n  contents: write\n"),
  "zusätzliches Recht für das Token": (t) => swap(t, "permissions:\n  contents: read\n", "permissions:\n  contents: read\n  id-token: write\n"),
  "Rechte an einem Job": (t) => swap(t, "    needs: build\n", "    needs: build\n    permissions:\n      contents: write\n"),
  "dritter Job": (t) => `${t}\n  extra:\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n`,
  "dritter Job mit Signier-Geheimnis und Quelltext": (t) => `${t}\n  extra:\n    runs-on: macos-latest\n    environment: release\n    steps:\n      - env:\n          X: \${{ secrets.APPLE_CERTIFICATE }}\n        run: bash gate/scripts/run-confidential.sh x ./build.sh\n`,
  "Arbeitsordner wird hochgeladen": (t) => intoSign(t, "      - name: Zusatz\n        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02\n        with:\n          name: x\n          path: ${{ runner.temp }}/handover\n"),
  "Version aus dem Bundle im Protokoll": (t) => intoSign(t, "      - name: Zusatz\n        run: echo \"gelesen: $version\"\n"),
  "Suche mit grep -q hinter einer Leitung": (t) => intoSign(t, "      - name: Zusatz\n        run: spctl --assess -vv \"$app\" 2>&1 | grep -q accepted\n"),
  "Geheimnis auf Workflow-Ebene": (t) => swap(t, "\nenv:\n", "\nenv:\n  X: ${{ secrets.APPLE_CERTIFICATE }}\n"),
};
for (const name of Object.keys(SIGNED_BUILDS)) {
  for (const [title, mutate] of Object.entries(MUTATIONS)) {
    if (name === "charge-build.yml" && title === "Signier-Job bekommt einen Quellzugang") continue; // dort: CHARGE_READ, siehe nächste Zeile
    test(`${name} Gegenprobe: ${title}`, () => {
      const errors = signedBuildErrors(name, mutate(read(name)));
      assert.notDeepEqual(errors, [], "die Änderung muss auffallen");
    });
  }
}
test("charge-build.yml Gegenprobe: Signier-Job holt sich das Lesetoken", () => {
  const mutated = intoSign(read("charge-build.yml"), "      - name: Zusatz\n        uses: actions/create-github-app-token@fee1f7d63c2ff003460e3d139729b119787bc349\n        with:\n          private-key: ${{ secrets.CHARGE_READ_APP_PRIVATE_KEY }}\n");
  assert.notDeepEqual(signedBuildErrors("charge-build.yml", mutated), []);
});
test("notch-build.yml Gegenprobe: Store-Weg ohne die eingebettete App, anderes Team", () => {
  const text = read("notch-build.yml");
  assert.notDeepEqual(signedBuildErrors("notch-build.yml", text.replace("--timestamp secure --with zentrale ;;", "--timestamp secure ;;")), []);
  assert.notDeepEqual(signedBuildErrors("notch-build.yml", text.replaceAll("--expect-team 8V35FVMFT9", "--expect-team ABCDE12345")), []);
  assert.notDeepEqual(signedBuildErrors("notch-build.yml", text.replaceAll("development) set -- --expect-team Y23NYAZM6M --timestamp none ;;", "development) set -- --expect-team Y23NYAZM6M --timestamp none --with zentrale ;;")), []);
  assert.notDeepEqual(signedBuildErrors("notch-build.yml", text.replace("--timestamp secure --with zentrale ;;", "--timestamp none --with zentrale ;;")), []);
});
