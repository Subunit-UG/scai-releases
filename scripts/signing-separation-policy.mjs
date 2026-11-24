// Regeln fuer die Trennung von Bauen und Signieren in den Workflows dieses Repos.
//
// jobViolations(text): gilt fuer jeden Workflow. Ein Job, der ein Signier-Geheimnis nennt, laeuft in der Umgebung
// `release` und fasst weder privaten Quelltext noch Baucode an; ein Job mit Zugang zu privatem Quelltext laeuft
// nicht in der Umgebung `release`.
// signedBuildErrors(name, text): die genaue Form der zweistufigen Workflows (build, sign).

const SIGNING_SECRET = /secrets\.(?:APPLE_[A-Z0-9_]+|WINDOWS_CERTIFICATE[A-Z0-9_]*|AZURE_[A-Z0-9_]+|[A-Z0-9_]*SIGNING[A-Z0-9_]*|RELEASE_HANDOVER_PRIVATE_KEY)\b|secrets: *inherit|toJSON\( *secrets *\)|secrets\[/;
const PRIVATE_SOURCE = /secrets\.[A-Z0-9_]*SOURCE_DEPLOY_KEY\b|secrets\.[A-Z0-9_]*READ_APP_PRIVATE_KEY\b|checkout-private-source\.sh(?! --cleanup-credentials)|working-directory: private\/|run-confidential\.sh|\bprivate\/[a-z]/;
const RELEASE_ENVIRONMENT = /^ {4}environment: release$/m;

export function jobsOf(text) {
  const at = text.indexOf("\njobs:\n");
  if (at < 0) return {};
  const body = text.slice(at + "\njobs:\n".length);
  const heads = [...body.matchAll(/^ {2}([A-Za-z0-9_-]+):[ \t]*$/gm)];
  return Object.fromEntries(heads.map((head, index) => [head[1], body.slice(head.index, heads[index + 1]?.index ?? body.length)]));
}

export function jobViolations(text) {
  const found = [];
  for (const [job, body] of Object.entries(jobsOf(text))) {
    const signing = SIGNING_SECRET.test(body);
    const source = PRIVATE_SOURCE.test(body);
    const release = RELEASE_ENVIRONMENT.test(body);
    if (signing && !release) found.push(`${job}: signing secret outside the release environment`);
    if (signing && source) found.push(`${job}: signing secret next to private source`);
    if (source && release) found.push(`${job}: private source inside the release environment`);
  }
  return found.sort();
}

const secretsOf = (text) => [...new Set([...text.matchAll(/secrets\.([A-Z0-9_]+)/g)].map((m) => m[1]))].sort();
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

const NOTCH_WAYS = `          case "$SIGNING" in
            developer-id) set -- --expect-team 8V35FVMFT9 --timestamp secure --with zentrale ;;
            development) set -- --expect-team Y23NYAZM6M --timestamp none ;;
            *) exit 1 ;;
          esac
`;

export const SIGNED_BUILDS = {
  "notch-build.yml": {
    product: "notch",
    buildSecrets: ["NOTCH_SOURCE_DEPLOY_KEY", "ZENTRALE_SOURCE_DEPLOY_KEY"],
    unsigned: ["NOTCH_SIGN_ID=- \\\n", "ZENTRALE_SIGN_ID=- "],
    signSecrets: [
      "APPLE_CERTIFICATE", "APPLE_CERTIFICATE_PASSWORD", "APPLE_DEVID_CERTIFICATE", "APPLE_DEVID_CERTIFICATE_PASSWORD",
      "APPLE_DEVID_SIGNING_IDENTITY", "APPLE_NOTARY_ISSUER_ID", "APPLE_NOTARY_KEY", "APPLE_NOTARY_KEY_ID",
      "APPLE_SIGNING_IDENTITY", "RELEASE_HANDOVER_PRIVATE_KEY",
    ],
    bundle: "SubunitNotch.app",
    resign: `${NOTCH_WAYS}          python3 -I gate/scripts/resign-app-bundle.py "$NOTCH_APP" --manifest gate/config/signing/notch.json "$@"\n`,
    verify: `${NOTCH_WAYS}`,
    verifyCall: '          python3 -I gate/scripts/resign-app-bundle.py "$NOTCH_APP" --manifest gate/config/signing/notch.json --verify-only "$@"\n',
    uploads: ["${{ runner.temp }}/notch-handover/", "${{ runner.temp }}/notch-out/"],
  },
  "charge-build.yml": {
    product: "charge",
    buildSecrets: ["CHARGE_READ_APP_PRIVATE_KEY"],
    unsigned: ["CHARGE_SIGN_ID=- \\\n"],
    signSecrets: ["APPLE_CERTIFICATE", "APPLE_CERTIFICATE_PASSWORD", "APPLE_SIGNING_IDENTITY", "RELEASE_HANDOVER_PRIVATE_KEY"],
    bundle: '"Subunit Charge.app"',
    resign: '          python3 -I gate/scripts/resign-app-bundle.py "$CHARGE_APP" --manifest gate/config/signing/charge.json \\\n            --expect-team "$EXPECTED_TEAM" --timestamp "$timestamp"\n',
    verify: "",
    verifyCall: '          python3 -I gate/scripts/resign-app-bundle.py "$CHARGE_APP" --manifest gate/config/signing/charge.json --verify-only \\\n            --expect-team "$EXPECTED_TEAM" --timestamp "$CHARGE_TIMESTAMP"\n',
    uploads: ["${{ runner.temp }}/charge-build-diagnostic.json", "${{ runner.temp }}/charge-handover/", "${{ runner.temp }}/charge-out/"],
  },
};

export function signedBuildErrors(name, text) {
  const spec = SIGNED_BUILDS[name];
  const errors = [...jobViolations(text)];
  const need = (condition, message) => { if (!condition) errors.push(message); };
  const jobsAt = text.indexOf("\njobs:\n");
  const head = jobsAt < 0 ? text : text.slice(0, jobsAt);
  const jobs = jobsOf(text);
  const build = jobs.build ?? "";
  const sign = jobs.sign ?? "";

  need(same(Object.keys(jobs), ["build", "sign"]), "exactly the jobs build and sign");
  need(/^on:\n {2}workflow_dispatch:\n/m.test(head), "manual trigger");
  need(!/^ {2}(push|pull_request|pull_request_target|schedule|workflow_run|workflow_call|repository_dispatch):/m.test(head), "no automatic trigger");
  need(/^permissions:\n {2}contents: read\n\n/m.test(head), "read-only token");
  need(!/^\s+permissions:/m.test(text.slice(Math.max(jobsAt, 0))), "no job-level permissions");
  need(same(secretsOf(head), []), "no secret outside a job");
  for (const [, action, pin] of text.matchAll(/uses: ([^@\s]+)@(\S+)/g)) need(/^[0-9a-f]{40}$/.test(pin), `action pinned to a commit: ${action}`);
  need(!/uses: (?!actions\/(checkout|upload-artifact|download-artifact|create-github-app-token)@)/.test(text), "only the known actions");
  need(!/actions\/cache|gh release|softprops|codesign|preserve-metadata|--allow-entitlement|--codesign/.test(text), "no cache, no publication, no direct signing call");

  // Bau-Job: nur Quellzugang, keine Umgebung, keine Signier-Identitaet.
  need(same(secretsOf(build), spec.buildSecrets), "build job: only the source-access secrets");
  need(!/^\s+environment:/m.test(build), "build job: no environment");
  need(!/notarytool|security (create|unlock|import)|load-signing-identity|resign-app-bundle|open-build-handover/.test(build), "build job: no signing tool");
  for (const marker of spec.unsigned) need(build.includes(marker), "build job: builds without a signing identity");
  need(!/_SIGN_ID="?\$/.test(build), "build job: no signing identity passed to the build");
  need(build.includes(`bash gate/scripts/check-signed-build-request.sh ${spec.product}\n`), "build job: request check");
  need(/\n {4}outputs:\n {6}handover_sha256: \$\{\{ steps\.handover\.outputs\.sha256 \}\}\n/.test(build), "build job: reports the envelope digest");
  need(/\n {8}id: handover\n[\s\S]*seal-build-handover\.sh" /.test(build), "build job: seals the handover");
  need(!/ditto -c|zip /.test(build), "build job: the bundle leaves only through the handover tool");

  // Signier-Job: nach dem Bau, in der Umgebung release, ohne Quelltext und ohne Baucode.
  need(/\n {4}needs: build\n {4}environment: release\n/.test(sign), "sign job: after build, in the release environment");
  need(same(secretsOf(sign), spec.signSecrets), "sign job: exactly the expected secrets");
  need(!/checkout-private-source|run-confidential|build\.sh|private\/|create-github-app-token|swift build|npm |cargo |repository:/.test(sign), "sign job: no source and no build code");
  need(!/ditto -x|unzip|tar -x/.test(sign), "sign job: unpacks only with the extraction tool");
  const steps = sign.split(/\n {6}(?:# [^\n]*\n {6})?- name: /).slice(1);
  const step = (title) => steps.find((candidate) => candidate.startsWith(`${title}\n`)) ?? "";
  const order = ["Commit-Pin", "Umschlag des Bau-Jobs holen", "Umschlag pruefen und oeffnen", "Bundle auspacken und pruefen",
    "Signier-Identitaet in temporaeren Schluesselbund laden", "Bundle neu signieren", "Signatur pruefen"].map((title) => steps.findIndex((s) => s.startsWith(title)));
  need(order.every((at, i) => at >= 0 && (i === 0 || at > order[i - 1])), "sign job: check, fetch, open, unpack, identity, sign, verify in this order");
  need(sign.includes(`bash gate/scripts/check-signed-build-request.sh ${spec.product}\n`), "sign job: request check");
  const open = step("Umschlag pruefen und oeffnen");
  need(same(secretsOf(open), ["RELEASE_HANDOVER_PRIVATE_KEY"]), "open step: only the handover key");
  need(open.includes("HANDOVER_SHA256: ${{ needs.build.outputs.handover_sha256 }}\n"), "open step: digest from the build job");
  need(/bash gate\/scripts\/open-build-handover\.sh "\$RUNNER_TEMP\/handover" "\$RUNNER_TEMP\/[a-z]+-work"\n/.test(open), "open step: handover tool");
  const unpack = step("Bundle auspacken und pruefen");
  need(same(secretsOf(unpack), []) && !/\n {8}env:/.test(unpack), "unpack step: no secret and no extra environment");
  need(unpack.includes(`python3 -I gate/scripts/extract-app-bundle.py "$work/unsigned.zip" "$work/app" ${spec.bundle}\n`), "unpack step: extraction tool");
  const resign = step("Bundle neu signieren");
  need(resign.includes(spec.resign), "sign step: re-signing tool with the list of this repository");
  need((resign.match(/resign-app-bundle\.py/g) ?? []).length === 1, "sign step: one call of the re-signing tool");
  need(/security delete-keychain "\$[A-Z]+_KEYCHAIN"\n/.test(resign), "sign step: keychain removed after signing");
  const verify = step("Signatur pruefen");
  need(same(secretsOf(verify), []) && !/\n {8}env:/.test(verify), "verify step: no secret and no extra environment");
  need(verify.includes(spec.verify) && verify.includes(spec.verifyCall), "verify step: every part checked against the list");
  need((sign.match(/resign-app-bundle\.py/g) ?? []).length === 2, "sign job: the re-signing tool is called to sign and to verify");
  // Was aus dem Bundle gelesen wird, steht nie im Protokoll.
  need(!/echo "[^"\n]*\$\{?(version|ztv)\b/.test(text), "nothing read from the bundle is printed");

  const uploads = [...text.matchAll(/uses: actions\/upload-artifact@[0-9a-f]{40}[^\n]*\n\s+with:\n\s+name: [^\n]+\n\s+path: ([^\n]+)\n/g)].map((m) => m[1]);
  need(same(uploads, spec.uploads), "only the envelopes and the receipt leave the runners");
  need((text.match(/actions\/upload-artifact@/g) ?? []).length === spec.uploads.length, "every upload is one of the expected");
  return errors;
}
