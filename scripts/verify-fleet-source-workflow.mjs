#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export function validateFleetSourceWorkflow(workflow, checkoutHelper) {
  const errors = [];
  const require = (condition, message) => { if (!condition) errors.push(message); };

  require(/^\s{2}workflow_dispatch:\s*$/m.test(workflow), "fleet source workflow must be manually dispatched");
  require(!/^\s{2}(pull_request|push|pull_request_target|schedule|workflow_run):/m.test(workflow), "fleet source workflow must not have an automatic or fork trigger");
  require(/^permissions:\n\s{2}contents:\s*read\s*$/m.test(workflow), "workflow permissions must be contents: read only");
  require(!/uses:\s*(?:actions\/cache|swatinem\/rust-cache)@/.test(workflow), "private Fleet outputs must never enter a public Actions cache");
  require(!/uses:\s*actions\/upload-artifact@/.test(workflow), "private Fleet jobs must not upload public artifacts");
  require(workflow.includes("image: pgvector/pgvector@sha256:"), "Atlas pgvector service image must be digest-pinned");

  for (const line of workflow.split("\n")) {
    const match = line.match(/^\s*(?:-\s*)?uses:\s*([^\s#]+)/);
    if (!match || match[1].startsWith("./")) continue;
    const ref = match[1].split("@").at(-1);
    require(/^[0-9a-f]{40}$/.test(ref ?? ""), `action reference must be immutable: ${match[1]}`);
  }

  for (const [component, input, secret, repository] of [
    ["u1-chat", "u1_chat_sha", "U1_CHAT_SOURCE_DEPLOY_KEY", "Subunit-UG/infra-u1-chat.git"],
    ["atlas", "atlas_sha", "ATLAS_SOURCE_DEPLOY_KEY", "Subunit-UG/infra-atlas.git"],
    ["subunit-auth", "auth_sha", "AUTH_SOURCE_DEPLOY_KEY", "Subunit-UG/infra-auth.git"],
    ["echo", "echo_sha", "ECHO_SOURCE_DEPLOY_KEY", "Subunit-UG/echo-server.git"],
  ]) {
    require(workflow.includes(`${input}:`), `${component}: immutable SHA input is missing`);
    require(workflow.includes(`secrets.${secret}`), `${component}: dedicated read-only deploy-key secret is missing`);
    require(workflow.includes(`checkout-private-source.sh ${component} git@github.com:${repository}`), `${component}: allowlisted exact checkout is missing`);
    require(workflow.includes(`rm -rf -- "$GITHUB_WORKSPACE/private/${component}"`), `${component}: ephemeral private checkout cleanup is missing`);
    require(checkoutHelper.includes(`${component}:git@github.com:${repository})`), `${component}: checkout helper repository allowlist is missing`);

    const checkoutNeedle = `checkout-private-source.sh ${component} git@github.com:${repository}`;
    const cleanupNeedle = `rm -rf -- "$GITHUB_WORKSPACE/private/${component}"`;
    const checkoutStart = workflow.indexOf(checkoutNeedle);
    const cleanupStart = workflow.indexOf(cleanupNeedle, checkoutStart + checkoutNeedle.length);
    if (checkoutStart >= 0 && cleanupStart >= 0) {
      const cleanupRunLineStart = workflow.lastIndexOf("\n", cleanupStart);
      const privateWindow = workflow.slice(checkoutStart + checkoutNeedle.length, cleanupRunLineStart);
      require(!/^\s*(?:-\s*)?uses:/m.test(privateWindow), `${component}: no action may run while private source is present`);
      const lines = privateWindow.split("\n");
      for (let index = 0; index < lines.length; index += 1) {
        const runMatch = lines[index].match(/^(\s*)run:\s*(.*)$/);
        if (!runMatch) continue;
        const runIndent = runMatch[1].length;
        const commands = runMatch[2] === "|" ? [] : [runMatch[2]];
        while (index + 1 < lines.length) {
          const next = lines[index + 1];
          const nextIndent = next.match(/^\s*/)?.[0].length ?? 0;
          if (next.trim() && nextIndent <= runIndent) break;
          index += 1;
          if (next.trim()) commands.push(next.trim());
        }
        for (const command of commands) {
          require(
            /^bash "\$GITHUB_WORKSPACE\/gate\/scripts\/run-confidential\.sh" [A-Za-z0-9._-]+\s/.test(command),
            `${component}: every command while private source exists must use the confidential runner`,
          );
        }
      }
    }
  }

  const secretReferences = [...workflow.matchAll(/secrets\.([A-Z0-9_]+)/g)].map((match) => match[1]);
  require(new Set(secretReferences).size === 4, "each private Fleet repository must use a distinct secret");
  require(secretReferences.length === 4, "deploy-key secrets may only be bound to their checkout steps");

  for (const label of [
    "u1-chat-tests", "u1-chat-build", "u1-anchor-tests", "atlas-web-tests",
    "atlas-web-build", "atlas-api-typecheck", "atlas-api-tests", "atlas-restore-proof",
    "atlas-trust-proof", "atlas-dirty-doc-proof", "atlas-memory-tests", "auth-tests",
    "auth-build", "echo-tests", "echo-compile",
  ]) {
    require(workflow.includes(`run-confidential.sh\" ${label}`), `${label}: private output is not confidential`);
  }

  require(checkoutHelper.includes("^[0-9a-f]{40}$"), "checkout helper must reject mutable/non-SHA refs");
  require(checkoutHelper.includes('fetch --depth 1 origin "$source_sha"'), "checkout helper must fetch the exact requested SHA");
  require(checkoutHelper.includes('checkout --detach "$source_sha"'), "checkout helper must detach at the exact requested SHA");
  require(checkoutHelper.includes('if [ "$actual_sha" != "$source_sha" ]'), "checkout helper must reject checkout drift");
  require(checkoutHelper.includes("IdentitiesOnly=yes"), "checkout helper must constrain SSH identities");
  require(checkoutHelper.includes("StrictHostKeyChecking=yes"), "checkout helper must verify the GitHub host key");
  require(checkoutHelper.includes("SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU"), "checkout helper must pin GitHub's ED25519 host fingerprint");
  require(checkoutHelper.includes('actual_fingerprint" != "$github_ed25519_fingerprint'), "checkout helper must reject an untrusted GitHub host key");
  require(checkoutHelper.includes('trap cleanup EXIT')
    && checkoutHelper.includes("trap 'exit 129' HUP")
    && checkoutHelper.includes("trap 'exit 130' INT")
    && checkoutHelper.includes("trap 'exit 143' TERM"), "checkout helper must clean credentials on every exit");
  require(checkoutHelper.includes('UserKnownHostsFile=$known_hosts')
    && checkoutHelper.includes('GlobalKnownHostsFile=/dev/null')
    && checkoutHelper.includes('-F /dev/null'), "checkout helper must isolate the host pin from standard SSH trust");
  require(checkoutHelper.includes('umask 077') && checkoutHelper.includes('mktemp -d "$credential_root/scai-checkout-credentials.XXXXXX"')
    && checkoutHelper.indexOf('trap cleanup EXIT') < checkoutHelper.indexOf('credential_dir=$(mktemp'),
    "checkout helper must allocate private credentials only after installing cleanup");
  require(checkoutHelper.includes('remote remove origin'), "checkout helper must remove the private remote after checkout");

  return errors;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const errors = validateFleetSourceWorkflow(
    readFileSync(join(ROOT, ".github/workflows/fleet-source-check.yml"), "utf8"),
    readFileSync(join(ROOT, "scripts/checkout-private-source.sh"), "utf8"),
  );
  if (errors.length) {
    for (const error of errors) console.error(`FAIL ${error}`);
    process.exit(1);
  }
  console.log("PASS public Fleet source workflow :: exact pins, dedicated keys, confidential output, no cache/artifact");
}
