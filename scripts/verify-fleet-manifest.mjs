#!/usr/bin/env node
import { readFileSync, readdirSync } from "node:fs";
import { resolve, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { isApprovedOwner, validateReleaseAuthorization } from "./release-authorization.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const EXPECTED_PINS = [
  "atlas",
  "echo",
  "scai_release_contract",
  "scai_source",
  "subunit_auth",
  "u1_chat",
];
const EXPECTED_GATES = ["A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8"];
const EXPECTED_MARKET_GATES = ["R0", "R1", "R2", "R3"];
const EXPECTED_PLATFORMS = [
  "linux_x64",
  "macos_arm64",
  "macos_x64",
  "windows_arm64",
  "windows_x64",
];
const ROOT_FIELDS = ["$schema", "schema_version", "release_id", "status", "created_at", "pins", "gates", "market_gates", "market_evidence", "source_ci", "artifacts", "governance", "operations", "approvals", "blockers"];
const PIN_FIELDS = ["repository", "sha", "branch", "pr_url", "merge_status"];
const GATE_FIELDS = ["title", "release_pin", "status", "owner", "judge", "evidence", "acceptance"];
const MARKET_GATE_FIELDS = ["title", "status", "owner", "evidence", "acceptance"];
const MARKET_EVIDENCE_FIELDS = ["status", "release_pin", "source_sha", "report_schema_version", "report_url", "report_sha256", "validator_name", "validator_role", "validated_at", "attestation_url", "attestation_sha256", "repeatable_paying_customers"];
const SOURCE_CI_FIELDS = ["status", "sha", "run_url", "checks"];
const ARTIFACT_FIELDS = [
  "status",
  "artifact_url",
  "sha256",
  "updater_signature_url",
  "updater_signature_verified",
  "code_signature_status",
  "code_signer",
  "code_signature_evidence_url",
  "sbom_url",
  "sbom_sha256",
  "provenance_url",
  "provenance_verified",
];
const GOVERNANCE_FIELDS = ["status", "release_pin", "legal_owner", "dpo_owner", "independent_judge", "decision", "evidence_url", "evidence_sha256"];
const OPERATIONS_FIELDS = ["status", "release_pin", "environment", "operator", "independent_judge", "started_at", "completed_at", "deployed", "health_verified", "recovery_verified", "rollback_verified", "evidence_url", "evidence_sha256"];
const APPROVAL_FIELDS = ["name", "evidence_url", "evidence_sha256"];
const BLOCKER_FIELDS = ["id", "owner", "resolution", "evidence_required"];
const SUPERSESSION_FIELDS = ["superseded_at", "superseded_by_source_sha", "reason"];
const FULL_SHA = /^[0-9a-f]{40}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const RELEASE_ID = /^scai-candidate-[0-9]{4}-[0-9]{2}-[0-9]{2}\.[0-9]+$/;
const HTTPS = /^https:\/\//;
// Org-Umzug (TJ 2026-10-30): Pins dürfen auf subunit-ai/<repo> (historisch, weitergeleitet)
// oder Subunit-UG/<repo> zeigen; der Owner kommt nur aus der gemeinsamen Allowlist.
const GITHUB_REPOSITORY_URL = /^https:\/\/github\.com\/([A-Za-z0-9-]+)\/[A-Za-z0-9._-]+$/;
const isApprovedRepositoryUrl = (value) => {
  const match = typeof value === "string" ? GITHUB_REPOSITORY_URL.exec(value) : null;
  return Boolean(match && isApprovedOwner(match[1]));
};

function exactKeys(value, expected) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function nonEmpty(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function evidenceIsHttps(values) {
  return Array.isArray(values) && values.length > 0 && values.every((value) => HTTPS.test(value));
}

export function validateManifest(manifest, filename = "<memory>") {
  const errors = [];
  const require = (condition, message) => {
    if (!condition) errors.push(`${filename}: ${message}`);
  };

  require(manifest && typeof manifest === "object" && !Array.isArray(manifest), "root must be an object");
  if (!manifest || typeof manifest !== "object") return errors;

  const expectedRootFields = manifest.status === "superseded"
    ? [...ROOT_FIELDS, "supersession"]
    : [...ROOT_FIELDS];
  // Historical non-PASS manifests stay readable. Publication requires the
  // independently hashed authorization, not hashes supplied by the draft itself.
  if (Object.hasOwn(manifest, "authorized_release")) {
    expectedRootFields.push("authorized_release");
    for (const error of validateReleaseAuthorization(manifest.authorized_release)) require(false, error);
  }
  require(exactKeys(manifest, expectedRootFields), "root fields must match schema exactly");
  require(manifest.$schema === "../manifest.schema.json", "$schema must pin the repository schema");
  require(manifest.schema_version === "1.2", "schema_version must equal 1.2");
  require(RELEASE_ID.test(manifest.release_id ?? ""), "release_id has an invalid format");
  require(["candidate", "pass", "rejected", "superseded"].includes(manifest.status), "status must be candidate, pass, rejected or superseded");
  require(Number.isFinite(Date.parse(manifest.created_at ?? "")), "created_at must be an ISO date-time");
  if (manifest.status === "superseded") {
    const supersession = manifest.supersession ?? {};
    require(exactKeys(supersession, SUPERSESSION_FIELDS), "supersession fields must match schema exactly");
    require(Number.isFinite(Date.parse(supersession.superseded_at ?? "")), "supersession.superseded_at must be an ISO date-time");
    require(FULL_SHA.test(supersession.superseded_by_source_sha ?? ""), "supersession.superseded_by_source_sha must be a full 40-character Git SHA");
    require(nonEmpty(supersession.reason), "supersession.reason is required");
    require(supersession.superseded_by_source_sha !== manifest.pins?.scai_source?.sha, "supersession must point to a different SCAI source SHA");
  }

  require(exactKeys(manifest.pins, EXPECTED_PINS), `pins must be exactly ${EXPECTED_PINS.join(", ")}`);
  for (const name of EXPECTED_PINS) {
    const pin = manifest.pins?.[name] ?? {};
    require(exactKeys(pin, PIN_FIELDS), `${name} fields must match schema exactly`);
    require(isApprovedRepositoryUrl(pin.repository), `${name}.repository must be an approved GitHub repository`);
    require(FULL_SHA.test(pin.sha ?? ""), `${name}.sha must be a full 40-character Git SHA`);
    require(nonEmpty(pin.branch), `${name}.branch is required`);
    require(pin.pr_url === "" || HTTPS.test(pin.pr_url ?? ""), `${name}.pr_url must be empty or HTTPS`);
    require(["open", "merged", "rejected"].includes(pin.merge_status), `${name}.merge_status is invalid`);
  }

  require(exactKeys(manifest.gates, EXPECTED_GATES), `gates must be exactly ${EXPECTED_GATES.join(", ")}`);
  for (const id of EXPECTED_GATES) {
    const gate = manifest.gates?.[id] ?? {};
    require(exactKeys(gate, GATE_FIELDS), `${id} fields must match schema exactly`);
    require(nonEmpty(gate.title), `${id}.title is required`);
    require(gate.release_pin === manifest.release_id, `${id}.release_pin must equal release_id`);
    require(["open", "candidate", "pass", "failed"].includes(gate.status), `${id}.status is invalid`);
    require(Array.isArray(gate.evidence), `${id}.evidence must be an array`);
    require(nonEmpty(gate.acceptance), `${id}.acceptance is required`);
    if (gate.status === "pass") {
      require(nonEmpty(gate.owner), `${id} PASS requires a named owner`);
      require(nonEmpty(gate.judge), `${id} PASS requires a named independent judge`);
      require(evidenceIsHttps(gate.evidence), `${id} PASS requires immutable HTTPS evidence`);
    }
  }

  require(exactKeys(manifest.market_gates, EXPECTED_MARKET_GATES), `market_gates must be exactly ${EXPECTED_MARKET_GATES.join(", ")}`);
  for (const id of EXPECTED_MARKET_GATES) {
    const gate = manifest.market_gates?.[id] ?? {};
    require(exactKeys(gate, MARKET_GATE_FIELDS), `${id} fields must match schema exactly`);
    require(nonEmpty(gate.title), `${id}.title is required`);
    require(["open", "pass", "failed"].includes(gate.status), `${id}.status is invalid`);
    require(Array.isArray(gate.evidence), `${id}.evidence must be an array`);
    require(nonEmpty(gate.acceptance), `${id}.acceptance is required`);
    if (gate.status === "pass") {
      require(nonEmpty(gate.owner), `${id} PASS requires a named owner`);
      require(evidenceIsHttps(gate.evidence), `${id} PASS requires immutable HTTPS customer evidence`);
      const requiredEvidence = id === "R3" ? 3 : 1;
      require(new Set(gate.evidence).size >= requiredEvidence, `${id} PASS requires at least ${requiredEvidence} distinct primary evidence URL${requiredEvidence === 1 ? "" : "s"}`);
    }
  }

  const marketEvidence = manifest.market_evidence ?? {};
  require(exactKeys(marketEvidence, MARKET_EVIDENCE_FIELDS), "market_evidence fields must match schema exactly");
  require(["open", "pass", "failed"].includes(marketEvidence.status), "market_evidence.status is invalid");
  require(marketEvidence.release_pin === manifest.release_id, "market_evidence.release_pin must equal release_id");
  require(FULL_SHA.test(marketEvidence.source_sha ?? ""), "market_evidence.source_sha must be a full Git SHA");
  require(marketEvidence.source_sha === manifest.pins?.scai_source?.sha, "market_evidence.source_sha must equal pins.scai_source.sha");
  require(marketEvidence.report_schema_version === "1.0", "market_evidence.report_schema_version must equal 1.0");
  for (const key of ["report_url", "attestation_url"]) {
    require(marketEvidence[key] === "" || HTTPS.test(marketEvidence[key] ?? ""), `market_evidence.${key} must be empty or HTTPS`);
  }
  for (const key of ["report_sha256", "attestation_sha256"]) {
    require(marketEvidence[key] === "" || SHA256.test(marketEvidence[key] ?? ""), `market_evidence.${key} must be empty or a full SHA-256`);
  }
  require(typeof marketEvidence.validator_name === "string", "market_evidence.validator_name must be a string");
  require(typeof marketEvidence.validator_role === "string", "market_evidence.validator_role must be a string");
  require(typeof marketEvidence.validated_at === "string", "market_evidence.validated_at must be a string");
  require(Number.isInteger(marketEvidence.repeatable_paying_customers) && marketEvidence.repeatable_paying_customers >= 0, "market_evidence.repeatable_paying_customers must be a non-negative integer");
  if (marketEvidence.status === "pass") {
    require(EXPECTED_MARKET_GATES.every((id) => manifest.market_gates?.[id]?.status === "pass"), "market_evidence PASS requires R0-R3 PASS");
    require(HTTPS.test(marketEvidence.report_url ?? ""), "market_evidence PASS requires report_url");
    require(SHA256.test(marketEvidence.report_sha256 ?? ""), "market_evidence PASS requires report_sha256");
    require(nonEmpty(marketEvidence.validator_name), "market_evidence PASS requires a named validator");
    require(nonEmpty(marketEvidence.validator_role), "market_evidence PASS requires the validator role");
    require(!new Set(Object.values(manifest.market_gates ?? {}).map((gate) => gate.owner).filter(nonEmpty)).has(marketEvidence.validator_name), "market_evidence validator must be independent of the market gate owners");
    require(Number.isFinite(Date.parse(marketEvidence.validated_at ?? "")), "market_evidence PASS requires validated_at");
    require(HTTPS.test(marketEvidence.attestation_url ?? ""), "market_evidence PASS requires attestation_url");
    require(SHA256.test(marketEvidence.attestation_sha256 ?? ""), "market_evidence PASS requires attestation_sha256");
    require(marketEvidence.attestation_url !== marketEvidence.report_url, "market evidence report and independent attestation must be distinct");
    require(marketEvidence.repeatable_paying_customers >= 3, "market_evidence PASS requires at least three repeatable paying customers");
  }

  const sourceCi = manifest.source_ci ?? {};
  require(exactKeys(sourceCi, SOURCE_CI_FIELDS), "source_ci fields must match schema exactly");
  require(["open", "local-pass", "pass", "failed"].includes(sourceCi.status), "source_ci.status is invalid");
  require(FULL_SHA.test(sourceCi.sha ?? ""), "source_ci.sha must be a full Git SHA");
  require(sourceCi.sha === manifest.pins?.scai_source?.sha, "source_ci.sha must equal pins.scai_source.sha");
  require(sourceCi.run_url === "" || HTTPS.test(sourceCi.run_url ?? ""), "source_ci.run_url must be empty or HTTPS");
  require(Array.isArray(sourceCi.checks) && sourceCi.checks.every(nonEmpty), "source_ci.checks must contain only non-empty strings");

  const artifacts = manifest.artifacts ?? {};
  require(exactKeys(artifacts, ["status", "platforms"]), "artifacts fields must match schema exactly");
  require(["open", "pass", "failed"].includes(artifacts.status), "artifacts.status is invalid");
  require(exactKeys(artifacts.platforms, EXPECTED_PLATFORMS), `artifact platforms must be exactly ${EXPECTED_PLATFORMS.join(", ")}`);
  for (const platform of EXPECTED_PLATFORMS) {
    const artifact = artifacts.platforms?.[platform] ?? {};
    require(exactKeys(artifact, ARTIFACT_FIELDS), `${platform} fields must match schema exactly`);
    require(["open", "pass", "failed"].includes(artifact.status), `${platform}.status is invalid`);
    for (const key of ["artifact_url", "updater_signature_url", "code_signature_evidence_url", "sbom_url", "provenance_url"]) {
      require(artifact[key] === "" || HTTPS.test(artifact[key] ?? ""), `${platform}.${key} must be empty or HTTPS`);
    }
    require(artifact.sha256 === "" || SHA256.test(artifact.sha256 ?? ""), `${platform}.sha256 must be empty or a full SHA-256`);
    require(artifact.sbom_sha256 === "" || SHA256.test(artifact.sbom_sha256 ?? ""), `${platform}.sbom_sha256 must be empty or a full SHA-256`);
    require(typeof artifact.updater_signature_verified === "boolean", `${platform}.updater_signature_verified must be boolean`);
    require(typeof artifact.provenance_verified === "boolean", `${platform}.provenance_verified must be boolean`);
    require(["open", "pass", "failed", "not_applicable"].includes(artifact.code_signature_status), `${platform}.code_signature_status is invalid`);
    require(typeof artifact.code_signer === "string", `${platform}.code_signer must be a string`);
    if (artifact.status === "pass") {
      require(HTTPS.test(artifact.artifact_url ?? ""), `${platform} PASS requires artifact_url`);
      require(SHA256.test(artifact.sha256 ?? ""), `${platform} PASS requires sha256`);
      require(HTTPS.test(artifact.updater_signature_url ?? ""), `${platform} PASS requires updater_signature_url`);
      require(artifact.updater_signature_verified === true, `${platform} PASS requires a verified updater signature`);
      require(HTTPS.test(artifact.sbom_url ?? ""), `${platform} PASS requires sbom_url`);
      require(SHA256.test(artifact.sbom_sha256 ?? ""), `${platform} PASS requires sbom_sha256`);
      require(HTTPS.test(artifact.provenance_url ?? ""), `${platform} PASS requires provenance_url`);
      require(artifact.provenance_verified === true, `${platform} PASS requires verified provenance`);
      if (platform === "linux_x64") {
        require(artifact.code_signature_status === "not_applicable", "linux_x64 PASS must mark native code signing not_applicable");
        require(artifact.code_signer === "", "linux_x64 PASS must not claim a native code signer");
      } else {
        require(artifact.code_signature_status === "pass", `${platform} PASS requires native code-signature PASS`);
        require(nonEmpty(artifact.code_signer), `${platform} PASS requires a named code signer`);
        require(HTTPS.test(artifact.code_signature_evidence_url ?? ""), `${platform} PASS requires code-signature evidence`);
      }
    }
  }
  if (artifacts.status === "pass") {
    require(EXPECTED_PLATFORMS.every((platform) => artifacts.platforms?.[platform]?.status === "pass"), "artifacts PASS requires every platform to PASS");
  }

  const governance = manifest.governance ?? {};
  require(exactKeys(governance, GOVERNANCE_FIELDS), "governance fields must match schema exactly");
  require(["open", "pass", "failed"].includes(governance.status), "governance.status is invalid");
  require(governance.release_pin === manifest.release_id, "governance.release_pin must equal release_id");
  require(["open", "approved", "rejected"].includes(governance.decision), "governance.decision is invalid");
  require(governance.evidence_url === "" || HTTPS.test(governance.evidence_url ?? ""), "governance.evidence_url must be empty or HTTPS");
  require(governance.evidence_sha256 === "" || SHA256.test(governance.evidence_sha256 ?? ""), "governance.evidence_sha256 must be empty or a full SHA-256");
  if (governance.status === "pass") {
    require(nonEmpty(governance.legal_owner), "governance PASS requires legal_owner");
    require(nonEmpty(governance.dpo_owner), "governance PASS requires dpo_owner");
    require(nonEmpty(governance.independent_judge), "governance PASS requires independent_judge");
    require(governance.decision === "approved", "governance PASS requires an approved decision");
    require(HTTPS.test(governance.evidence_url ?? ""), "governance PASS requires HTTPS evidence");
    require(SHA256.test(governance.evidence_sha256 ?? ""), "governance PASS requires evidence_sha256");
  }

  const operations = manifest.operations ?? {};
  require(exactKeys(operations, OPERATIONS_FIELDS), "operations fields must match schema exactly");
  require(["open", "pass", "failed"].includes(operations.status), "operations.status is invalid");
  require(operations.release_pin === manifest.release_id, "operations.release_pin must equal release_id");
  require(typeof operations.deployed === "boolean", "operations.deployed must be boolean");
  require(typeof operations.health_verified === "boolean", "operations.health_verified must be boolean");
  require(typeof operations.recovery_verified === "boolean", "operations.recovery_verified must be boolean");
  require(typeof operations.rollback_verified === "boolean", "operations.rollback_verified must be boolean");
  require(operations.evidence_url === "" || HTTPS.test(operations.evidence_url ?? ""), "operations.evidence_url must be empty or HTTPS");
  require(operations.evidence_sha256 === "" || SHA256.test(operations.evidence_sha256 ?? ""), "operations.evidence_sha256 must be empty or a full SHA-256");
  if (operations.status === "pass") {
    require(nonEmpty(operations.environment), "operations PASS requires environment");
    require(nonEmpty(operations.operator), "operations PASS requires a named operator");
    require(nonEmpty(operations.independent_judge), "operations PASS requires an independent judge");
    require(Number.isFinite(Date.parse(operations.started_at ?? "")), "operations PASS requires started_at");
    require(Number.isFinite(Date.parse(operations.completed_at ?? "")), "operations PASS requires completed_at");
    require(Date.parse(operations.completed_at ?? "") >= Date.parse(operations.started_at ?? ""), "operations.completed_at must not precede started_at");
    for (const key of ["deployed", "health_verified", "recovery_verified", "rollback_verified"]) {
      require(operations[key] === true, `operations PASS requires ${key}=true`);
    }
    require(HTTPS.test(operations.evidence_url ?? ""), "operations PASS requires HTTPS evidence");
    require(SHA256.test(operations.evidence_sha256 ?? ""), "operations PASS requires evidence_sha256");
  }

  require(exactKeys(manifest.approvals, ["product", "security", "legal"]), "approvals fields must match schema exactly");
  for (const role of ["product", "security", "legal"]) {
    const approval = manifest.approvals?.[role] ?? {};
    require(exactKeys(approval, APPROVAL_FIELDS), `approvals.${role} fields must match schema exactly`);
    require(typeof approval.name === "string", `approvals.${role}.name must be a string`);
    require(approval.evidence_url === "" || HTTPS.test(approval.evidence_url ?? ""), `approvals.${role}.evidence_url must be empty or HTTPS`);
    require(approval.evidence_sha256 === "" || SHA256.test(approval.evidence_sha256 ?? ""), `approvals.${role}.evidence_sha256 must be empty or a full SHA-256`);
  }

  require(Array.isArray(manifest.blockers), "blockers must be an array");
  for (const [index, blocker] of (manifest.blockers ?? []).entries()) {
    require(exactKeys(blocker, BLOCKER_FIELDS), `blockers[${index}] fields must match schema exactly`);
    for (const key of ["id", "owner", "resolution", "evidence_required"]) {
      require(nonEmpty(blocker?.[key]), `blockers[${index}].${key} is required`);
    }
  }

  if (manifest.status === "candidate") {
    require((manifest.blockers ?? []).length > 0, "candidate must name at least one blocker");
  }

  if (manifest.status === "pass") {
    require(Object.hasOwn(manifest, "authorized_release"), "PASS requires complete authorized_release policy, tag and asset hashes");
    require((manifest.blockers ?? []).length === 0, "PASS requires an empty blocker list");
    require(EXPECTED_PINS.every((name) => manifest.pins?.[name]?.merge_status === "merged" && HTTPS.test(manifest.pins?.[name]?.pr_url ?? "")), "PASS requires every pin to be merged with HTTPS PR evidence");
    require(EXPECTED_GATES.every((id) => manifest.gates?.[id]?.status === "pass"), "PASS requires A1-A8 to PASS on the same release pin");
    require(EXPECTED_MARKET_GATES.every((id) => manifest.market_gates?.[id]?.status === "pass"), "PASS requires market gates R0-R3 to PASS");
    require(marketEvidence.status === "pass", "PASS requires independently attested market evidence");
    require(sourceCi.status === "pass" && HTTPS.test(sourceCi.run_url ?? ""), "PASS requires green remote source CI evidence");
    require(artifacts.status === "pass", "PASS requires artifact status PASS");
    require(governance.status === "pass", "PASS requires governance status PASS");
    require(operations.status === "pass", "PASS requires operations status PASS");
    for (const role of ["product", "security", "legal"]) {
      const approval = manifest.approvals?.[role] ?? {};
      require(nonEmpty(approval.name) && HTTPS.test(approval.evidence_url ?? "") && SHA256.test(approval.evidence_sha256 ?? ""), `PASS requires named ${role} approval with HTTPS evidence and SHA-256`);
    }
  }

  return errors;
}

function defaultManifestPaths() {
  const directory = join(ROOT, "fleet", "manifests");
  return readdirSync(directory)
    .filter((name) => name.endsWith(".json"))
    .sort()
    .map((name) => join(directory, name));
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const paths = process.argv.slice(2).map((path) => resolve(path));
  const manifests = paths.length > 0 ? paths : defaultManifestPaths();
  let failed = false;
  for (const path of manifests) {
    try {
      const manifest = JSON.parse(readFileSync(path, "utf8"));
      const errors = validateManifest(manifest, path);
      if (errors.length > 0) {
        failed = true;
        for (const error of errors) console.error(`FAIL ${error}`);
      } else {
        console.log(`PASS ${path} :: ${manifest.status} :: ${manifest.release_id}`);
      }
    } catch (error) {
      failed = true;
      console.error(`FAIL ${path}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  process.exit(failed ? 1 : 0);
}
