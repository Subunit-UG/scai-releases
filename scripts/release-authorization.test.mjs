import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import {
  APPROVED_OWNERS, RELEASE_REPOSITORY, isApprovedOwner, isReleaseRepository, releaseAssetNames, releaseAssetUrl,
  sameReleaseAssetUrl, sameReleaseRepository, validateReleaseAuthorization,
} from "./release-authorization.mjs";

// Org-Umzug (TJ 2026-10-30): subunit-ai/scai-releases -> Subunit-UG/scai-releases.
// Erlaubt sind genau diese zwei Owner, Groß-/Kleinschreibung egal, sonst nichts.
const tag = "v1.2.3";
const SPELLINGS = ["subunit-ai/scai-releases", "Subunit-UG/scai-releases", "SUBUNIT-AI/scai-releases", "subunit-ug/scai-releases"];
const FOREIGN = [
  "attacker/scai-releases", "Subunit-UG-evil/scai-releases", "evil-subunit-ai/scai-releases", "subunit/scai-releases",
  "subunit-ug.attacker/scai-releases", "Subunit-UG/scai-releases2", "Subunit-UG/other", "Subunit-UG/Scai-Releases",
  "Subunit-UG/scai-releases/", "/Subunit-UG/scai-releases", "Subunit-UG//scai-releases", " Subunit-UG/scai-releases",
  "Subunit-UG/scai-releases ", "Subunit-UG/scai-releases\n", "Subunit-UG", "scai-releases", "",
  "subunit-aı/scai-releases", "subunit-aİ/scai-releases", "Subunit-Uɢ/scai-releases",
];
const authorization = repository => ({
  repository, tag, distribution_policy: "market-ready",
  assets: releaseAssetNames(tag).map(name => ({ name, url: releaseAssetUrl(repository, tag, name), sha256: createHash("sha256").update(name).digest("hex") })),
});

test("kanonischer Name ist die neue Org, Allowlist hat genau zwei Owner", () => {
  assert.equal(RELEASE_REPOSITORY, "Subunit-UG/scai-releases");
  assert.deepEqual([...APPROVED_OWNERS], ["subunit-ai", "Subunit-UG"]);
  assert.ok(Object.isFrozen(APPROVED_OWNERS));
  for (const owner of ["subunit-ai", "Subunit-UG", "SUBUNIT-AI", "subunit-ug", "Subunit-Ug"]) assert.equal(isApprovedOwner(owner), true, owner);
  for (const owner of ["attacker", "subunit", "subunit-ai-", "-subunit-ai", "Subunit-UG-evil", "subunit_ai", "", null, undefined, 42, ["subunit-ai"]]) {
    assert.equal(isApprovedOwner(owner), false, String(owner));
  }
});

for (const repository of SPELLINGS) test(`Freigabe mit Schreibweise ${repository} ist gültig`, () => {
  assert.equal(isReleaseRepository(repository), true);
  assert.deepEqual(validateReleaseAuthorization(authorization(repository)), []);
});

for (const repository of FOREIGN) test(`fremdes oder unscharfes Release-Repo bleibt abgewiesen: ${JSON.stringify(repository)}`, () => {
  assert.equal(isReleaseRepository(repository), false);
  // Auch eine in sich vollständig konsistente Freigabe für ein fremdes Repo ist keine Freigabe.
  assert.match(validateReleaseAuthorization(authorization(repository)).join("\n"), /repository must be the approved release repository/);
});

test("Nicht-Strings sind nie das Release-Repo", () => {
  for (const value of [null, undefined, 0, {}, ["Subunit-UG/scai-releases"], { toString: () => "Subunit-UG/scai-releases" }]) {
    assert.equal(isReleaseRepository(value), false);
    assert.equal(sameReleaseRepository(value, RELEASE_REPOSITORY), false);
  }
});

test("Gleichheit akzeptiert beide Schreibweisen desselben Repos, sonst nichts", () => {
  for (const a of SPELLINGS) for (const b of SPELLINGS) assert.equal(sameReleaseRepository(a, b), true, `${a} == ${b}`);
  for (const foreign of FOREIGN) {
    assert.equal(sameReleaseRepository(foreign, RELEASE_REPOSITORY), false, foreign);
    assert.equal(sameReleaseRepository(RELEASE_REPOSITORY, foreign), false, foreign);
  }
});

test("Asset-URL-Gleichheit: Owner aus der Allowlist, Tag und Dateiname exakt", () => {
  const name = "SCAI_1.2.3_x64-setup.exe";
  for (const a of SPELLINGS) for (const b of SPELLINGS) assert.equal(sameReleaseAssetUrl(releaseAssetUrl(a, tag, name), releaseAssetUrl(b, tag, name)), true);
  const good = releaseAssetUrl(RELEASE_REPOSITORY, tag, name);
  for (const bad of [
    ...FOREIGN.map(repository => `https://github.com/${repository}/releases/download/${tag}/${name}`),
    releaseAssetUrl(RELEASE_REPOSITORY, "v1.2.4", name),
    releaseAssetUrl(RELEASE_REPOSITORY, tag, `${name}.sig`),
    `${good}?download=1`, `${good}#x`, `${good}/`, `${good} `,
    good.replace("https://", "http://"), good.replace("github.com", "github.com.attacker.invalid"),
    good.replace("/releases/download/", "/releases/tag/"), releaseAssetUrl(RELEASE_REPOSITORY, tag, "%2e%2e/other"),
    "", null, undefined, {},
  ]) {
    assert.equal(sameReleaseAssetUrl(bad, good), false, String(bad));
    assert.equal(sameReleaseAssetUrl(good, bad), false, String(bad));
  }
});

test("innerhalb einer Freigabe bleiben URL und repository exakt dieselbe Schreibweise", () => {
  const mixed = authorization("subunit-ai/scai-releases");
  mixed.assets[0].url = releaseAssetUrl("Subunit-UG/scai-releases", tag, mixed.assets[0].name);
  assert.match(validateReleaseAuthorization(mixed).join("\n"), /asset URL must match exact repository, tag and filename/);
});
