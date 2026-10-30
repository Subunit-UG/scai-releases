import { parseVersion } from "./assert-semver-monotonic.mjs";

// Org-Umzug (TJ 2026-10-30): subunit-ai/scai-releases heißt jetzt Subunit-UG/scai-releases.
// GitHub leitet die alte Adresse weiter, github.repository und browser_download_url
// liefern danach aber die neue. Freigaben und Belege aus der Zeit vor dem Umzug tragen
// die alte. Zugelassen sind deshalb genau diese zwei Owner (Groß-/Kleinschreibung egal,
// wie bei GitHub) und genau dieser Repo-Name, kein offenes Muster.
export const RELEASE_REPOSITORY = "Subunit-UG/scai-releases";
export const APPROVED_OWNERS = Object.freeze(["subunit-ai", "Subunit-UG"]);
const RELEASE_REPOSITORY_NAME = "scai-releases";
const APPROVED_OWNER_KEYS = new Set(APPROVED_OWNERS.map(owner => owner.toLowerCase()));
const RELEASE_ASSET_URL = /^https:\/\/github\.com\/([A-Za-z0-9-]+)\/([A-Za-z0-9._-]+)\/releases\/download\/([^/?#\s]+)\/([^/?#\s]+)$/;

// Erst ASCII erzwingen, dann kleinschreiben: Unicode-Doppelgänger (etwa das punktlose ı,
// das per toUpperCase() zu I wird) dürfen nie über Groß-/Kleinschreibung zum Owner werden.
export const isApprovedOwner = owner => typeof owner === "string" && /^[A-Za-z0-9-]+$/.test(owner)
  && APPROVED_OWNER_KEYS.has(owner.toLowerCase());

export function isReleaseRepository(value) {
  if (typeof value !== "string") return false;
  const parts = value.split("/");
  return parts.length === 2 && isApprovedOwner(parts[0]) && parts[1] === RELEASE_REPOSITORY_NAME;
}

// Es gibt genau ein Release-Repo; beide Seiten müssen eine seiner zwei Schreibweisen sein.
export const sameReleaseRepository = (a, b) => isReleaseRepository(a) && isReleaseRepository(b);

// Gleiche Download-Datei im Release-Repo: Tag und Dateiname exakt, Owner nur aus der Allowlist.
export function sameReleaseAssetUrl(actual, expected) {
  const a = typeof actual === "string" ? RELEASE_ASSET_URL.exec(actual) : null;
  const e = typeof expected === "string" ? RELEASE_ASSET_URL.exec(expected) : null;
  return Boolean(a && e && sameReleaseRepository(`${a[1]}/${a[2]}`, `${e[1]}/${e[2]}`) && a[3] === e[3] && a[4] === e[4]);
}

export const RELEASE_POLICIES = ["market-ready", "legacy-v0.125"];
export const TARGETS = ["aarch64-apple-darwin", "x86_64-apple-darwin", "aarch64-pc-windows-msvc", "x86_64-pc-windows-msvc", "x86_64-unknown-linux-gnu"];

export const exactKeys = (value, keys) => value !== null && typeof value === "object" && !Array.isArray(value)
  && Object.keys(value).length === keys.length
  && Object.keys(value).sort().join("\n") === [...keys].sort().join("\n");

export function releaseAssetNames(tag) {
  if (typeof tag !== "string" || !/^v[0-9A-Za-z.+-]+$/.test(tag) || tag.trim() !== tag) throw new Error("invalid authorized release tag");
  parseVersion(tag);
  const version = tag.slice(1);
  const payloads = ["SCAI_aarch64.app.tar.gz", "SCAI_x64.app.tar.gz",
    `SCAI_${version}_arm64-setup.exe`, `SCAI_${version}_x64-setup.exe`,
    `SCAI_${version}_amd64.AppImage`, `SCAI_${version}_amd64.deb`];
  // The current five-target build has a closed, versioned 26-file contract.
  // New published evidence/files need an explicit contract change, not a glob.
  return [...payloads, ...payloads.map(name => `${name}.sig`),
    `SCAI_${version}_aarch64.dmg`, `SCAI_${version}_x64.dmg`,
    "latest.json", "scai.cdx.json", "SHA256SUMS",
    ...TARGETS.map(target => `runtime-evidence-${target}.json`),
    ...TARGETS.slice(0, 4).map(target => `signing-evidence-${target}.json`)].sort();
}

export const releaseAssetUrl = (repository, tag, name) =>
  `https://github.com/${repository}/releases/download/${encodeURIComponent(tag)}/${encodeURIComponent(name)}`;

export function validateReleaseAuthorization(value) {
  const errors = [];
  const require = (condition, message) => { if (!condition) errors.push(`authorized_release: ${message}`); };
  require(exactKeys(value, ["repository", "tag", "distribution_policy", "assets"]), "fields must match exactly");
  if (!value || typeof value !== "object") return errors;
  require(isReleaseRepository(value.repository), "repository must be the approved release repository");
  require(RELEASE_POLICIES.includes(value.distribution_policy), "distribution policy is unsupported");
  let expected;
  try { expected = releaseAssetNames(value.tag); } catch { require(false, "tag must be an exact SemVer tag"); }
  require(Array.isArray(value.assets), "assets must be an array");
  if (!Array.isArray(value.assets)) return errors;
  const names = [];
  for (const asset of value.assets) {
    require(exactKeys(asset, ["name", "url", "sha256"]), "asset fields must be name, url and sha256");
    if (!asset || typeof asset !== "object") continue;
    require(typeof asset.name === "string" && /^[A-Za-z0-9][A-Za-z0-9._+-]*$/.test(asset.name)
      && asset.name.length <= 200 && !asset.name.includes("..") && asset.name.trim() === asset.name, "unsafe asset name");
    names.push(asset.name);
    require(typeof asset.sha256 === "string" && /^[0-9a-f]{64}$/.test(asset.sha256)
      && asset.sha256.length === 64, "asset needs an exact SHA-256");
    require(asset.url === releaseAssetUrl(value.repository, value.tag, asset.name), "asset URL must match exact repository, tag and filename");
  }
  require(new Set(names).size === names.length, "duplicate asset name");
  require(expected && names.length === expected.length && [...names].sort().every((name, i) => name === expected[i]), "complete exact release asset inventory required");
  return errors;
}
