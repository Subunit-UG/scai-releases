#!/usr/bin/env node
// Geschlossener Sonar-Vertrag: nur Installer, Updater-Payloads und deren Signaturen.
import { appendFileSync, closeSync, constants, copyFileSync, fstatSync, lstatSync, mkdirSync, mkdtempSync, openSync, readFileSync, readSync, readdirSync, realpathSync, unlinkSync, writeFileSync } from 'node:fs';
import { join, resolve, extname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, createPublicKey } from 'node:crypto';
import { execFileSync, spawn } from 'node:child_process';
import { assertMonotonic } from './assert-semver-monotonic.mjs';
import { exactKeys, releaseAssetUrl } from './release-authorization.mjs';

// Liegt seit dem Org-Umzug unter Subunit-UG (gleiche Repo-ID 1296325507).
export const REPOSITORY = 'Subunit-UG/sonar-releases';
export const TARGETS = ['aarch64-apple-darwin', 'x86_64-apple-darwin', 'x86_64-pc-windows-msvc', 'aarch64-pc-windows-msvc', 'x86_64-unknown-linux-gnu'];
const sha = value => typeof value === 'string' && /^[0-9a-f]{40}$/.test(value) && value.length === 40;
const tag = value => typeof value === 'string' && /^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(value) && !value.endsWith('\n');
const json = path => JSON.parse(readFileSync(path, 'utf8'));
const gh = args => JSON.parse(execFileSync('gh', ['api', ...args], { encoding: 'utf8' }));
const digest = path => createHash('sha256').update(readFileSync(path)).digest('hex');
const regular = path => { const s = lstatSync(path); if (!s.isFile() || s.isSymbolicLink() || !s.size) throw Error('Leere Datei oder unzulässiger Dateityp'); };

export function validateRequest(sourceSha, releaseTag, diagnosticKey = '') {
  if (!sha(sourceSha) || !tag(releaseTag)) throw Error('Vollständiger SHA und stabiler vX.Y.Z-Tag erforderlich');
  if (diagnosticKey) {
    const key = createPublicKey(Buffer.from(diagnosticKey, 'base64'));
    if (key.asymmetricKeyType !== 'rsa' || key.asymmetricKeyDetails.modulusLength < 3072) throw Error('Diagnose benötigt RSA mit mindestens 3072 Bit');
  }
  return { source_sha: sourceSha, tag: releaseTag };
}

export function validateSource(config, pins, releaseTag) {
  if (!tag(releaseTag) || config.version !== releaseTag.slice(1) || config.productName !== 'Sonar'
      || config.bundle?.createUpdaterArtifacts !== true) throw Error('Sonar-Version oder Updater-Vertrag abweichend');
  const pubkey = config.plugins?.updater?.pubkey;
  if (typeof pubkey !== 'string' || !Buffer.from(pubkey, 'base64').toString('utf8').startsWith('untrusted comment:')) throw Error('Updater-Public-Key fehlt');
  if (!exactKeys(pins, ['bridge-tauri', 'trace-tauri'])) throw Error('Komponenten-Pins fehlen oder sind unerwartet');
  const result = {};
  for (const [component, prefix] of [['bridge-tauri', 'bridge'], ['trace-tauri', 'trace']]) {
    const pin = pins[component];
    if (!exactKeys(pin, ['tag', 'sha']) || !tag(pin.tag) || !sha(pin.sha)) throw Error('Ungültiger Komponenten-Pin');
    result[`${prefix}_sha`] = pin.sha;
    result[`${prefix}_tag`] = pin.tag;
  }
  return result;
}

export function assertRemoteState(releases, refs, releaseTag) {
  if (!Array.isArray(releases) || !Array.isArray(refs)) throw Error('Ungültige GitHub-Antwort');
  if (releases.some(r => r.tag_name === releaseTag) || refs.some(r => r.ref === `refs/tags/${releaseTag}`)) throw Error('Release oder Tag existiert bereits; unveränderlich');
  // Jede veröffentlichte stabile Version prüfen, auch wenn Latest manuell zurückgesetzt wurde.
  for (const release of releases.filter(r => !r.draft && !r.prerelease)) {
    if (!tag(release.tag_name)) throw Error('Veröffentlichter Tag ist kein stabiler SemVer-Tag');
    assertMonotonic(release.tag_name, releaseTag);
  }
}
function checkRemote(releaseTag) {
  const releases = gh(['--paginate', '--slurp', `repos/${REPOSITORY}/releases?per_page=100`]).flat();
  const refs = gh(['--paginate', '--slurp', `repos/${REPOSITORY}/git/matching-refs/tags/${releaseTag}`]).flat();
  assertRemoteState(releases, refs, releaseTag);
}

export function targetAssets(releaseTag, target) {
  if (!tag(releaseTag) || !TARGETS.includes(target)) throw Error('Unzulässiger Tag oder Target');
  const version = releaseTag.slice(1);
  if (target.endsWith('apple-darwin')) {
    const arch = target.startsWith('aarch64') ? 'aarch64' : 'x64';
    return [`Sonar_${arch}.app.tar.gz`, `Sonar_${arch}.app.tar.gz.sig`, `Sonar_${version}_${arch}.dmg`];
  }
  const name = target.endsWith('windows-msvc')
    ? `Sonar_${version}_${target.startsWith('aarch64') ? 'arm64' : 'x64'}-setup.exe`
    : `Sonar_${version}_amd64.deb`;
  return [name, `${name}.sig`];
}
export const assetNames = releaseTag => [...TARGETS.flatMap(t => targetAssets(releaseTag, t)), 'latest.json'].sort();

export const FRONTEND_LIMITS = Object.freeze({ entries: 4096, depth: 32, fileBytes: 32 * 1024 * 1024, totalBytes: 128 * 1024 * 1024 });
const frontendExtensions = new Set(['.html', '.js', '.mjs', '.css', '.svg', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.avif', '.ico', '.woff', '.woff2', '.ttf', '.otf', '.wasm']);
const fingerprint = s => [s.dev, s.ino, s.mode, s.nlink, s.size, s.mtimeNs, s.ctimeNs].map(String);
const sameStat = (a, b) => JSON.stringify(fingerprint(a)) === JSON.stringify(fingerprint(b));
const directoryStat = path => {
  const s = lstatSync(path, { bigint: true });
  if (!s.isDirectory() || s.isSymbolicLink()) throw Error('Ungültiges Frontend-Verzeichnis');
  return s;
};
// Bound the read as well as the stat: a growing/replaced file must never turn
// the scanner into an unbounded allocation or make it inspect another inode.
function frontendBytes(path, before) {
  if (!before.isFile() || before.nlink !== 1n || before.size > BigInt(FRONTEND_LIMITS.fileBytes)) throw Error('Unzulässige Frontend-Datei/Größe/Hardlink');
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
  try {
    if (!sameStat(before, fstatSync(fd, { bigint: true }))) throw Error('Frontend-Datei ausgetauscht');
    const data = Buffer.alloc(Number(before.size) + 1);
    let length = 0, read;
    while (length < data.length && (read = readSync(fd, data, length, data.length - length, null))) length += read;
    if (length !== Number(before.size) || !sameStat(before, fstatSync(fd, { bigint: true }))
        || !sameStat(before, lstatSync(path, { bigint: true }))) throw Error('Frontend-Datei während Prüfung verändert');
    return data.subarray(0, length);
  } finally { closeSync(fd); }
}
function confidentialMarker(data) {
  // Byte scan, independent of extension, BOM, alignment and text decoding.
  // Removing NUL also covers UTF-16 LE/BE and UTF-32 LE/BE in binary assets.
  const marker = /sourceMappingURL|sourcesContent/i;
  if (marker.test(data.toString('latin1').replace(/\0/g, ''))) return true;
  const normalize = text => text.normalize('NFKC').replace(/[\p{White_Space}\p{Cf}\u0000]/gu, '');
  const scanText = text => marker.test(normalize(normalize(text)
    .replace(/\\u\{([0-9a-f]{1,6})\}|\\u([0-9a-f]{4})|\\x([0-9a-f]{2})/gi,
      (match, brace, unicode, hex) => { const n = parseInt(brace || unicode || hex, 16); return n <= 0x10ffff ? String.fromCodePoint(n) : match; })));
  if (scanText(data.toString('utf8'))) return true;
  if (data.includes(0)) {
    for (const offset of [0, 1]) {
      const aligned = data.subarray(offset, offset + Math.floor((data.length - offset) / 2) * 2);
      if (scanText(aligned.toString('utf16le')) || scanText(Buffer.from(aligned).swap16().toString('utf16le'))) return true;
    }
  }
  return false;
}
function verifyCrystal(data) {
  // Sonar's CrystalOverlay loads this exact Draco GLB; no general .glb escape.
  if (data.length < 20 || !data.subarray(0, 4).equals(Buffer.from('glTF'))
      || data.readUInt32LE(4) !== 2 || data.readUInt32LE(8) !== data.length) throw Error('Ungültiges Sonar-GLB');
  let offset = 12, chunks = 0;
  while (offset < data.length) {
    if (offset + 8 > data.length) throw Error('Ungültiges Sonar-GLB');
    const size = data.readUInt32LE(offset), type = data.readUInt32LE(offset + 4);
    if (size % 4 || offset + 8 + size > data.length || chunks > 1
        || type !== (chunks === 0 ? 0x4e4f534a : 0x004e4942)) throw Error('Ungültiges Sonar-GLB');
    if (chunks === 0 && JSON.parse(data.toString('utf8', offset + 8, offset + 8 + size)).asset?.version !== '2.0') throw Error('Ungültiges Sonar-GLB');
    offset += 8 + size; chunks++;
  }
  if (!chunks) throw Error('Ungültiges Sonar-GLB');
}
function archiveHeader(data) {
  // Renaming an archive to an allowed asset extension must not bypass the gate.
  return ['504b0304', '504b0506', '504b0708', '1f8b08', '377abcaf271c', '526172211a07', 'fd377a585a00', '425a68', '28b52ffd']
    .some(hex => data.subarray(0, hex.length / 2).equals(Buffer.from(hex, 'hex')))
    || data.subarray(257, 262).equals(Buffer.from('ustar'));
}
export function verifyFrontend(source) {
  directoryStat(source);
  source = realpathSync(source);
  const tauri = join(source, 'src-tauri'); directoryStat(tauri);
  // Tauri merges platform configs and TAURI_CONFIG, including JSON5/TOML and
  // kebab-case aliases. Sonar needs none: reject rather than emulate its parser.
  if (process.env.TAURI_CONFIG !== undefined || readdirSync(tauri).some(name =>
    /^(?:tauri(?:\.[^.]+)?\.conf\.json5?|Tauri(?:\.[^.]+)?\.toml)$/i.test(name) && name !== 'tauri.conf.json')) throw Error('Ungeprüfte Tauri-Konfiguration');
  const configPath = join(tauri, 'tauri.conf.json'), configStat = lstatSync(configPath, { bigint: true });
  const configBytes = frontendBytes(configPath, configStat), config = JSON.parse(configBytes.toString('utf8'));
  if (config.build?.frontendDist !== '../dist' || Object.keys(config.build).some(k => k.includes('-'))
      || config.build.runner || config.build.beforeBundleCommand
      || (config.bundle?.resources && Object.keys(config.bundle.resources).length)) throw Error('Ungeprüfter Frontend- oder Ressourcenpfad');
  const dist = join(tauri, config.build.frontendDist), records = [];
  let entries = 0, bytes = 0, index = false;
  const visit = (directory, relative = '', depth = 0) => {
    const before = directoryStat(directory);
    if (depth > FRONTEND_LIMITS.depth) throw Error('Frontend zu tief verschachtelt');
    // Directory sizes/metadata vary across filesystems; only their path/type bind.
    records.push([relative, 'directory', 0, null]);
    for (const name of readdirSync(directory).sort()) {
      if (++entries > FRONTEND_LIMITS.entries) throw Error('Frontend enthält zu viele Einträge');
      // No dotfiles, ADS, trailing dots/spaces, Unicode/path-parser differences
      // or Windows device names, on any runner platform.
      if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(name) || name.endsWith('.')
          || /^(?:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/i.test(name)) throw Error('Unzulässiger Frontend-Name');
      const path = join(directory, name), rel = relative ? `${relative}/${name}` : name;
      const entry = lstatSync(path, { bigint: true });
      if (entry.isDirectory()) visit(path, rel, depth + 1);
      else {
        if (!frontendExtensions.has(extname(name).toLowerCase()) && rel !== 'unitone-crystall.glb') throw Error('Nicht erlaubtes Frontend-Format');
        bytes += Number(entry.size);
        if (bytes > FRONTEND_LIMITS.totalBytes) throw Error('Frontend zu groß');
        const data = frontendBytes(path, entry);
        if (archiveHeader(data)) throw Error('Archiv im Frontend');
        if (confidentialMarker(data)) throw Error('Frontend enthält Sourcemap-/Quelltext-Marker');
        if (rel === 'unitone-crystall.glb') verifyCrystal(data);
        if (rel === 'index.html') index = data.length > 0;
        records.push([rel, 'file', data.length, createHash('sha256').update(data).digest('hex')]);
      }
    }
    if (!sameStat(before, lstatSync(directory, { bigint: true }))) throw Error('Frontend-Verzeichnis während Prüfung verändert');
  };
  visit(dist);
  if (!index) throw Error('Frontend index.html fehlt oder ist leer');
  // Canonical content inventory: relative path, type, size and SHA-256, sorted
  // by path. Empty directories bind too; symlinks/special files fail above.
  records.sort((a, b) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0);
  const hash = createHash('sha256').update(JSON.stringify(records)).digest('hex');
  const configRecord = ['src-tauri/tauri.conf.json', 'file', configBytes.length,
    createHash('sha256').update(configBytes).digest('hex')];
  const configHash = createHash('sha256').update(JSON.stringify([configRecord])).digest('hex');
  return { path: realpathSync(dist), hash, configHash, entries, bytes,
    binding: JSON.stringify([source, configHash, hash]) };
}
function runFrontendBuild(command, args, options) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, options);
    child.once('error', reject);
    child.once('close', (status, signal) => status === 0 && !signal ? resolve() : reject(Object.assign(Error('Tauri-Bau fehlgeschlagen'), { status })));
  });
}
export async function buildFrontend(source, target, run = runFrontendBuild) {
  if (!TARGETS.includes(target)) throw Error('Unzulässiges Target');
  const root = realpathSync(source);
  // Residual risk: a change during the build that is fully restored before
  // this post-check cannot be reliably detected without kernel enforcement.
  // Threat model: the build code is ours and Sonar's source revision is pinned.
  // These checks guarantee equal content at both boundaries, not immutability
  // throughout the build; filesystem notifications provide no such guarantee.
  const before = verifyFrontend(source);
  let failure;
  try {
    await run('bun', ['run', 'tauri', 'build', '--target', target, '--bundles', target.endsWith('apple-darwin') ? 'app,dmg' : target.endsWith('windows-msvc') ? 'nsis' : 'deb',
      '--config', '{"build":{"beforeBuildCommand":"","beforeBundleCommand":"","frontendDist":"../dist"},"bundle":{"resources":[]}}'],
    { cwd: root, stdio: 'inherit' });
  } catch (error) { failure = error; }
  // Re-run the complete allowlist, marker/encoding, GLB and config checks on
  // the actual post-build state, even when Tauri reports a build failure.
  const after = verifyFrontend(source);
  if (before.path !== after.path || before.hash !== after.hash || before.configHash !== after.configHash
      || before.binding !== after.binding) throw Error('Frontend während Tauri-Bau verändert');
  if (failure) throw failure;
  return before.hash;
}

export function assertTargetInventory(directory, releaseTag, target) {
  const stat = lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw Error('Ungültiges Installer-Verzeichnis');
  const expected = targetAssets(releaseTag, target).sort();
  if (JSON.stringify(readdirSync(directory).sort()) !== JSON.stringify(expected)) throw Error('Unerlaubtes Target-Inventar');
  for (const name of expected) regular(join(directory, name));
  return expected.map(name => join(resolve(directory), name));
}

// Never trust a filename/glob to prove that a diagnostic was encrypted. Seal
// every matching byte again; plaintext or forged inner envelopes stay private.
function sealDiagnostics(root, key, output) {
  validateRequest('a'.repeat(40), 'v0.0.0', key);
  if (!key) throw Error('Diagnose-Empfänger fehlt');
  const files = [], maxBytes = 64 * 1024 * 1024;
  let bytes = 0;
  for (const name of readdirSync(root).sort().filter(n => /^sonar-diagnostic(?:-[A-Za-z0-9._-]+)?\.json$/.test(n))) {
    const path = join(root, name);
    regular(path);
    bytes += lstatSync(path).size;
    if (bytes > maxBytes) throw Error('Diagnose zu groß');
    files.push({ name, data_base64: readFileSync(path).toString('base64') });
  }
  if (!files.length) return;
  const sealed = mkdtempSync(join(root, 'sonar-sealed-diagnostic.'));
  const payload = join(sealed, 'payload'), envelope = join(sealed, 'envelope.json');
  try {
    writeFileSync(payload, JSON.stringify({ schema_version: 1, files }), { flag: 'wx', mode: 0o600 });
    execFileSync(process.execPath, [join(fileURLToPath(new URL('.', import.meta.url)), 'encrypt-confidential-log.mjs'), payload, envelope, key], { stdio: 'pipe' });
    appendFileSync(output, `path=${envelope}\n`);
  } finally {
    try { unlinkSync(payload); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
}

function collect(source, directory, releaseTag, target) {
  // Nur die fertigen Bundle-Dateien lesen; weder target/release noch binaries/ hochladen.
  mkdirSync(directory);
  const bundle = join(source, 'src-tauri', 'target', target, 'release', 'bundle');
  const folder = target.endsWith('apple-darwin') ? 'macos' : target.endsWith('windows-msvc') ? 'nsis' : 'deb';
  for (const name of targetAssets(releaseTag, target)) {
    const original = name.endsWith('.dmg') ? join(bundle, 'dmg', name)
      : join(bundle, folder, name.replace(/^Sonar_(?:aarch64|x64)\.app/, 'Sonar.app'));
    regular(original);
    copyFileSync(original, join(directory, name), /* COPYFILE_EXCL */ 1);
  }
}
export function assertInventory(directory, releaseTag, withManifest = false) {
  const expected = assetNames(releaseTag).filter(n => withManifest || n !== 'latest.json');
  const actual = readdirSync(directory).sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) throw Error('Installer-Inventar ist unvollständig oder enthält unerlaubte Dateien');
  for (const name of actual) regular(join(directory, name));
}

export function createManifest(directory, releaseTag, verify, now = new Date()) {
  assertInventory(directory, releaseTag);
  const platforms = {};
  for (const target of TARGETS) {
    const name = targetAssets(releaseTag, target)[0];
    const signature = readFileSync(join(directory, `${name}.sig`), 'utf8').trim();
    if (!signature || !/^[A-Za-z0-9+/]+={0,2}$/.test(signature)) throw Error('Ungültige base64-Updater-Signatur');
    verify(join(directory, name), Buffer.from(signature, 'base64'));
    const platform = target.endsWith('apple-darwin') ? 'darwin' : target.endsWith('windows-msvc') ? 'windows' : 'linux';
    const arch = target.startsWith('aarch64') ? 'aarch64' : 'x86_64';
    const suffix = platform === 'darwin' ? 'app' : platform === 'windows' ? 'nsis' : 'deb';
    const entry = { signature, url: releaseAssetUrl(REPOSITORY, releaseTag, name) };
    platforms[`${platform}-${arch}`] = entry;
    platforms[`${platform}-${arch}-${suffix}`] = entry;
  }
  return { version: releaseTag.slice(1), notes: `Sonar ${releaseTag} — macOS, Windows, Linux`, pub_date: now.toISOString(), platforms };
}

function prepare(source, directory, releaseTag) {
  const config = json(join(source, 'src-tauri/tauri.conf.json'));
  validateSource(config, json(join(source, 'component-pins.json')), releaseTag);
  const pub = join(process.env.RUNNER_TEMP, 'sonar-updater.pub');
  const sig = join(process.env.RUNNER_TEMP, 'sonar-updater.minisig');
  writeFileSync(pub, Buffer.from(config.plugins.updater.pubkey, 'base64'), { flag: 'wx' });
  const manifest = createManifest(directory, releaseTag, (payload, signature) => {
    writeFileSync(sig, signature);
    execFileSync(process.env.MINISIGN_BIN, ['-Vm', payload, '-x', sig, '-p', pub], { stdio: 'pipe' });
  });
  writeFileSync(join(directory, 'latest.json'), `${JSON.stringify(manifest, null, 2)}\n`, { flag: 'wx' });
}

function publish(directory, releaseTag) {
  assertInventory(directory, releaseTag, true);
  checkRemote(releaseTag);
  const names = assetNames(releaseTag);
  const body = `Sonar ${releaseTag} — macOS, Windows, Linux`;
  // POST-Antwort bindet diesen Lauf an seinen eigenen Draft; kein Resume fremder Drafts.
  const draft = gh(['-X', 'POST', `repos/${REPOSITORY}/releases`, '-f', `tag_name=${releaseTag}`, '-f', `name=Sonar ${releaseTag}`, '-f', `body=${body}`, '-F', 'draft=true']);
  if (!Number.isSafeInteger(draft.id) || draft.draft !== true || draft.tag_name !== releaseTag) throw Error('Ungültige Draft-Antwort');
  execFileSync('gh', ['release', 'upload', releaseTag, '-R', REPOSITORY, ...names.map(n => join(directory, n))], { stdio: 'pipe' });
  const uploaded = gh(['--paginate', '--slurp', `repos/${REPOSITORY}/releases/${draft.id}/assets?per_page=100`]).flat();
  if (JSON.stringify(uploaded.map(a => a.name).sort()) !== JSON.stringify(names)) throw Error('Remote-Inventar abweichend');
  for (const asset of uploaded) {
    const path = join(directory, asset.name);
    if (asset.state !== 'uploaded' || asset.size !== lstatSync(path).size || asset.digest !== `sha256:${digest(path)}`) throw Error('Remote-Asset-Digest abweichend');
  }
  const state = gh([`repos/${REPOSITORY}/releases/${draft.id}`]);
  if (!state.draft || state.tag_name !== releaseTag) throw Error('Draft wurde verändert');
  const releases = gh(['--paginate', '--slurp', `repos/${REPOSITORY}/releases?per_page=100`]).flat();
  assertRemoteState(releases.filter(r => r.id !== draft.id), [], releaseTag);
  const released = gh(['-X', 'PATCH', `repos/${REPOSITORY}/releases/${draft.id}`, '-F', 'draft=false', '-f', 'make_latest=true']);
  if (released.draft || released.tag_name !== releaseTag || gh([`repos/${REPOSITORY}/releases/latest`]).id !== draft.id) throw Error('Veröffentlichung/Latest nicht bestätigt');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [mode, ...args] = process.argv.slice(2);
    const releaseTag = process.env.TAG;
    if (mode === 'request') {
      const output = validateRequest(process.env.SOURCE_SHA, releaseTag, process.env.DIAGNOSTIC_KEY);
      appendFileSync(process.env.GITHUB_OUTPUT, Object.entries(output).map(([k, v]) => `${k}=${v}\n`).join(''));
    } else if (mode === 'source') {
      const pins = validateSource(json(join(args[0], 'src-tauri/tauri.conf.json')), json(join(args[0], 'component-pins.json')), releaseTag);
      appendFileSync(process.env.GITHUB_OUTPUT, Object.entries(pins).map(([k, v]) => `${k}=${v}\n`).join(''));
    } else if (mode === 'check-remote') checkRemote(releaseTag);
    else if (mode === 'collect') collect(args[0], args[1], releaseTag, args[2]);
    else if (mode === 'frontend-proof') verifyFrontend(args[0]);
    else if (mode === 'frontend-build') await buildFrontend(args[0], args[1]);
    else if (mode === 'delivery') {
      const paths = assertTargetInventory(args[0], releaseTag, args[1]);
      appendFileSync(process.env.GITHUB_OUTPUT, `paths<<SONAR_INSTALLER_PATHS\n${paths.join('\n')}\nSONAR_INSTALLER_PATHS\n`);
    }
    else if (mode === 'seal-diagnostics') sealDiagnostics(process.env.RUNNER_TEMP, process.env.SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64, process.env.GITHUB_OUTPUT);
    else if (mode === 'prepare') prepare(args[0], args[1], releaseTag);
    else if (mode === 'publish') publish(args[0], releaseTag);
    else throw Error('Unbekannter Sonar-Modus');
  } catch (error) {
    // Daten/Exceptions können private Dateipfade oder GitHub-Antworten enthalten.
    console.error('Sonar-Vertrag fehlgeschlagen; Details ausschließlich in vertraulicher Diagnose.');
    process.exit(process.argv[2] === 'frontend-build' && Number.isInteger(error.status) && error.status > 0 && error.status < 256 ? error.status : 1);
  }
}
