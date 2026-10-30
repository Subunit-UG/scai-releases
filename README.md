# SCAI — Releases

Installer für **SCAI (Subunit Corporate AI)** und der Feed für den In-App-Auto-Updater (`latest.json`).
Der proprietäre Quellcode liegt ausschließlich im privaten Repo
`Subunit-UG/scai-app` (früher `subunit-ai/subunit-scai`). Dieses öffentliche Repo enthält nur den Release-Vertrag,
sanitisierte Prüfevidenz und ausdrücklich allowlistete Binärartefakte.
Release-Builds aktivieren das Cargo-Feature `local-meet` auf **macOS Apple Silicon,
Windows x64 und Windows ARM64**. Dort sind lokale Meeting-Aufzeichnung,
Sprechertrennung und (unter Windows) Systemaudio in den ausgelieferten Paketen enthalten.
macOS Intel und Linux enthalten das vollständige Meet-Plugin mit Cloud-Meeting,
Bibliothek, Atlas-Anbindung und Legacy-Protokollimport; die native lokale Engine meldet
auf diesen Targets über denselben stabilen IPC-Vertrag explizit `built=false`.

Grund für die Target-Grenze: `ort`/ONNX Runtime stellt keine passende vorgebaute
x86_64-macOS-Runtime bereit. Das aktuelle Linux-Archiv referenziert glibc-2.38/C23-
Symbole, während unser kompatibler Ubuntu-22.04-Release glibc 2.35 verwendet. Die
Pipeline baut deshalb keine nicht startfähigen oder nur auf neuen Distributionen
laufenden Pakete.
Für Windows ARM64 baut die Pipeline die nativen whisper.cpp/ggml-Anteile mit
ClangCL + Ninja und aktiviert die von ggml benötigte C++-Exception-Semantik;
Rust/Tauri bleiben dabei auf `aarch64-pc-windows-msvc`.

## Download
- **macOS (Apple Silicon):** `SCAI_x.y.z_aarch64.dmg`
- **Windows x64:** `SCAI_x.y.z_x64-setup.exe`
- **Windows ARM64:** `SCAI_x.y.z_arm64-setup.exe`

Die App hält sich danach selbst aktuell (Einstellungen → Updates).

## Fleet-Release-Vertrag

`fleet/manifests/` enthält die unveränderlichen Kandidaten-Pins über alle
SCAI-Dienste. Ein Manifest darf erst `status: pass` tragen, wenn sowohl A1–A8
als auch die Marktnachweise R0–R3, getrennt verifizierte Updater- und native
Plattformsignaturen, SBOM-Digests/Provenance,
Governance-Freigaben und Betriebsdrills maschinell vollständig belegt sind.

`build-all.yml` erzeugt für eine vollständige `release_id` und einen exakten
`source_sha` zunächst einen technischen Draft. Vor Source-Checkout und
Draft-Erzeugung prüft es fail-closed, dass sämtliche Quell-, Updater-, Apple-
und Windows-Signing-Secrets gesetzt sind, ohne deren Werte auszugeben. Es
veröffentlicht standardmäßig nicht. Der explizite `publish_update=true`-Pfad ist
der technische SCAI-Updater-Zug: Nach vollständiger Plattformmatrix, Runtime-
Smokes, Signaturen, SBOM, Provenance und erneutem Asset-Digest-Check veröffentlicht
er nur, wenn privates Source-`main`, Source-Tag und eingebetteter `source_sha`
weiterhin exakt übereinstimmen. Ein langsamer alter Build kann deshalb niemals
einen neueren Updater überschreiben.

`publish-approved.yml` bleibt das strengere Fleet-Promotionstor; dafür
verlangt es ein gemergtes Fleet-Manifest mit `status: pass`, dessen vorab
bestätigten SHA-256, einen unveränderten Release-Vertrag und erneut geprüfte
Asset-Digests.

## Warum der Build in einem öffentlichen Repo läuft

Das öffentliche Repo ist ausschließlich unser CI-/Release-Orchestrator: Es stellt
die GitHub-gehosteten Linux-, macOS- und Windows-Runner sowie stabile Run- und
Release-Belege bereit, während die private Organisation derzeit keine Actions-Jobs
startet. Es macht weder `subunit-scai` noch ein anderes Quell-Repo öffentlich.

Die Vertraulichkeitsgrenze ist fail-closed:

- ausschließlich manuell ausgelöste `workflow_dispatch`-Runs, niemals Fork-/PR-Trigger,
- eindeutig nach dem exakten privaten Source-SHA benannte PR-Checks, damit parallele Läufe nicht verwechselt werden,
- je privatem Repo ein eigener read-only Deploy-Key,
- sämtliche Actions auf unveränderliche 40-Zeichen-Commits gepinnt,
- Compiler-, Test- und Build-Ausgaben werden nur in einer flüchtigen Runner-Datei
  gehalten; öffentlich erscheinen Status, Bytezahl und SHA-256, aber keine Source-Zeilen,
- private Rust-/Tauri-Buildausgaben gelangen nie in einen öffentlichen Actions-Cache,
- bei einem Fehler wird das Detail-Log nicht als öffentliches Artefakt hochgeladen;
  die Reproduktion erfolgt am gebundenen SHA im privaten Worktree,
- Release-Uploads akzeptieren nur die geschlossene Installer-/Updater-Allowlist.

Vor einer stabilen Veröffentlichung vergleicht `publish-approved.yml` außerdem
die vollständige Inventarliste in `fleet/release-contract.paths` bytegenau mit
dem gemergten Release-Contract-SHA. Der technische Draft bleibt vom Markt-Gate
getrennt; die Stable-Promotion verlangt zusätzlich einen gehashten privaten
R0–R3-Report und eine davon getrennte unabhängige Attestation.

`fleet-source-check.yml` wendet dieselbe Grenze auf die releasebezogenen
u1-chat-, Atlas-, subunit-auth- und Echo-Gates an. Jeder Lauf verlangt vier
vollständige Kandidaten-SHAs und je Repo einen eigenen read-only Deploy-Key; er
veröffentlicht keine privaten Befehlsausgaben, Evidence- oder Build-Artefakte.
Die temporären Source-Checkouts werden vor den Post-Actions entfernt. Ohne die
vier Credentials stoppt der Checkout fail-closed.

Die vom PR-Check hochgeladenen Meet- und Chat-Dock-Screenshots zeigen ausschließlich
die gebaute Produktoberfläche aus deterministischen Test-Harnessen; sie enthalten
weder den privaten Source-Tree noch Build-Logs. Der Chat-Dock-Beweis deckt Desktop,
Mobile, Browser, die freigegebene macOS-Lane und die gesperrte Windows-Pilot-Lane ab.
GitHubs automatisch angebotene Source-Archive eines Releases enthalten nur dieses
öffentliche Release-Repo.

```bash
node scripts/verify-fleet-manifest.mjs
node --test scripts/verify-fleet-manifest.test.mjs
node scripts/verify-release-workflow.mjs
node --test scripts/verify-release-workflow.test.mjs scripts/merge-cyclonedx.test.mjs
node scripts/verify-source-confidentiality.mjs
node --test scripts/run-confidential.test.mjs scripts/decrypt-confidential-envelope.test.mjs scripts/validate-release-assets.test.mjs scripts/verify-source-confidentiality.test.mjs
node scripts/verify-fleet-source-workflow.mjs
node --test scripts/checkout-private-source.test.mjs scripts/verify-fleet-source-workflow.test.mjs
node scripts/verify-echo-pr-workflow.mjs
node --test scripts/verify-echo-pr-workflow.test.mjs
node scripts/verify-readiness-evidence.mjs fleet/evidence/operations-template.json fleet/evidence/market-template.json
node --test scripts/verify-market-evidence-binding.test.mjs
```

Ein interner, Apple-signierter Trace-macOS-Pilotbundle kann im `pr-check.yml` ausschließlich für
einen exakten `trace_ref` und einen einmaligen RSA-3072+-Empfängerschlüssel erzeugt werden. Der
öffentliche Runner lädt nur den AES-256-GCM-/RSA-OAEP-verschlüsselten Umschlag für einen Tag hoch;
DMG, Build-Logs und privater Source bleiben plaintext-frei. Lokal wird er so entschlüsselt:

```bash
node scripts/decrypt-confidential-envelope.mjs envelope.json trace-host-delivery.tar.gz private-key.pem
tar -xzf trace-host-delivery.tar.gz
```

Das entschlüsselte Archiv enthält sowohl das intern signierte DMG als auch denselben geprüften
App-Bundle separat. So lässt sich die Signatur auch in eingeschränkten Testumgebungen ohne
Disk-Image-Mount kontrollieren; installiert wird weiterhin der App-Bundle bzw. das DMG.

Dieser interne Bundle ist ausdrücklich **nicht kundentauglich**: Solange Developer ID,
Notarisierung und Gatekeeper-Abnahme fehlen, dient er ausschließlich dem physischen TCC-/Capture-
Canary auf unserem eigenen Mac.

`sonar-build.yml` baut einen exakten privaten Sonar-Commit mit gebundenen Bridge-/Trace-Pins
vertraulich auf fünf Targets. Nur fertige Installer, Updater-Payloads, Signaturen und
`latest.json` gelangen nach `Subunit-UG/sonar-releases`; vorhandene Tags/Releases und
nicht monotone Versionen werden abgewiesen. Fehlerdiagnosen sind nur mit dem optionalen
Einmal-RSA-Schlüssel verschlüsselt und für einen Tag verfügbar.
