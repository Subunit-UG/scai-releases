# Release-Signierung vorbereiten

Diese Datei beschreibt ausschließlich die Signierung in `.github/workflows/build-all.yml`.
Alle Einstellungen unten sind Namen; Konto-Endpunkte, Zertifikat-Subjects und
Schlüsselwerte gehören ausschließlich in die Repository-Einstellungen.

## Windows

Ohne Auswahlvariable bleibt der bisherige PFX-Weg einschließlich seiner Preflight-Prüfungen und des Thumbprint-Vergleichs erhalten. Bei `legacy-v0.125` bleibt Windows wie bisher unsigniert.

| `WINDOWS_SIGNING_BACKEND` | Verhalten |
| --- | --- |
| nicht gesetzt / `legacy-pfx` | Unverändert: bei `market-ready` PFX-Import, Tauri `certificateThumbprint`, SHA-256 und bisheriger DigiCert-Zeitstempel; bei `legacy-v0.125` keine Authenticode-Signatur. |
| `none` | Nur mit `legacy-v0.125` und dessen bestehender Risikoannahme zulässig; `market-ready` bricht vor Draft-Erstellung ab. |
| `artifact-signing` | **Noch blockiert:** Einstellungen werden geprüft, dann Azure-OIDC-Anmeldung; die Vorbereitung bricht ausdrücklich ab. Die unveränderte `artifact-signing-cli` 0.12.0 verlangt ein Client-Secret. Ein direkter SignTool/dlib-Weg benötigt die Entscheidung zur Abweichung vom Auftrag. |
| `azure-key-vault` | `relic` 8.2.0 (x64, Download mit festem SHA-256) signiert während des Tauri-Bundlings über den HSM-Schlüssel im Key Vault. |

Cloud-Signierung benutzt eine zur Laufzeit erzeugte Override-Datei
`src-tauri/tauri.windows-signing.json` und Tauris `--config`. Die eingecheckte
App-Konfiguration bleibt unverändert. `signCommand` verwendet ein Argument-Array,
damit Pfade mit Leerzeichen intakt bleiben. Nach jeder Signatur muss
`Get-AuthenticodeSignature` einen gültigen Signer, den **exakten vollständigen
Subject** aus `WINDOWS_PUBLISHER` und einen Zeitstempel melden. Eine weitere
Prüfung erfasst Anwendung und NSIS-Installer nach dem Build. Jeder Fehler stoppt
den Build und damit die nachfolgenden Veröffentlichungsgates.

Für Key Vault wurde `relic` gewählt: Es unterstützt ausdrücklich
Azure-CLI-Zugang und Workload Federation; `pin: ""` wählt die von
`azure/login` per OIDC erzeugte CLI-Sitzung. Es braucht kein Client-Secret.
Signaturdigest: SHA-256; RFC-3161-Dienst:
`http://timestamp.acs.microsoft.com`. Der private Schlüssel bleibt im HSM.
OIDC-Rechte stehen im Build-/Signierjob, weil Tauri beim Bundling signiert.
Die Matrix teilt diese Jobrechte; der Azure-Login läuft ausschließlich in den
Windows-Zeilen mit ausdrücklich ausgewähltem Cloud-Backend.
Die vorhandenen Sigstore-Attestierungen behalten ihre OIDC-/Attestierungsrechte ausschließlich im Manifest-Job.

### Später zu setzen: nur Namen

Repository-Variablen:

- `WINDOWS_SIGNING_BACKEND`
- `WINDOWS_PUBLISHER`
- Für Artifact Signing: `ARTIFACT_SIGNING_ENDPOINT`,
  `ARTIFACT_SIGNING_ACCOUNT`, `ARTIFACT_SIGNING_CERTIFICATE_PROFILE`
- Für Key Vault: `AZURE_KEY_VAULT_CERTIFICATE_URL` (Zertifikat-URL, keine Secret-URL)

Repository-Secrets für Azure-OIDC:

- `AZURE_CLIENT_ID`
- `AZURE_TENANT_ID`
- `AZURE_SUBSCRIPTION_ID`

Azure muss eine Federated Credential für das konkrete Release-Repository und
den erlaubten Ref erhalten. Die notwendigen Rollen werden auf das jeweilige
Zertifikatsprofil bzw. den Key Vault beschränkt: Artifact Signing Certificate
Profile Signer bzw. Key Vault Certificate User und Key Vault Crypto User.
Kein `AZURE_CLIENT_SECRET` anlegen.

Der bisherige PFX-Weg benutzt unverändert die Secrets `WINDOWS_CERTIFICATE`, `WINDOWS_CERTIFICATE_PASSWORD` und `WINDOWS_CERTIFICATE_SUBJECT`. Cloud-Backends benötigen diese drei Secrets nicht.

## macOS

`APPLE_NOTARIZE_METHOD` fehlt oder ist `apple-id`: bisheriger Apple-ID-Weg bei `market-ready`; bei `legacy-v0.125` weiterhin keine Notarisierung. `api-key` ist nur mit `market-ready` zulässig.

Bei ausdrücklich gewählter Notarisierung ist eine
`Developer ID Application`-Identität erforderlich. Die bestehenden Secrets
`APPLE_CERTIFICATE`, `APPLE_CERTIFICATE_PASSWORD` und
`APPLE_SIGNING_IDENTITY` bleiben erforderlich.

| Methode | Zusätzliche Secrets |
| --- | --- |
| `apple-id` | `APPLE_ID`, `APPLE_PASSWORD`, `APPLE_TEAM_ID` |
| `api-key` | `APPLE_API_ISSUER`, `APPLE_API_KEY` (Key-ID), `APPLE_API_PRIVATE_KEY` (vollständiger roher .p8-Inhalt) |

Auswahlvariable: `APPLE_NOTARIZE_METHOD`. Im API-Key-Pfad wird die .p8 nur im
Job unter `RUNNER_TEMP` mit `umask 077` und Modus `0600` geschrieben.
`APPLE_API_KEY_PATH` entsteht ausschließlich zur Laufzeit; kein Pfad-Secret
anlegen. Nur die zur ausgewählten Methode gehörenden Authentifizierungsvariablen
werden an Tauri exportiert. Ein `always()`-Schritt entfernt die Datei auch nach
fehlgeschlagenen Builds. Native Signatur- und Stapler-Prüfungen bleiben Pflicht.


## Umstellen und zurückkehren

1. Azure-Federation/Rollen bzw. Developer-ID-Zertifikat und Apple-API-Key außerhalb
   dieses PRs bereitstellen. Obige Variablen/Secrets hinterlegen; es wurden im
   Rahmen dieses Auftrags keine Einstellungen oder Geheimnisse gelesen/gesetzt.
2. Vor Windows-Aktivierung die zugangsfreie ARM-/x64-Probe auswerten. Der
   Artifact-Signing-Pfad ist bis zur OIDC-Entscheidung ausdrücklich **nicht bereit**.
   Ein erfolgreiches `--help` beweist keine funktionsfähige Cloud-Signatur.
3. Backend bzw. Notarisierungsmethode ausdrücklich auswählen. Später einen
   separat freigegebenen Release-Lauf verwenden und Signaturen, Publisher,
   Zeitstempel, Stapler und die vorhandenen Updater-Gates prüfen.
4. Rückweg: Auswahlvariablen auf die bisherigen Standardwerte zurücknehmen bzw.
   entfernen. SCAI fällt dabei auf den PFX-Weg zurück, der bei `market-ready` weiterhin die historischen Secrets benötigt. Die bestehenden v1-/Market-Ready-Gates bleiben aktiv und
   werden durch einen Rückweg auf unsignierte Artefakte nicht umgangen.

## Probe und offene Verifikation

Die separate Probe liegt in [echo-releases/signing-probe.yml](https://github.com/subunit-ai/echo-releases/blob/feat/signing-ready-20261024/.github/workflows/signing-probe.yml). Sie prüft die gepinnten x64-CLIs, x64-SignTool und das Laden der Microsoft-dlib einschließlich ihres Exports in einem x64-.NET-Host auf `windows-latest` und `windows-11-arm`. Kein Export wird aufgerufen; es wird nichts signiert.

Stand: Die Probe wurde als Dispatch-Workflow auf
`feat/signing-ready-20261024` hochgeladen. Der Start per
`gh workflow run signing-probe.yml --ref feat/signing-ready-20261024`
scheitert mit HTTP 404: `workflow signing-probe.yml not found on the default branch`.
Es wurde kein Workflow auf main gestartet und nichts gemergt.
Es gibt **keinen Run-Link und kein Messergebnis**. Beide Runner sowie tatsächliche
OIDC-Anmeldung, Zertifikatszugriff, Signierung und Notarisierung sind
**nicht verifiziert**. Die CLI-Quellen belegen unabhängig davon die fehlende
OIDC-Unterstützung der unveränderten Version 0.12.0.
Eine einmalige Registrierung über einen eng begrenzten Branch-Trigger ist eine
angefragte Alternative und noch nicht freigegeben.

### Plan B, falls ARM-Werkzeuge nicht starten

In einem gesonderten Umbau: auf ARM64 nur kompilieren und die benötigten
ARM64-Anwendungsdateien, Sidecars und Bundle-Eingaben an einen Windows-x64-Job
übergeben. Dort zuerst die ARM64-Anwendung und Sidecars signieren, danach mit
dem ARM64-Target den NSIS-Installer paketieren und auch diesen signieren.
Nur den fertigen Installer nachträglich zu signieren würde eine unsignierte
eingebettete Anwendung nicht beheben. Den fertigen Installer anschließend
auf ARM64 für Paket-Smoke und Evidenz über die endgültigen Bytes prüfen.

Authenticode verändert die Dateibytes. Deshalb erst **nach** der letzten
Authenticode-Signatur die Tauri-Updater-Signatur `.sig` erzeugen bzw. neu erzeugen.
`latest.json` muss diese endgültige Signatur referenzieren. Sämtliche SHA-256-Werte
in Trust-Evidenz, Manifesten und Prüfsummen sowie die Asset-IDs müssen an die
endgültig hochgeladenen Dateien gebunden werden. Bereits veröffentlichte Assets
oder Signaturen dürfen nicht ersetzt werden. Der aktuelle PR setzt diesen
Job-Umbau nicht um und verändert weder die Updater- noch die Lockstep-Logik.

## Lokale Prüfung dieses Standes

`actionlint` 1.7.12 besteht mit `-shellcheck=`; der vollständige Lauf meldet
unverändert die drei bereits auf main vorhandenen ShellCheck-Hinweise
(SC2015, zweimal SC2094). Keine neue Diagnose. Alle 34 bestehenden
Release-Workflow-Tests bestehen.
28 synthetische Vergleiche des alten und neuen Preflights (beide Policies,
jeweils vollständige und einzeln fehlende Secrets) ergeben bei fehlenden
Auswahlvariablen identische Exitcodes und Ausgaben. Source-Checkout,
Build-/Updater-/Upload-Befehl und Manifest-Gates sind strukturell unverändert;
im Manifest-Job wurden ausschließlich bestehende Rechte auf Job-Ebene verlagert.
Tatsächliche Plattform-Builds und Anbieterzugriffe sind nicht geprüft.

## Quellen

- [Tauri: Windows-Signierung und signCommand](https://v2.tauri.app/distribute/sign/windows/)
- [Tauri: signCommand mit Argument-Array](https://v2.tauri.app/reference/config/#customsigncommandconfig)
- [artifact-signing-cli 0.12.0: verpflichtendes Secret und eigener Azure-Login](https://github.com/Levminer/artifact-signing-cli/blob/0.12.0/src/main.rs)
- [relic 8.2.0: Azure-Authentifizierung](https://github.com/sassoftware/relic/blob/v8.2.0/doc/azure.md)
- [Azure Login: OIDC](https://github.com/Azure/login/tree/v2#login-with-openid-connect-oidc-recommended)
- [Microsoft: SignTool, dlib und Authentifizierung](https://learn.microsoft.com/en-us/azure/artifact-signing/how-to-signing-integrations)
- [GitHub: Dispatch und Default-Branch](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_dispatch)
