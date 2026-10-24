# SAML emergency setup: dev520 and kombitspnew

> Steps 2–6 use the current single-tenant configuration. Dated deployment sections retain historical actions; the final section records the latest folder migration. For reusable instructions, see [README-emergency.md](README-emergency.md).


This guide records the local setup for `https://kombitspnew.safewhere.local/`. Commands that change IIS or machine environment variables require an elevated PowerShell 7 session. Do not paste real keys, secrets, assertions, or state files into the repository.

## Values for this deployment

| Setting | Value |
|---|---|
| Website | `https://kombitspnew.safewhere.local/` |
| Deployment directory | `C:\inetpub\wwwroot\kombitspnew` |
| IIS pool | `kombitspnew.safewhere.local` |
| Current pool identity | `NetworkService`; pool is 64-bit |
| SAML SP entity ID | `https://kombitspnew.safewhere.local` (no trailing slash) |
| Identify connection GUID | `99d52401-c82f-4bb0-94eb-a864be68bd37` |
| Normal SAML issuer | Identify entity ID from trusted IdP metadata (the recorded local value was `https://dev520.safewhere.local/runtime/`; verify against your tenant metadata) |
| Emergency issuer | `https://dev520.safewhere.local/runtime/emergency` |
| Issuer API base | `https://dev520.safewhere.local/runtime/` |
| Emergency client ID | `saml-example` |
| Emergency audience | `urn:emergency:saml-example` |
| WebAuthn origin | `https://kombitspnew.safewhere.local` |
| WebAuthn RP ID | `kombitspnew.safewhere.local` |
| Backend authentication | `ApiKey` in the client and matching Identify issuer client configuration |
| External file directory | `C:\ProgramData\SafewhereSamples\SamlEmergency` |

The issuer was checked against the deployed `metadata\dev520.xml`; the SP entity ID was checked against the deployed `Web.config`. Preserve their exact spelling and trailing-slash differences.

## 1. Completed: register the SAML client at Identify

On October 21, 2026:

- Added `saml-example` to `C:\ProgramData\Safewhere\EmergencyIssuer\dev520\issuer-settings.json` with the connection GUID and identifiers above.
- Enabled issuance and `PreserveNormalClaims` for the SAML client. The claim list includes the seven attributes required by `ValidateKombitAttributeProfile` and optional CPR.
- Preserved the existing OIDC registration and its encryption key.
- Created a separate RSA-2048 key, with public key ID `saml-emergency-encryption`:
  - Private, machine-DPAPI-protected key: `C:\ProgramData\SafewhereSamples\SamlEmergency\decryption-key.bin`.
  - Public JWK: `C:\ProgramData\SafewhereSamples\SamlEmergency\encryption-public.jwk.json`.
- Provisioned the SAML backend secret in the machine variable and explicit environment entries for `Identify dev520` and `kombitspnew.safewhere.local`.
- Saved the previous issuer JSON at `C:\ProgramData\Safewhere\EmergencyIssuer\dev520\backups\saml-20261021-145425\issuer-settings.json`.

Neither pool was restarted. The SAML client's operator secret, enabled external settings, signing-key trust, and stable machine key have not been provisioned as part of this issuer-only step. A complete normal-login/emergency test for this SAML deployment is still pending.

Do not rerun `New-EmergencyKey.ps1` for this directory. Replacing the key after registering it would require coordinated recovery. Keep the private key at the SAML application; Identify receives only its public JWK fields.

## 2. Verify normal SAML login first

The website currently lists both kombitdev and dev520 IdPs. Use **dev520** for this setup. A successful login through another IdP will not match this emergency registration.

Confirm that normal login reaches `MyPage.aspx`, that assertion signature checking is enabled (`OmitAssertionSignatureCheck=false`), and that the assertion satisfies `MyPage.aspx.cs`'s `ValidateKombitAttributeProfile`. A PoC claim-transformation example is:

```csharp
Issue("https://data.gov.dk/model/core/specVersion", "OIO-SAML-3.0");
Issue("https://data.gov.dk/concept/core/nsis/loa", "Substantial");
Issue("https://data.gov.dk/model/core/eid/email", "test.user@example.invalid");
Issue("https://data.gov.dk/model/core/eid/professional/cvr", "12345678");
Issue("https://data.gov.dk/model/core/eid/professional/orgName", "Example Test Organisation");
Issue("dk:gov:saml:attribute:KombitSpecVer", "1.0");
var bppXml =
    "<PrivilegeList xmlns=\"http://itst.dk/xml/ns/2006/01/privilege\">" +
        "<PrivilegeGroup Scope=\"urn:dk:gov:saml:cvr:12345678\">" +
            "<Privilege>urn:example:kombit:read</Privilege>" +
        "</PrivilegeGroup>" +
    "</PrivilegeList>";
Issue("https://data.gov.dk/model/core/eid/privilegesIntermediate",
    System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(bppXml)));
```

These are illustrative values for a local test. The profile validator checks presence rather than complete profile conformance. Email is optional only for `Profile=KOMBIT_WITHOUT_PERSONAL_DATA`; CPR is optional and is unnecessary for the emergency test. Configure NameID separately according to the normal SP configuration. Do not fabricate a bootstrap token for emergency testing; STS exchange and service-token calls are separate normal-login features.

## 3. Prepare the SAML application's external settings

Create this file outside the web root and repositories:

`C:\ProgramData\SafewhereSamples\SamlEmergency\emergency-settings.json`

Its root is the settings object itself. It does **not** have the OIDC sample's `EmergencyCredential` wrapper:

```json
{
  "Origin": "https://kombitspnew.safewhere.local",
  "RpId": "kombitspnew.safewhere.local",
  "EmergencyIssuer": "https://dev520.safewhere.local/runtime/emergency",
  "IssuerRuntimeUrl": "https://dev520.safewhere.local/runtime/",
  "NormalSamlIssuer": "https://dev520.safewhere.local/runtime/",
  "Audience": "urn:emergency:saml-example",
  "StateDirectory": "C:\\ProgramData\\SafewhereSamples\\SamlEmergency\\state",
  "PrivateEncryptionKeyFile": "C:\\ProgramData\\SafewhereSamples\\SamlEmergency\\decryption-key.bin",
  "EncryptionKeyId": "saml-emergency-encryption",
  "InitialSigningKeysFile": "C:\\ProgramData\\SafewhereSamples\\SamlEmergency\\issuer-signing-keys.json",
  "ApiKey": "replace-with-the-matching-issuer-client-key",
  "SessionMinutes": 480
}
```

All normal assertion claims, including roles, BPP privileges and historical LoA, pass through to the emergency session. Only reserved `emergency*` and `local_*` control claims are excluded. The session supplies `local_assurance=emergency-possession`; historical LoA does not grant normal NSIS assurance.

This SAML sample uses the signed assertion claim snapshot carried by Identify's emergency credential. Do not add `UseNormalAccessTokenClaims` to the SAML JSON; its loader rejects unknown properties.

Establish emergency signing-key trust over verified HTTPS and save the public JWKS at `InitialSigningKeysFile`:

```powershell
Invoke-WebRequest 'https://dev520.safewhere.local/runtime/emergency/signing-keys' `
    -OutFile 'C:\ProgramData\SafewhereSamples\SamlEmergency\issuer-signing-keys.json'
```

Do not bypass certificate validation if this fails. Correct the HTTPS binding/trust first. The key directory was provisioned for administrators, the creating user, SYSTEM, and `IIS APPPOOL\kombitspnew.safewhere.local`. Keep those restrictive permissions on the settings, keys, and state. Ensure the application's pool SID can read the files and modify its state directory.

## 4. Provision the machine key

Set `ApiKey` to the existing matching key in Identify’s SAML issuer client entry. The current setup does not require backend environment variables or an operator secret.

Provision a stable application-specific ASP.NET `machineKey` using IIS server-level configuration or a protected external deployment configuration. `AutoGenerate` is rejected by enabled emergency support. Preserve the machine key across restarts and redeployments; it protects this client's durable state and cookies. Do not copy a machine key from another sample or commit generated key values.

## 5. Build and deploy the SAML sample

Follow [the build instructions](README-emergency.md#build-package-and-test). Back up the deployed application's binaries and configuration, stop only `kombitspnew.safewhere.local`, and wait for its worker to exit before replacing files.

Deploy the website assembly, the `Kombit.Samples.CH.Emergency` assembly and dependencies, `libsodium.dll`, all emergency ASPX/ASHX files, `Emergency.Master`, and `EmergencyAssets`. Preserve deployment-specific normal SAML configuration, certificates, metadata, and machine-key settings. Use the 64-bit pool. Existing emergency pages alone do not prove that matching assemblies or enabled settings are deployed.

Add or update these entries inside the deployed `Web.config`'s existing `<appSettings>` element; do not create duplicate keys:

```xml
<add key="EmergencyCredential.Enabled" value="true" />
<add key="EmergencyCredential.SettingsFile" value="C:\ProgramData\SafewhereSamples\SamlEmergency\emergency-settings.json" />
<add key="EmergencyCredential.StateDirectory" value="C:\ProgramData\SafewhereSamples\SamlEmergency\state" />
<add key="aspnet:UseTaskFriendlySynchronizationContext" value="true" />
```

The state directory must match the external JSON. Neither that JSON nor its contents belong inside the web root.

Stop/start `Identify dev520` once to load the new issuer client configuration (only if it changed). Start the SAML pool after its settings, trust keys, and machine key are ready. Use stop/wait/start rather than an overlapping recycle because each PoC state file has one writer. No Identify OAuth2 source modification is needed for this SAML configuration.

## 6. Test preparation and emergency access

1. Obtain a **fresh normal login through dev520** after restarting Identify. A previous SAML session alone does not supply a fresh preparation record.
2. In the same browser/profile, open `https://kombitspnew.safewhere.local/Emergency.aspx` and choose **Prepare this browser**. For an existing active credential, use renewal after a fresh normal login instead of generating another key.
3. Complete authenticator registration, browser storage/read-back, and the separate possession check. Wait for **Ready**. The `poc-up` policy requires user presence, prefers user verification, and allows backed-up passkeys.
4. Expand **Identify endpoint results (PoC)** and confirm the enrollment/completion or renewal responses. A successful response alone is not readiness.
5. Open `https://kombitspnew.safewhere.local/EmergencyLogin.aspx`, choose the newest prepared credential, and complete the key check.
6. On `EmergencyHome.aspx`, verify identity/organisation claims and the BPP privilege from the normal assertion. Normal assurance claims remain historical snapshot data; local emergency controls determine the session.
7. Use **Sign out locally**. Normal federation logout and STS/service-token actions are unavailable during emergency access.

A prepared browser can use emergency login immediately; no local activation step is needed. No outage simulation or Identify pool shutdown is needed for this first test.

## Troubleshooting

| Symptom | Check |
|---|---|
| Normal SAML login reports missing profile claims | Check the seven types in `ValidateKombitAttributeProfile`; privileges must contain Base64 XML. |
| Preparation requires a new normal login | Use dev520 and complete a fresh login; issuer records last up to 24 hours, normal session validity may shorten eligibility, and enrollment consumes the record. |
| Issuer rejects enrollment | Match connection GUID, SP entity ID, and exact normal issuer, including the trailing slash. |
| `client_not_authenticated` | Match `ApiKey` in both client and Identify issuer settings and restart the affected pools after changing settings. |
| `emergency_unavailable` | Check stable machine key, external file paths, ACLs, and matching 64-bit/native dependencies. Remove `OperatorSecretVariable`, `PreserveNormalClaims`, `ClaimTypes`, `Roles`, `Privileges`, and `PrivilegeScopes` from settings files created for earlier versions. |
| BPP absent in emergency claims | Confirm the normal assertion carries `privilegesIntermediate` and Identify's issuer client has `PreserveNormalClaims` enabled, then renew. |
| Claims remain old after a configuration change | Fresh normal login, credential renewal, possession check, then login using the newest credential. |
| `csrf_rejected` | Reload the page, then retry with the freshly issued CSRF token. |
| No credential in this browser | Use the original browser/profile; clearing site data removes the stored credential. After fresh normal login, remove any **Browser copy missing** registration before preparing the same key again. |

## Deployment preparation update

The SAML website build and all 50 emergency tests passed. The preparation-page normal-login control now uses a GET link to the existing SAML login handler so that the emergency page's `form-action 'self'` policy does not block a federation redirect.

The combined live setup has been prepared with backups, hash verification, and rollback, but has not run. It will deploy the client, add the missing `EmergencyNormalLogin` action before `Redirect`, create external settings and public signing-key trust, provision a separate SAML operator secret, create and protect a stable application-specific machine key, and stop/start the SAML and Identify pools. Emergency acceptance will remain off for the initial health check.

The embedded browser currently rejects the SAML site's HTTPS certificate with a hostname mismatch. The prepared change replaces only that host's binding with the existing trusted SAN certificate `C630C059CE1E1D7FD04B8D975F8561378D491015` (`*.safewhere.local`). It does not add a new trusted certificate. Automatic approval review requires explicit user approval for this combined live scope before execution. Until that approval and successful execution, the client configuration steps above remain pending.

## Live configuration completed

The approved setup completed on October 21, 2026:

- Deployed the matching SAML website/emergency artifacts and added `EmergencyNormalLogin` before `Redirect` in the live actions list.
- Created `settings.json` and established public issuer-signing-key trust in the directory above.
- Provisioned the distinct SAML operator key and explicit pool environment variables.
- Created an application-specific stable machine key and encrypted its configuration section with `DataProtectionConfigurationProvider`.
- Switched only the kombitspnew HTTPS binding to the existing trusted wildcard certificate ending `D491015`.
- Restarted Identify dev520 to load the SAML issuer registration and started the SAML pool.
- Verified the operator page returned HTTP 200 and emergency login returned HTTP 403 while acceptance was off.
- The website build and all 50 SAML emergency tests passed. Main setup backup: `C:\Users\caotr\AppData\Local\Temp\codex-saml-complete-setup\backup-20261021-150345`.

Normal SAML login through dev520 was then verified in the embedded browser. Registration and credential storage succeeded. The initial possession check returned `key_proof_rejected`. Inspection found that the deployed configuration lacked the source's System.Memory redirect: Fido2 references 4.0.1.1 while the installed assembly is 4.0.1.2. The following redirect was added to the deployed assemblyBinding section and only the SAML pool was restarted:

```xml
<dependentAssembly>
  <assemblyIdentity name="System.Memory" publicKeyToken="cc7b13ffcd2ddd51" culture="neutral" />
  <bindingRedirect oldVersion="0.0.0.0-4.0.1.2" newVersion="4.0.1.2" />
</dependentAssembly>
```

When preserving an existing Web.config during deployment, merge required assembly binding redirects as well as app settings/actions. The pre-redirect configuration backup is `C:\Users\caotr\AppData\Local\Temp\codex-saml-complete-setup\Web.before-memory-redirect-20261021-150812.config`. The pending credential was preserved. After a fresh normal login, use **Confirm stored credential** rather than registering another key. Possession verification and emergency login are the remaining live checks until recorded below.

## Possession verification passed

The second diagnostic check confirmed a dependency-loading failure inside Fido2, rather than a rejected hardware signature. In addition to System.Memory, the deployed site needed these redirects already generated for the passing test process:

| Assembly | Installed / redirect version |
|---|---|
| CBOR | 4.5.5.0 |
| Microsoft.IdentityModel.Tokens | 6.8.0.0 |
| System.IdentityModel.Tokens.Jwt | 6.8.0.0 |
| System.Memory | 4.0.1.2 |

All four redirects now match the installed assembly identities; the three missing source entries were added to the website Web.config. The configuration backup before adding the three additional entries is `C:\Users\caotr\AppData\Local\Temp\codex-saml-complete-setup\Web.before-fido-redirects-20261021-151308.config`.

After fresh dev520 SAML login, **Confirm stored credential** succeeded in the embedded browser. The existing credential is active and the page reports **Ready**; no second binding was created. The operator page is open for explicit acceptance activation. Emergency login and its final claim display remain pending at this point.

For future verification failures, the client writes a bounded `state\proof-diagnostic.json` with only the stage, exception type, inner exception type, and a fixed reason category. It contains no challenges, assertions, signatures, token values, keys, or personal claims. Access remains restricted by the state directory's ACL. User-facing errors remain generic.

## Operator role removed
 local operator page, emergency acceptance switch, local account/key blocking, and operator secret were removed from the SAML client. The operator steps recorded above are historical. A browser can log in with its emergency credential as soon as preparation reports **Ready**. Synchronization with Identify now runs automatically, at most every ten minutes, when the preparation page loads key status.
 deploying this version to kombitspnew, delete the `OperatorSecretVariable`, `PreserveNormalClaims`, `ClaimTypes`, `Roles`, `Privileges`, and `PrivilegeScopes` properties from `settings.json`; the loader rejects unknown properties. Normal-login claims, including roles and privileges, are now always preserved unchanged. Keep `PreserveNormalClaims` enabled on the Identify issuer client. The `SAML_EMERGENCY_OPERATOR_KEY` machine and pool environment entries are no longer read and can be removed.

## October 23, 2026: current PoC deployment test

After the user deployed the current SAML client, normal login worked but emergency preparation returned 503 (`emergency_unavailable`, reference `1118b3d57ded498396a2a3daca0a7fe4`). The external settings still contained retired operator/claim-filter fields rejected by the strict settings loader. Migrated that file to the current schema, copied the existing matching SAML issuer key into `ApiKey`, and removed the obsolete properties. Keys, machine key, and state were preserved. Backup: `settings.json.before-poc-20261023-162650.bak` beside the live settings file. Restarted only the SAML pool; EmergencyLogin.aspx returned HTTP 200.

A fresh dev520 SAML login completed and the existing credential was available for renewal. Renewal was started to obtain the current `poc-up` policy and 30-day lifetime; possession verification and final emergency login are pending until recorded below.

The October 23 live SAML test completed successfully: renewal produced an active credential expiring November 22, 2026, and emergency login with it succeeded. The emergency home page displayed the normal assertion snapshot, including name, all seven KOMBIT profile claim types, repeated role values, the original BPP value, and internal user ID, plus the local emergency-session controls. Normal LoA is present as historical assertion data under the requested PoC claim-preservation behavior. No raw assertion, token, secret, or personal claim value is recorded here. The browser was left on the successful emergency home page for inspection.


## 23 October 2026: flat configuration and missing browser copies

Moved the sample's live files to `C:\ProgramData\SafewhereSamples\SamlEmergency`, without a tenant subdirectory. The settings file is now `emergency-settings.json`. Existing encryption keys, trust, and protected state were preserved. Backups are in `backups\flat-layout-20261023-164425`. Only the two sample pools were stopped/started; Identify was unchanged.

Updated the settings JSON key/state paths and both `EmergencyCredential.SettingsFile` and `EmergencyCredential.StateDirectory` in the deployed Web.config. Preserved the protected ASP.NET machine key.

Deployed the updated browser script. It removes **Forget browser copy** and shows account registrations whose browser copy is missing during normal-login preparation. The existing SAML registration has not been revoked automatically: remove it using the authenticated preparation page before retrying enrollment. The normal-login capture is in memory and must be renewed after a pool restart.


## Provision the ASP.NET machine key

Run [Set-EmergencyMachineKey.ps1](Set-EmergencyMachineKey.ps1) in an elevated PowerShell session against the deployed website, outside Git. Stop the pool first and wait until it is stopped:

```powershell
Import-Module WebAdministration
Stop-WebAppPool 'kombitspnew.safewhere.local'
Get-WebAppPoolState 'kombitspnew.safewhere.local' # Must report Stopped before continuing.
.\Set-EmergencyMachineKey.ps1 -WebConfigPath 'C:\inetpub\wwwroot\kombitspnew\Web.config'
Start-WebAppPool 'kombitspnew.safewhere.local'
```

The script generates a 64-byte validation key and a 32-byte AES key using a cryptographic RNG, then writes `system.web/machineKey` with `validation="HMACSHA256"` and `decryption="AES"`. It backs up the original configuration beside Web.config using a `.config` extension and preserves its ACL. It never prints keys or puts them on the clipboard. Keep both files restricted and outside source control. Existing explicit or encrypted keys are preserved, so rerunning the script does not rotate them. `-WhatIf` previews the change. `configSource` requires separate handling of the external file. If the application inherits a stable key from server-level configuration, retain that setup instead of creating an override.

Use `-ReplaceExisting` only during a coordinated reset: changing a machine key invalidates cookies and can make emergency state unreadable. For an existing working deployment, preserve its key. The script writes plaintext keys in deployed Web.config, as requested for the PoC; protect that file with IIS/filesystem permissions, or encrypt the section using the established deployment process. It does not change IIS pools itself.

## SAML issuer identity and PoC settings changes

Set the sample's `NormalSamlIssuer` and Identify's SAML client `NormalLoginIssuer` to the Identify tenant's **SAML entity ID**: copy `EntityDescriptor/@entityID` from trusted IdP metadata and verify that it matches the normal assertion's `Issuer`. Do not derive this value from the Runtime API URL. A tenant may use a URL or a URN as its entity ID; match it exactly. `IssuerRuntimeUrl` remains the API base URL, while `EmergencyIssuer` identifies the emergency credential issuer. The SP entity ID is a separate value.

Configuration-fingerprint checks have been removed from both sample clients and Identify for this PoC. Remove `ResetPreviousConfigurationHash` from old issuer settings. No hash-approval step or automatic revocation occurs after a settings change. Protected-state integrity, protocol/token validation, state-file ownership and missing-state checks still apply. Preserve the machine/data-protection keys; existing credentials are not rewritten to match changed settings.
