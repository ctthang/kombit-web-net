# SAML emergency setup: dev520 and kombitspnew

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
| Normal SAML issuer | `https://dev520.safewhere.local/runtime/` (trailing slash required) |
| Emergency issuer | `https://dev520.safewhere.local/runtime/emergency` |
| Issuer API base | `https://dev520.safewhere.local/runtime/` |
| Emergency client ID | `saml-example` |
| Emergency audience | `urn:emergency:saml-example` |
| WebAuthn origin | `https://kombitspnew.safewhere.local` |
| WebAuthn RP ID | `kombitspnew.safewhere.local` |
| Backend secret variable | `SAML_EMERGENCY_ISSUER_KEY` |
| Operator secret variable | `SAML_EMERGENCY_OPERATOR_KEY` |
| External file directory | `C:\ProgramData\SafewhereSamples\SamlEmergency\dev520-kombitspnew` |

The issuer was checked against the deployed `metadata\dev520.xml`; the SP entity ID was checked against the deployed `Web.config`. Preserve their exact spelling and trailing-slash differences.

## 1. Completed: register the SAML client at Identify

On October 21, 2026:

- Added `saml-example` to `C:\ProgramData\Safewhere\EmergencyIssuer\dev520\issuer-settings.json` with the connection GUID and identifiers above.
- Enabled issuance and `PreserveNormalClaims` for the SAML client. The claim list includes the seven attributes required by `ValidateKombitAttributeProfile` and optional CPR.
- Preserved the existing OIDC registration and its encryption key.
- Created a separate RSA-2048 key, with public key ID `saml-emergency-encryption`:
  - Private, machine-DPAPI-protected key: `C:\ProgramData\SafewhereSamples\SamlEmergency\dev520-kombitspnew\decryption-key.bin`.
  - Public JWK: `C:\ProgramData\SafewhereSamples\SamlEmergency\dev520-kombitspnew\encryption-public.jwk.json`.
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

These are illustrative values for a local test. The BPP XML was checked with the sample's parser. The profile validator checks presence rather than complete profile conformance. Email is optional only for `Profile=KOMBIT_WITHOUT_PERSONAL_DATA`; CPR is optional and is unnecessary for the emergency test. Configure NameID separately according to the normal SP configuration. Do not fabricate a bootstrap token for emergency testing; STS exchange and service-token calls are separate normal-login features.

## 3. Prepare the SAML application's external settings

Create this file outside the web root and repositories:

`C:\ProgramData\SafewhereSamples\SamlEmergency\dev520-kombitspnew\settings.json`

Its root is the settings object itself. It does **not** have the OIDC sample's `EmergencyCredential` wrapper:

```json
{
  "Origin": "https://kombitspnew.safewhere.local",
  "RpId": "kombitspnew.safewhere.local",
  "EmergencyIssuer": "https://dev520.safewhere.local/runtime/emergency",
  "IssuerRuntimeUrl": "https://dev520.safewhere.local/runtime/",
  "NormalSamlIssuer": "https://dev520.safewhere.local/runtime/",
  "Audience": "urn:emergency:saml-example",
  "StateDirectory": "C:\\ProgramData\\SafewhereSamples\\SamlEmergency\\dev520-kombitspnew\\state",
  "PrivateEncryptionKeyFile": "C:\\ProgramData\\SafewhereSamples\\SamlEmergency\\dev520-kombitspnew\\decryption-key.bin",
  "EncryptionKeyId": "saml-emergency-encryption",
  "InitialSigningKeysFile": "C:\\ProgramData\\SafewhereSamples\\SamlEmergency\\dev520-kombitspnew\\issuer-signing-keys.json",
  "BackendSecretVariable": "SAML_EMERGENCY_ISSUER_KEY",
  "OperatorSecretVariable": "SAML_EMERGENCY_OPERATOR_KEY",
  "PreserveNormalClaims": true,
  "ClaimTypes": [
    "https://data.gov.dk/model/core/specVersion",
    "https://data.gov.dk/model/core/eid/privilegesIntermediate",
    "https://data.gov.dk/model/core/eid/email",
    "https://data.gov.dk/model/core/eid/professional/cvr",
    "https://data.gov.dk/model/core/eid/professional/orgName",
    "dk:gov:saml:attribute:KombitSpecVer"
  ],
  "Roles": [],
  "Privileges": ["urn:example:kombit:read"],
  "PrivilegeScopes": ["urn:dk:gov:saml:cvr:12345678"],
  "SessionMinutes": 480
}
```

The privilege and scope entries above match the synthetic BPP example. For a different test, replace both with explicitly permitted values. An empty privilege or scope list grants no BPP privileges. Normal LoA is deliberately excluded from emergency claims; the emergency session supplies `local_assurance=emergency-possession`. `PreserveNormalClaims` keeps ordinary assertion claim types while role, privilege, and assurance filters still apply.

Unlike OIDC's local access-token snapshot, this SAML sample uses the signed assertion claim snapshot carried by Identify's emergency credential. Do not add `UseNormalAccessTokenClaims` to the SAML JSON; its loader rejects unknown properties.

Establish emergency signing-key trust over verified HTTPS and save the public JWKS at `InitialSigningKeysFile`:

```powershell
Invoke-WebRequest 'https://dev520.safewhere.local/runtime/emergency/signing-keys' `
    -OutFile 'C:\ProgramData\SafewhereSamples\SamlEmergency\dev520-kombitspnew\issuer-signing-keys.json'
```

Do not bypass certificate validation if this fails. Correct the HTTPS binding/trust first. The key directory was provisioned for administrators, the creating user, SYSTEM, and `IIS APPPOOL\kombitspnew.safewhere.local`. Keep those restrictive permissions on the settings, keys, and state. Ensure the application's pool SID can read the files and modify its state directory.

## 4. Provision the local operator secret and machine key

The existing SAML backend secret must be reused. Do not replace the OIDC backend or operator variables. The SAML operator uses a separate random secret; it must differ from the backend secret.

Provision `SAML_EMERGENCY_OPERATOR_KEY` securely in the machine environment and an explicit environment entry for pool `kombitspnew.safewhere.local`. Generate a cryptographically random value of at least 32 characters only if the SAML operator key does not exist. An interactive PowerShell variable alone is not visible to an independently started IIS worker. Never print either secret or add it to JSON/source control.

Provision a stable application-specific ASP.NET `machineKey` using IIS server-level configuration or a protected external deployment configuration. `AutoGenerate` is rejected by enabled emergency support. Preserve the machine key across restarts and redeployments; it protects this client's durable state and cookies. Do not copy a machine key from another sample or commit generated key values.

## 5. Build and deploy the SAML sample

Follow [the build instructions](README-emergency.md#build-package-and-test). Back up the deployed application's binaries and configuration, stop only `kombitspnew.safewhere.local`, and wait for its worker to exit before replacing files.

Deploy the website assembly, the `Kombit.Samples.CH.Emergency` assembly and dependencies, `libsodium.dll`, all emergency ASPX/ASHX files, `Emergency.Master`, and `EmergencyAssets`. Preserve deployment-specific normal SAML configuration, certificates, metadata, and machine-key settings. Use the 64-bit pool. Existing emergency pages alone do not prove that matching assemblies or enabled settings are deployed.

Add or update these entries inside the deployed `Web.config`'s existing `<appSettings>` element; do not create duplicate keys:

```xml
<add key="EmergencyCredential.Enabled" value="true" />
<add key="EmergencyCredential.SettingsFile" value="C:\ProgramData\SafewhereSamples\SamlEmergency\dev520-kombitspnew\settings.json" />
<add key="EmergencyCredential.StateDirectory" value="C:\ProgramData\SafewhereSamples\SamlEmergency\dev520-kombitspnew\state" />
<add key="aspnet:UseTaskFriendlySynchronizationContext" value="true" />
```

The state directory must match the external JSON. Neither that JSON nor its contents belong inside the web root.

Stop/start `Identify dev520` once to load the new issuer client and backend environment entry. Start the SAML pool after its settings, trust keys, machine key, and operator variable are ready. Use stop/wait/start rather than an overlapping recycle because each PoC state file has one writer. No Identify OAuth2 source modification is needed for this SAML configuration.

## 6. Test preparation and emergency access

1. Obtain a **fresh normal login through dev520** after restarting Identify. A previous SAML session alone does not supply a fresh preparation record.
2. In the same browser/profile, open `https://kombitspnew.safewhere.local/Emergency.aspx` and choose **Prepare this browser**. For an existing active credential, use renewal after a fresh normal login instead of generating another key.
3. Complete authenticator registration, browser storage/read-back, and the separate possession check. Wait for **Ready**. Keep using a key with user verification and no passkey backup.
4. Expand **Identify endpoint results (PoC)** and confirm the enrollment/completion or renewal responses. A successful response alone is not readiness.
5. Open `https://kombitspnew.safewhere.local/EmergencyOperator.aspx`, sign in locally with the SAML operator key, and enable acceptance for ten minutes for the test.
6. Open `https://kombitspnew.safewhere.local/EmergencyLogin.aspx`, choose the newest prepared credential, and complete the key check.
7. On `EmergencyHome.aspx`, verify identity/organisation claims and the explicitly allowed BPP privilege. Normal LoA and bootstrap tokens must be absent. Existing role and privilege restrictions still apply.
8. Use **Sign out locally**. Normal federation logout and STS/service-token actions are unavailable during emergency access.

To copy the operator key without displaying it, run locally immediately before pasting it into the operator page:

```powershell
[Environment]::GetEnvironmentVariable('SAML_EMERGENCY_OPERATOR_KEY', 'Machine') | Set-Clipboard
```

Opening the operator or emergency-login page does not enable acceptance. Enabling issuer issuance also does not enable acceptance in the SAML client. No outage simulation or Identify pool shutdown is needed for this first test.

## Troubleshooting

| Symptom | Check |
|---|---|
| Normal SAML login reports missing profile claims | Check the seven types in `ValidateKombitAttributeProfile`; privileges must contain Base64 XML. |
| Preparation requires a new normal login | Use dev520 and complete a fresh login; references last ten minutes and are consumed by enrollment. |
| Issuer rejects enrollment | Match connection GUID, SP entity ID, and exact normal issuer, including the trailing slash. |
| `client_not_authenticated` | Match `SAML_EMERGENCY_ISSUER_KEY` in both pool environments and restart workers after changing entries. |
| `emergency_unavailable` | Check stable machine key, external file paths, ACLs, and matching 64-bit/native dependencies. |
| BPP absent in emergency claims | Populate both `Privileges` and `PrivilegeScopes` with values present in the normal assertion, then renew. |
| Claims remain old after a configuration change | Fresh normal login, credential renewal, possession check, then login using the newest credential. |
| `csrf_rejected` | Reload the page, then retry with the freshly issued CSRF token. |
| No credential in this browser | Use the original browser/profile; clearing site data removes the stored credential. |

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
