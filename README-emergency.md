# SAML emergency access PoC
## Current PoC configuration (October 23, 2026)

Configure a matching `ApiKey` string directly in each Identify `Clients[]` entry and in that client's settings. For example, use `"ApiKey": "oidc-poc-key"` on both OIDC sides and a different `"ApiKey": "saml-poc-key"` on both SAML sides. Plain nonempty text or a GUID is supported, up to 512 characters without control characters. No issuer-key environment variables are required. Existing environment-variable settings are supported only as a legacy fallback when ApiKey is absent. Do not print live keys in diagnostics.

The issuer defaults and upper bounds are RecordLifetime=`1.00:00:00` (24 hours), EnrollmentLifetime=`01:00:00` (1 hour), and CredentialLifetime=`30.00:00:00` (30 days). The enrollment deadline is capped by its source record's expiry. Client preparation is also bounded by normal-login validity. Both clients accept the corresponding 30-day credentials; revocations are retained for 30 days plus five minutes. WebAuthn proof challenges remain short-lived. Deploy issuer and client updates together before issuing longer credentials.

OIDC uses the normal ID token; SAML uses the normal assertion. Normal protocol, assurance, identity, application, and repeated claims are retained in the credential snapshot and emergency principal. Their original exp/iat/iss/acr values describe the original login; the emergency session has its own independently enforced expiry and authentication type. Source claims cannot replace internal `emergency*` or `local_*` session controls. General size, signature, issuer, audience, and input validation remain enforced. Renew after a fresh normal login to obtain a new snapshot. Attributes absent from the ID token/assertion cannot be invented by the client.


The sample keeps Web Forms, .NET Framework 4.8, and OIOSAML.NET. Emergency support is disabled by default. `Kombit.Samples.CH.Emergency` belongs to this repository and uses public Fido2 2.0.2. It shares no code, DTO project, or browser bundle with the OIDC example. Identify keeps Safewhere.Fido2.

For the local dev520/kombitspnew deployment, use the [step-by-step setup guide and completed setup record](README-emergency-setup-dev520.md).

## Configure an isolated deployment

1. Build with Visual Studio's .NET Framework and Web Application tools. Use a 64-bit IIS/IIS Express worker. Keep `libsodium.dll` and the managed dependencies in the web output/package.
2. Configure normal SAML login. Its IdP must validate assertion signatures: `OmitAssertionSignatureCheck` must be false. Emergency capture runs after `SetSamlPrincipal`/`LogAction` and before `Redirect`. It uses the accepted OIOSAML callback, not raw posted XML.
3. Assign this sample a separate HTTPS host, RP ID, audience, and RSA key. In PowerShell 7.2 or later:

   ```powershell
   ./New-EmergencyKey.ps1 -Directory C:\ProgramData\SafewhereSamples\SamlEmergency -EmergencyAudience urn:emergency:saml-example -ApplicationPoolIdentity 'IIS APPPOOL\SamlSample'
   ```

   The directory must be new, local, and outside all repositories and web roots. The tool restricts ACLs and creates a DPAPI-protected private key plus a public JWK. It does not enable support or create TLS credentials.
4. Register the public JWK's `kid`, `n`, and `e` in Identify. Match the normal SAML entity ID, issuer, and Identify connection GUID, and enable issuance for that client.
5. Copy [emergency-settings.example.json](emergency-settings.example.json) outside the repository. Replace all placeholders. `IssuerRuntimeUrl` ends in `/`. Obtain emergency signing keys over verified HTTPS, establish trust during setup, and save them at `InitialSigningKeysFile`. Offline login never fetches keys. Remove `OperatorSecretVariable`, `PreserveNormalClaims`, `ClaimTypes`, `Roles`, `Privileges`, and `PrivilegeScopes` from settings files created for earlier versions; unknown properties are rejected.
6. Set `ApiKey` in the external SAML JSON to the same string as the issuer SAML client entry. No backend-key environment variable is required.
7. Provision a stable ASP.NET `machineKey` for this application through IIS server-level configuration or an encrypted configuration section in an external deployment. Preserve it across restarts. Enabled emergency support rejects `AutoGenerate` keys. Do not commit key values.
8. Set these deployment application settings and restart:

   ```xml
   <add key="EmergencyCredential.Enabled" value="true" />
   <add key="EmergencyCredential.SettingsFile" value="C:\ProgramData\SafewhereSamples\SamlEmergency\emergency-settings.json" />
   <add key="EmergencyCredential.StateDirectory" value="C:\ProgramData\SafewhereSamples\SamlEmergency\state" />
   <add key="EmergencyCredential.Authenticator" value="any" />
   <add key="aspnet:UseTaskFriendlySynchronizationContext" value="true" />
   ```

   The state path must match the external JSON. `EmergencyCredential.Authenticator` is optional (`any`, `platform`, or `security-key`); see [Preferred authenticator](#preferred-authenticator). The synchronization setting supports the async handler while keeping the current framework.

State uses `MachineKey.Protect` with an application-specific purpose. Private RSA files use machine-bound DPAPI and an audience-specific purpose. Restrict ACLs to the application identity and approved administrators. Use one worker; a second writer is rejected. Loss of state or a machine-key change requires deliberate recovery and new preparation. DPAPI files are not portable between machines.

## Use the feature

After a normal login, My Page (and the home page's **Prepare emergency access** button) offers emergency setup. **Set up emergency access** registers a discoverable passkey with user verification required (one WebAuthn prompt). Identify issues the emergency credential to the server, which validates and activates it in its registry in the same request. The browser never receives or stores the credential; it keeps only a non-secret marker (binding ID and expiry) in `localStorage` so the sign-in page knows this browser has a key. Emergency login is immediately available from the sign-in page. Missing or old assertion evidence requires a new normal login; the preparation window is at most 24 hours. See [No emergency credential in the browser](#no-emergency-credential-in-the-browser).

Emergency login from the sign-in page, `EmergencyHome.aspx`, and local logout need no Identify request. A separate protected cookie and principal represent the emergency session. No SAML assertion or `Saml20Identity` is fabricated. `MyPage.aspx` redirects an emergency user locally before its SAML expressions run. Normal STS/service-action posts and SAML login/logout handlers reject emergency callers.

Renewal is automatic and needs no browser copy. When My Page or the home page loads after a normal login and half of any of the account's active credentials' lifetime has passed (`renew_due` in the status response), the widget renews it in the background and the server activates the replacement. No prompt is shown. Renewal uses the unused normal-login record, so it happens at most once per login; a failed renewal is retried after the next login while the current credential stays valid. Removing a key deletes its registration, all associated credential versions, and sessions; failed issuer revocation reports remain queued. When My Page or the key management page loads key status, the sample synchronizes with Identify at most once every ten minutes: it refreshes trust, applies central revocations, and retries queued removals. Synchronization failures are ignored. There is no issuer request from emergency login.

Claims from the normal login are always preserved, including roles and `privilegesIntermediate` privilege XML, which pass through unchanged. An emergency session therefore carries the same roles and privileges as the normal login it was prepared from. Normal assurance, tokens, bootstrap tokens, and reserved emergency markers cannot enter the emergency principal.

To disable support, retain the settings/state-path entries, set `EmergencyCredential.Enabled=false`, and restart. Startup marks existing state so that existing emergency sessions are ended on the next enabled start, without loading the private key. Prepared browsers can log in again after re-enabling. Removing path settings is not the supported disable procedure.

## Error logs and reference IDs

Emergency failures use the existing log4net configuration in `Web.config`; no separate emergency log file is created. The sample's configured rolling-file appender writes to `log.txt`. Use the deployment's actual appender location and ensure its directory is writable by the application identity and readable only by approved administrators. Keep production logs outside publicly accessible web content.

The error page and browser action errors show a reference ID. API errors also include `reference_id` in JSON and `X-Emergency-Reference` in the response headers. Search the existing application logs for that ID to find the matching `emergency_failure` JSON event. Include the reference ID, time, error code, HTTP status, and attempted action in support reports, never the credential or token.

Events include UTC time, the error code and safe explanation, HTTP status, a normalized endpoint and recognized operation, exception types and HResults, and bounded method/line stack locations including inner causes. API failures also include the existing sanitized issuer-call diagnostics, including actual issuer HTTP statuses and endpoint templates. Client rejections are warnings; server-side failures are errors. Initialization, disabled-state marker, normal-login capture, and session-authentication exceptions are logged even when normal login or session cleanup continues.

Raw exception messages, exception `Data`, stack source paths, request bodies, arbitrary URL/query values, cookies, credentials, and issuer response bodies are deliberately omitted because they can contain secrets or personal data. Public responses never include the exception details. If a reference cannot be found, check the configured log level, appender location, and file permissions. A logging failure does not replace the original response or prevent normal authentication; a best-effort Trace fallback records only the reference ID.

## Build, package, and test

Use Visual Studio MSBuild. To compile without the existing deployment-copy event:

```powershell
MSBuild.exe ./Kombit.Samples.CH.WebsiteDemo/Kombit.Samples.CH.WebsiteDemo.csproj /restore /nodeReuse:false /maxCpuCount:1 /p:UseSharedCompilation=false /p:PostBuildEvent= /p:SolutionDir=<absolute-repository-path-with-trailing-separator>
MSBuild.exe ./Kombit.Samples.CH.Emergency.Tests/Kombit.Samples.CH.Emergency.Tests.csproj /restore /nodeReuse:false /maxCpuCount:1 /p:UseSharedCompilation=false
./Kombit.Samples.CH.Emergency.Tests/bin/Debug/net48/Kombit.Samples.CH.Emergency.Tests.exe --report-trx
dotnet build-server shutdown
```

The deployment-copy event includes the new ASPX/ASHX files, `Emergency.Master`, `EmergencyAssets`, and bin files. Confirm `libsodium.dll` is present. Provision enabled settings and machine keys in the external deployment. Keep private keys, live settings, state, and verification fixtures out of source and distributable artifacts.

Verification includes independent credential/assertion/state tests, actual Identify-issued ES256/RS256 credentials, compilation of the ASPX pages, and virtual-authenticator login at an IIS virtual directory. The browser fixture used synthetic accepted-login evidence, seeded through the actual services. It verified support off/on and restart persistence. It did not execute normal SAML federation against a configured Identify tenant or call STS.

## Remaining gaps

This is a bounded, single-process PoC. Files are not rollback-proof. Trusted hardware attestation, an emergency on/off switch, local account blocking, multi-node state, key rotation/recovery, and complete revocation resynchronization remain open. Offline authorization may be stale. Browser data deletion loses preparation.

Public Fido2 2.0.2 remains an old PoC baseline. CBOR is pinned to patched 4.5.5. The retained IdentityModel 6.8 family reports NU1902 advisories; no audit suppression was added. Complete dependency maintenance and support review before production. Full normal SAML/logout/STS regression and physical-device evidence remain required. The original demo shortcuts are not certified by this feature.

## PoC: inspect Identify endpoint results

Expand **Identify endpoint results (PoC)** on any emergency page. Open the preparation page, or perform preparation, renewal, or key removal, to see the backend calls made by that action. Each entry shows the HTTP method, endpoint template, HTTP status, elapsed milliseconds, and a redacted result summary. Network failures and rejected response bodies are distinguished from HTTP failures. A successful issuer response is not proof that local credential validation or preparation completed.

Local operations such as authenticator possession checks, emergency login, and local logout show **no Identify endpoint called** when their backend request makes no issuer call. Viewing the panel never contacts Identify or repeats an operation.

The panel keeps the latest 40 entries in this tab's session storage, including across redirects to the emergency home page. Each action includes at most its latest 8 issuer calls (synchronization may paginate). **Clear displayed history** removes only this display history; it does not remove credentials or revoke keys. If session storage is unavailable, the panel works until navigation. Existing calls from before this version was loaded are not reconstructed.

Results contain no request/response bodies, API keys, token references, emergency credential values, enrollment IDs, binding IDs, subjects, or personal claims. HTTP statuses and fixed summaries are returned only on the originating request via the bounded `X-Emergency-Issuer-Calls` response header. This is a demonstration aid, not a durable audit log.

## Preserve claims from normal login

The sample always preserves the claims from the normal login; there is no setting for it in the sample's emergency settings. The matching Identify issuer client must still have `PreserveNormalClaims: true` so that the credential carries the full snapshot. For this SAML sample, Identify captures the claims it issued in the normal SAML assertion and signs them into the emergency credential. The browser never supplies a replacement claims list. The sample projects the verified credential's snapshot into its emergency principal, preserving claim types, values, value types, and repeated claims. It does not fetch current claims during offline login.

Normal-login claim types and values, including protocol metadata and assurance claims, are preserved as historical snapshot data. Local `emergency*` and `local_*` control claims remain reserved so a source token cannot override the active session identifier or expiry. The emergency session authenticates and expires independently of the original token. Roles and SAML BPP claims are not allowlisted or rewritten.

Deploy the updated issuer and sample, remove `PreserveNormalClaims`, `ClaimTypes`, `Roles`, `Privileges`, and `PrivilegeScopes` from the sample's external settings, and restart their application pools. Then obtain a fresh normal login and renew or prepare the emergency credential. Existing credentials contain the old snapshot and cannot acquire claims retroactively. Missing attributes that were never present in the assertion cannot be invented by this option.

## Remove a key

**Remove key** on `Emergency.aspx` (two clicks: **Remove key**, then **Confirm removal**) deletes the binding and all associated credential versions from the client registry and removes the binding from this browser's marker. It ends existing sessions for that binding in every browser and rejects any further login with that passkey. An offline removal is immediately effective and survives restart; only the binding identifier needed to retry issuer revocation is retained in the internal queue. This removes the application registration; it does not erase the passkey from the authenticator or passkey manager. After removal the same authenticator can be prepared again.



The My Page card shows one state: **ready** with its expiry date and a **Manage keys** link when a key set up in this browser is active; **Set up emergency access** while a fresh unused normal-login record is available (worded as "set it up here too" when the account already has keys from other browsers or devices); or **Sign in again** when that record was used or lost (for example after an application pool restart). `Emergency.aspx` is the key management page: it lists the account's keys from the server, marks the ones set up in this browser, and offers **Remove key**. There is no "Browser copy missing" state and no browser-side activation; the `activate-stored` API operation was removed.

## Trace a request from start to finish

Emergency API responses include `X-Emergency-Reference`. The same ID appears in the existing error JSON's `reference_id` and the server's structured events. Search the log for that value to join `request_started`, any `emergency_failure`, and `request_completed`. Completion records include UTC time, normalized endpoint/recognized operation, HTTP status, elapsed milliseconds, and sanitized issuer-call summaries. Successful normal SAML capture emits `normal_login_captured` on the accepted-login callback's own reference.

These events use the existing log4net logger `Kombit.Samples.CH.WebsiteDemo.EmergencyFeature.EmergencyDiagnostics`. Enable Information or lower for that logger to see successful lifecycle events; Warning/Error still carry failures. The sample Web.config uses the `LogFileAppender` rolling-file appender with a 10 MB file limit and ten backups. Check its configured File path in the deployed configuration; for shared deployments, use a restricted writable directory outside the web root.

No request bodies, query values, cookies, tokens, credentials, API keys, or claim values are added to these lifecycle events. Existing sanitized failure records retain exception types/HResults and bounded stack method/line details. Logging failures do not interrupt the operation. A successful local removal can still have a failed upstream revocation summary because its retry is queued internally.

## No emergency credential in the browser

The browser no longer stores the emergency credential (EC). The server already keeps everything emergency login needs in its MachineKey-protected registry: the key's credential ID, public key, user handle, counter, and the credential's claims and expiry.

- **Setup.** The page requests a discoverable passkey with user verification required. Identify issues the EC to the server, which validates it and activates it immediately (`enroll-complete` and `renew` return only `ready`, `binding_id`, `ec_id`, and `expires_at`).
- **Marker.** The browser keeps `saml-emergency-login-v1` in `localStorage`: a list of `{ binding_id, expires_at }` for keys set up in this browser. It is not a secret and grants nothing; it only tells the sign-in page whether to offer emergency login. Losing it hides the card in this browser but does not break the key.
- **Login.** The page sends only the marker's binding IDs (`login-options`). The server names those keys' passkeys in the challenge (`allowCredentials`) if they are still active, so the browser goes straight to the right passkey instead of listing every passkey it holds for this site (for example a leftover Windows Hello passkey next to the Microsoft Password Manager one). Unknown, removed, or inactive bindings are ignored; with none left the challenge names no key and the browser offers its discoverable passkeys. User verification is always required. The passkey's credential ID selects the registered key; the server checks the signature, the user handle (required when no key is named, compared when returned), user verification, the counter, and the newest active credential.
- **Migration.** On the sign-in page and My Page, browsers prepared with an earlier version copy each old IndexedDB entry's binding ID and expiry into the marker and then delete the `saml-emergency-credentials-v1` database. The credentials themselves are not carried over. Keys registered as non-discoverable (possible for security keys prepared with the previous version) cannot be found without their ID; remove and prepare them again.
- **Home page.** `EmergencyHome.aspx` shows the session's credential as decrypted JSON (`jwe_header`, `jws_header`, `payload`) under **Permitted claims**, followed by a technical explanation of setup, storage, login, and claims. The server keeps this decrypted copy in the registry, with the credential, from the moment it validates it, and drops it when a renewal replaces the credential. Credentials issued before this version have no copy; the page says so until the next renewal or a new setup.

Security trade-off: the "prepared browser" factor is gone, so the passkey with user verification is the only factor. A synced passkey (for example in Microsoft Password Manager) can be used for emergency login on any device where it is available. If emergency access must stay on one device, save the passkey to Windows Hello or a security key; a policy that rejects backed-up passkeys would need the backup flags, which Identify does not yet record in the EC.
## Preferred authenticator

`EmergencyCredential.Authenticator` in the deployed `Web.config` `<appSettings>` tells the browser which kind of authenticator to use for emergency setup and emergency login, so supporting browsers can skip their authenticator chooser (this device, security key, or phone).

```xml
<add key="EmergencyCredential.Authenticator" value="platform" />
```

| Value | Setup (registration) | Emergency login |
|---|---|---|
| `any` (default) | No change; the browser offers every option. | No change. |
| `platform` | Requests this device, such as Windows Hello (`authenticatorAttachment: platform`, hint `client-device`). | Adds the hint `client-device`. |
| `security-key` | Requests a roaming USB, NFC, or BLE key (`authenticatorAttachment: cross-platform`, hint `security-key`). | Adds the hint `security-key`. |

A missing, empty, or unknown value behaves as `any`. Changing `Web.config` restarts the application.

How it works:

- The server passes the value to the emergency widgets on the home page, My Page, and the sign-in page. `EmergencyAssets/setup.js` and `EmergencyAssets/login-options.js` add the preference to the WebAuthn options just before the browser prompt. Identify's registration options and verification are unchanged (`poc-up`); the sample itself requests user verification at setup and requires it at emergency login.
- Login only adds a hint and never restricts transports; the named keys carry no transports. Forcing the `internal` transport made Windows Hello reject an existing passkey ("There was a problem signing in with your passkey").
- Independently of this value, setup requests a discoverable passkey (`residentKey: required`) with `userVerification: required`, because emergency login names no key and the passkey is its only factor. Security keys then use a resident-key slot and need a PIN.

What it does not change:

- The operating system's final prompt (touch, PIN, face, or fingerprint) always remains.
- The passkey provider's save confirmation at first setup remains and cannot be suppressed by the page: Edge shows "Create a passkey" for Microsoft Password Manager, and Windows shows "Save your passkey". Renewal reuses the key and shows no prompt.
- In the tested Windows 11 and Edge setup, `platform` did not reduce the number of dialogs. Use the value as a policy ("Windows Hello only" or "security keys only"), not as a prompt reduction.
- Choose the value before users prepare their browsers. A key registered as one kind may not be offered when the value names the other kind; affected users remove the key under **Manage keys** and prepare again.

Browser notes:

- A passkey saved to Edge's Microsoft Password Manager can sync to the user's other devices, and with no browser copy those devices can then use it for emergency login. To keep emergency access on one device, choose **Save another way** and Windows Hello in Edge's dialog, or use `security-key`.
- In an InPrivate window, a passkey saved to Microsoft Password Manager could not be used for emergency login in the same session. Prepare and test in a normal window, or save the passkey to Windows Hello.
- Browsers disable WebAuthn on pages with certificate errors (Edge: "WebAuthn is not supported on sites with TLS certificate errors"), whatever this value is.
## Authenticator policy compatibility

The current issuer and both clients use `poc-up`: presence is required, verification is preferred, and valid backup-eligible/backed-up passkeys are accepted. A backup-state bit without backup eligibility is rejected. Signature, origin/RP, one-use challenge, credential ownership, and counter checks remain enforced. Credentials labeled with the older `poc-uv-nonbackup` policy must be renewed to the current policy; they are not silently reinterpreted.


## Single-tenant configuration layout

Use `C:\ProgramData\SafewhereSamples\SamlEmergency` directly. Do not add a tenant subfolder. Keep these files outside the deployed website and source control:

```text
SamlEmergency/
  emergency-settings.json
  decryption-key.bin
  encryption-public.jwk.json
  issuer-signing-keys.json
  state/
  backups/
```

SAML uses a flat JSON object. Set `EmergencyCredential.SettingsFile` in deployed `Web.config` to the root `emergency-settings.json` and `EmergencyCredential.StateDirectory` to its `state` directory. The ASP.NET machine key stays in protected IIS/Web.config configuration; it is not an ASP.NET Core `protection` folder.

To migrate an existing installation, stop the client pool, back up its settings and protected state, and move the existing files rather than generating new keys. Update every absolute path in the settings and the deployed configuration, then restart the pool. Preserve directory ACLs and the existing machine/data-protection keys. Do not reset state, change the emergency audience, or run the key-generation script over the existing installation. Keep old files only in `backups`, not as a second live configuration. No Identify redeployment or issuer configuration change is needed for this directory move.

Regression check: prepare a key, clear the site's browser data, then open the sign-in page: the emergency card is hidden, but after a normal login My Page reports the account's key as set up elsewhere, and **Manage keys** can remove it. **Remove key** must report revocation to Identify and remove the row; a failed removal request must leave the marker untouched.


### Active keys on emergency login

Emergency login starts from the sign-in page (`login.ashx`). Its **Other login options** card appears only when this browser's marker lists a key that the client registry currently accepts as active and unexpired. The page asks a read-only status endpoint about each marked binding ID (`login-status`); it does not contact Identify, require normal login, or create a WebAuthn challenge, and it drops stale marker entries. **Emergency login** sends the marked binding IDs to `login-options`, which names those keys' passkeys in the challenge so the browser skips its passkey list, and sends the assertion to `login-complete`. The server finds the key by the passkey's credential ID, verifies the signature against the public key in its registry, checks the user handle and user verification and the counter, and starts the session from that key's newest active credential. The former `EmergencyLogin.aspx` page has been removed and its URL redirects to `login.ashx`. Revocations unknown to the offline client cannot be detected until synchronization.

Deploy the updated client assemblies and browser scripts together: the scripts use the new `login-status`, `login-options`, and `login-complete` request formats. No Identify redeployment or settings change is needed. The pages load their scripts with a file-version query string, so no hard refresh is needed after deployment.


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
