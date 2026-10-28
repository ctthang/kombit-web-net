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
   <add key="aspnet:UseTaskFriendlySynchronizationContext" value="true" />
   ```

   The state path must match the external JSON. The synchronization setting supports the async handler while keeping the current framework.

State uses `MachineKey.Protect` with an application-specific purpose. Private RSA files use machine-bound DPAPI and an audience-specific purpose. Restrict ACLs to the application identity and approved administrators. Use one worker; a second writer is rejected. Loss of state or a machine-key change requires deliberate recovery and new preparation. DPAPI files are not portable between machines.

## Use the feature

After a normal login, My Page shows an **Emergency access** card. **Set up emergency access** registers a security key or passkey (one WebAuthn prompt), stores the issued credential in IndexedDB, reads it back, and asks the server to activate it. There is no second key check: the server activates a pending credential only for the same account's normal login in the same browser, after the browser presents the stored copy, and possession of the authenticator is proven at the first emergency login. Emergency login is immediately available from the sign-in page. Use a security key or passkey with user presence; user verification is preferred and backup is allowed. Missing or old assertion evidence requires a new normal login; the preparation window is at most 24 hours.

Emergency login from the sign-in page, `EmergencyHome.aspx`, and local logout need no Identify request. A separate protected cookie and principal represent the emergency session. No SAML assertion or `Saml20Identity` is fabricated. `MyPage.aspx` redirects an emergency user locally before its SAML expressions run. Normal STS/service-action posts and SAML login/logout handlers reject emergency callers.

Renewal is automatic. When My Page loads after a normal login and half of an active credential's lifetime has passed (`renew_due` in the status response), the card renews it in the background, stores and reads back the replacement, activates it, and deletes the older browser copies. No prompt is shown. Renewal uses the unused normal-login record, so it happens at most once per login; a failed renewal is retried after the next login while the current credential stays valid. A setup or renewal that stopped after storage is finished on the next My Page load. Removing a key deletes its local registration, all associated credential versions, and sessions; failed issuer revocation reports remain queued. When My Page or the key management page loads key status, the sample synchronizes with Identify at most once every ten minutes: it refreshes trust, applies central revocations, and retries queued removals. Synchronization failures are ignored. There is no issuer request from emergency login.

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

## Remove a local key

**Remove key locally** deletes the binding and all associated credential versions from the client registry and this browser's IndexedDB, including renewed/replaced copies. It ends existing sessions for that binding and rejects replay of its previously issued credentials. The row disappears rather than becoming Blocked. An offline removal is immediately effective and survives restart; only the binding identifier needed to retry issuer revocation is retained in the internal queue. Other browsers may retain stale copies, but the server rejects them. This removes the application registration; it does not erase a hardware authenticator's internal key through WebAuthn.

The browser-only **Forget browser copy** action has been removed: it could strand an active issuer registration and prevent the same authenticator from being prepared again. If browser storage is lost, obtain a fresh normal login and open the preparation page. Registered keys without a browser copy are now shown as **Browser copy missing**, with **Remove key locally** available. Remove the old registration, let issuer revocation synchronize, and then prepare the authenticator again. Removal ends that binding's emergency sessions in every browser. If the client registry itself was lost (not only browser storage), an issuer administrator must revoke the orphaned binding. Clearing browser storage alone never unregisters a key.

The My Page card shows one state: **ready** with its expiry date and a **Manage keys** link; **Set up emergency access** while a fresh unused normal-login record is available; **Sign in again** when that record was used or lost (for example after an application pool restart); or a **browser copy missing** notice that links to key management. `Emergency.aspx` is now the key management page: it lists this account's keys in this browser, offers **Remove key locally**, and **Finish setup** for a stored pending credential without a key prompt. The `activate-options` and `activate-complete` API operations were replaced by `activate-stored`.

## Trace a request from start to finish

Emergency API responses include `X-Emergency-Reference`. The same ID appears in the existing error JSON's `reference_id` and the server's structured events. Search the log for that value to join `request_started`, any `emergency_failure`, and `request_completed`. Completion records include UTC time, normalized endpoint/recognized operation, HTTP status, elapsed milliseconds, and sanitized issuer-call summaries. Successful normal SAML capture emits `normal_login_captured` on the accepted-login callback's own reference.

These events use the existing log4net logger `Kombit.Samples.CH.WebsiteDemo.EmergencyFeature.EmergencyDiagnostics`. Enable Information or lower for that logger to see successful lifecycle events; Warning/Error still carry failures. The sample Web.config uses the `LogFileAppender` rolling-file appender with a 10 MB file limit and ten backups. Check its configured File path in the deployed configuration; for shared deployments, use a restricted writable directory outside the web root.

No request bodies, query values, cookies, tokens, credentials, API keys, or claim values are added to these lifecycle events. Existing sanitized failure records retain exception types/HResults and bounded stack method/line details. Logging failures do not interrupt the operation. A successful local removal can still have a failed upstream revocation summary because its retry is queued internally.

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

Regression check: prepare a key, simulate losing its browser storage, then perform a fresh normal login. The preparation page must show one **Browser copy missing** row per binding, including when it has several renewed versions. **Remove key locally** must report revocation to Identify and remove the row. Only then enroll the same authenticator again. A failed removal request must leave browser data untouched. The sign-in page must never offer browser-only deletion.


### Active keys on emergency login

Emergency login starts from the sign-in page (`login.ashx`). Its **Other login options** card appears only when this browser holds a key that the client registry currently accepts as active and unexpired. Pending, replaced, blocked, removed, expired, and invalid credentials are ignored, and only the newest stored credential per key is used. The page checks each stored credential through a read-only local status endpoint; it does not contact Identify, require normal login, or create a WebAuthn challenge. **Emergency login** runs the key check in place and opens `EmergencyHome.aspx`; with several active keys, the card shows one button per key. The former `EmergencyLogin.aspx` page has been removed and its URL redirects to `login.ashx`. Preparation still shows management and pending-confirmation controls. Login rechecks eligibility when the key is used. Revocations unknown to the offline client cannot be detected until synchronization.

Deploy the updated client assemblies and browser script together: the script now requires the local login-status endpoint. No Identify redeployment or settings change is needed. The sign-in page loads the site stylesheet and its script with a file-version query string, so no hard refresh is needed after deployment.


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
