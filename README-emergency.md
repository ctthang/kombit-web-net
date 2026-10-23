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
   <add key="EmergencyCredential.SettingsFile" value="C:\ProgramData\SafewhereSamples\SamlEmergency\settings.json" />
   <add key="EmergencyCredential.StateDirectory" value="C:\ProgramData\SafewhereSamples\SamlEmergency\state" />
   <add key="aspnet:UseTaskFriendlySynchronizationContext" value="true" />
   ```

   The state path must match the external JSON. The synchronization setting supports the async handler while keeping the current framework.

State uses `MachineKey.Protect` with an application-specific purpose. Private RSA files use machine-bound DPAPI and an audience-specific purpose. Restrict ACLs to the application identity and approved administrators. Use one worker; a second writer is rejected. Loss of state or a machine-key change requires deliberate recovery and new preparation. DPAPI files are not portable between machines.

## Use the feature

Open `Emergency.aspx` after normal login. Complete registration, IndexedDB storage/read-back, and the second key check. Only then is the browser ready, and emergency login is immediately available for it. Use a security key or passkey with user presence; user verification is preferred and backup is allowed. Missing or old assertion evidence requires a new normal login; the preparation window is at most 24 hours.

`EmergencyLogin.aspx`, `EmergencyHome.aspx`, and local logout need no Identify request. A separate protected cookie and principal represent the emergency session. No SAML assertion or `Saml20Identity` is fabricated. `MyPage.aspx` redirects an emergency user locally before its SAML expressions run. Normal STS/service-action posts and SAML login/logout handlers reject emergency callers.

Renewal requires a newer normal login. The replacement stays pending until storage and possession succeed. Removing a key deletes its local registration, all associated credential versions, and sessions; failed issuer revocation reports remain queued. When the preparation page loads its key status, the sample synchronizes with Identify at most once every ten minutes: it refreshes trust, applies central revocations, and retries queued removals. Synchronization failures are ignored. There is no issuer request from emergency login.

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

If removal succeeds on the server but browser cleanup fails or the response is lost, open the emergency-login page and use **Forget browser copy** for that key. This clears all its versions from this browser without contacting the server; it does not revoke an otherwise valid server registration.

The preparation page shows exactly one next action: **Prepare this browser** while a fresh unused normal-login record is eligible, or **Get a new normal login for preparation or renewal** otherwise. Starting preparation/renewal consumes that record, so the page switches back to the login action. Pending credentials can still be confirmed using their own key-check control.

## Trace a request from start to finish

Emergency API responses include `X-Emergency-Reference`. The same ID appears in the existing error JSON's `reference_id` and the server's structured events. Search the log for that value to join `request_started`, any `emergency_failure`, and `request_completed`. Completion records include UTC time, normalized endpoint/recognized operation, HTTP status, elapsed milliseconds, and sanitized issuer-call summaries. Successful normal SAML capture emits `normal_login_captured` on the accepted-login callback's own reference.

These events use the existing log4net logger `Kombit.Samples.CH.WebsiteDemo.EmergencyFeature.EmergencyDiagnostics`. Enable Information or lower for that logger to see successful lifecycle events; Warning/Error still carry failures. The sample Web.config uses the `LogFileAppender` rolling-file appender with a 10 MB file limit and ten backups. Check its configured File path in the deployed configuration; for shared deployments, use a restricted writable directory outside the web root.

No request bodies, query values, cookies, tokens, credentials, API keys, or claim values are added to these lifecycle events. Existing sanitized failure records retain exception types/HResults and bounded stack method/line details. Logging failures do not interrupt the operation. A successful local removal can still have a failed upstream revocation summary because its retry is queued internally.

## Authenticator policy compatibility

The current issuer and both clients use `poc-up`: presence is required, verification is preferred, and valid backup-eligible/backed-up passkeys are accepted. A backup-state bit without backup eligibility is rejected. Signature, origin/RP, one-use challenge, credential ownership, and counter checks remain enforced. Credentials labeled with the older `poc-uv-nonbackup` policy must be renewed to the current policy; they are not silently reinterpreted.
