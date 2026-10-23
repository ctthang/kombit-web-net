# SAML emergency access PoC

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
6. Supply a random backend secret of at least 32 characters through the named environment variable for the IIS worker. The key must match Identify's emergency client. Keep all values outside source, URLs, and logs.
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

Open `Emergency.aspx` after normal login. Complete registration, IndexedDB storage/read-back, and the second key check. Only then is the browser ready, and emergency login is immediately available for it. Use a key with user verification and no passkey backup. Missing or old assertion evidence requires a new normal login; the preparation window is ten minutes.

`EmergencyLogin.aspx`, `EmergencyHome.aspx`, and local logout need no Identify request. A separate protected cookie and principal represent the emergency session. No SAML assertion or `Saml20Identity` is fabricated. `MyPage.aspx` redirects an emergency user locally before its SAML expressions run. Normal STS/service-action posts and SAML login/logout handlers reject emergency callers.

Renewal requires a newer normal login. The replacement stays pending until storage and possession succeed. Removing a key blocks it locally first; failed issuer reports remain queued. When the preparation page loads its key status, the sample synchronizes with Identify at most once every ten minutes: it refreshes trust, applies central revocations, and retries queued removals. Synchronization failures are ignored. There is no issuer request from emergency login.

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

Token metadata, raw tokens, and emergency-reserved claims remain excluded. Clients continue to exclude normal assurance claims such as `acr`, `amr`, `auth_time`, and LoA claims. Roles, SAML privileges, and scopes are not restricted. `emergency=true`, `local_assurance=emergency-possession`, and local session expiry remain authoritative. A `name` or standard name claim replaces the generic Prepared user display. Original claim names are preserved rather than automatically applying OIDC inbound claim-name mapping.

Deploy the updated issuer and sample, remove `PreserveNormalClaims`, `ClaimTypes`, `Roles`, `Privileges`, and `PrivilegeScopes` from the sample's external settings, and restart their application pools. Then obtain a fresh normal login and renew or prepare the emergency credential. Existing credentials contain the old snapshot and cannot acquire claims retroactively. Missing attributes that were never present in the assertion cannot be invented by this option.
