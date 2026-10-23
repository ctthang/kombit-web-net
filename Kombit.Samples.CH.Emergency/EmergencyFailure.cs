using System;

namespace Kombit.Samples.CH.Emergency
{
    public sealed class EmergencyFailure : Exception
    {
        public int StatusCode { get; private set; }
        public string ErrorCode { get; private set; }

        public EmergencyFailure(int status, string code)
            : this(status, code, null) { }

        public EmergencyFailure(int status, string code, Exception innerException)
            : base(Describe(code), innerException)
        {
            StatusCode = status;
            ErrorCode = code;
        }

        private static string Describe(string code)
        {
            switch (code)
            {
                case "not_found":
                    return "The emergency feature or requested operation is unavailable. Check that emergency access is enabled and the requested address and operation are correct.";
                case "https_origin_required":
                    return "The request did not use HTTPS at the configured emergency origin. Open the configured HTTPS address; administrators should check the origin setting and reverse-proxy HTTPS configuration.";
                case "csrf_or_origin_rejected":
                    return "The request origin, browser cookie, or anti-forgery token did not match the current session. Reload the page at the configured HTTPS address, allow cookies, and retry from the same browser tab.";
                case "normal_login_required":
                    return "This action requires a normal SAML login, not an emergency session. Use the normal login flow and then return to the emergency preparation page.";
                case "new_normal_login_required":
                    return "The normal-login record is missing, expired, already reserved for preparation, or belongs to a different browser. Use Get a new normal login and restart preparation in the same browser.";
                case "login_not_eligible":
                    return "The normal SAML login is not eligible for emergency preparation: its issuer, subject, assertion identifier, or validity period failed validation. Check the configured normal SAML issuer and identity-provider claims, then sign in again.";
                case "login_capacity":
                    return "The server has reached its limit of tracked normal logins. Retry after old login records expire; administrators should investigate unusually high login volume.";
                case "registration_capacity":
                    return "The server has reached its limit of pending key registrations. Complete or cancel pending registrations, or wait for them to expire before retrying.";
                case "registration_expired":
                    return "The pending key registration expired or no longer matches this browser and login. Obtain a new normal login and restart key registration in the same browser.";
                case "registration_not_found":
                    return "The pending registration could not be found for this login and browser. Reload the preparation page and restart registration with a new normal login.";
                case "issuer_response_rejected":
                    return "The issuer response did not match the expected format or registration data, or exceeded the response size limit. Administrators should check issuer compatibility and the issuer-call diagnostics before retrying.";
                case "issuer_request_failed_new_login_may_be_required":
                    return "The emergency issuer returned an unsuccessful HTTP status. Check the issuer-call diagnostics for the endpoint and actual status; administrators should verify issuer availability and backend client authorization. A new normal login may be needed before retrying.";
                case "issued_credential_mismatch":
                    return "The issued emergency credential does not match the expected account, source assertion, credential identifier, expiry, profile version, key binding, or authenticator. Check the issuer configuration and restart preparation with the correct account and key.";
                case "local_policy_denied":
                    return "The local emergency registry has reached its limit of 10,000 credential entries. Administrators should review registry growth and credential retention before retrying preparation; a different login will not bypass this limit.";
                case "key_conflict":
                    return "The expected key binding is missing, the registry has reached 10,000 keys, or this authenticator is already registered under another binding. Administrators should review the existing binding and registry capacity before registration is retried.";
                case "key_mismatch":
                    return "The existing key binding is blocked or its account, authenticator, public key, or user handle differs from the issued credential. Administrators should review the binding and revocation status; use a credential for an eligible matching key.";
                case "credential_already_registered":
                    return "This emergency credential has already been registered locally. Use the existing registration or renew it rather than activating the same credential again.";
                case "proof_capacity":
                    return "The server has reached its limit of pending key checks. Wait for pending checks to complete or expire, then start a new check.";
                case "credential_not_registered":
                    return "The supplied credential's digest differs from the credential stored under the same identifier in the local registry. Use the exact credential received during preparation; administrators should investigate inconsistent issuer data if the mismatch persists.";
                case "account_mismatch":
                    return "The emergency credential belongs to a different account from the current normal login. Sign in with the matching account or use that account's credential.";
                case "proof_unavailable":
                    return "The key-check transaction is missing, already consumed, or does not match the browser or requested action. Start a new key check in the same browser and submit it only once.";
                case "proof_expired":
                    return "The key-check transaction expired before completion. Start a new check and respond promptly to the security-key or passkey prompt.";
                case "state_changed_retry":
                    return "The local emergency state changed while the key check was in progress. Reload the page and start a new check against the current state.";
                case "replacement_superseded":
                    return "This credential replacement is no longer current because another replacement changed the registration. Use the latest issued credential or restart renewal.";
                case "session_capacity":
                    return "The server has reached its limit of emergency sessions. End unused sessions or wait for sessions to expire before retrying.";
                case "credential_unavailable":
                    return "The credential is missing, expired, not in the required state, or its key is missing or blocked. Check readiness using normal login and prepare or renew a valid credential; administrators should review revocations and key status.";
                case "key_not_found":
                    return "The requested key registration does not exist for the current account. Reload the key list and select a key registered to the signed-in account.";
                case "key_blocked":
                    return "The registered key is blocked and cannot be used for this operation. Use another eligible key; administrators should review the key's revocation status.";
                case "sync_changed":
                    return "Another synchronization changed the local revocation state during this request. Retry synchronization against the latest state.";
                case "revocation_gap":
                    return "The issuer revocation feed contains a sequence gap, so local revocation state cannot be trusted as current. Administrators should check feed continuity and restore synchronization before emergency access is used.";
                case "sync_more_pages_required":
                    return "The revocation feed still has more pages after the per-request synchronization limit. Run synchronization again until the local state is current.";
                case "rate_limited":
                    return "Too many emergency requests were received from this source, or the rate-limit tracker is full. Wait at least 60 seconds before retrying; administrators should investigate sustained excessive traffic.";
                case "credential_rejected":
                    return "The emergency credential failed format, cryptographic, issuer, audience, time-validity, or required-claim validation. Use an intact, current credential issued for this application; administrators should check trust settings and server time.";
                case "state_unavailable":
                    return "The protected local emergency-state file could not be read or saved. Administrators should check storage availability, application-pool file permissions, and the state-protection configuration. Do not delete the state file to bypass this error.";
                case "registry_capacity":
                    return "The local emergency registry has reached its storage limit. Administrators should review registry growth and expired records before retrying.";
                case "key_proof_rejected":
                    return "The WebAuthn security-key proof failed validation. Use the registered key at the configured HTTPS origin; administrators should check the relying-party ID, origin, user-verification requirements, and authenticator compatibility.";
                case "invalid_request":
                    return "The request contains malformed, missing, unexpected, or invalid data. Reload the page and retry using the supplied controls; API clients must send the expected JSON fields and value formats.";
                case "method_not_allowed":
                    return "The emergency API accepts POST requests only. Submit the action through the emergency page or send a POST request with the required anti-forgery header.";
                case "request_too_large":
                    return "The emergency request exceeds the allowed size. Submit only the expected credential and request fields; do not include extra files or data.";
                case "emergency_unavailable":
                    return "The emergency service could not initialize or complete the operation. Administrators should check server logs, emergency configuration, signing and decryption certificates, backend secret availability, issuer connectivity, and local state storage before retrying.";
                case "normal_protocol_action_unavailable":
                    return "Normal SAML token actions are unavailable during an emergency session. End the emergency session and sign in normally before using this action.";
                default:
                    return "The emergency operation could not be completed. Contact an administrator with the error code, HTTP status, time, and action attempted so the server logs can be checked.";
            }
        }
    }
}
