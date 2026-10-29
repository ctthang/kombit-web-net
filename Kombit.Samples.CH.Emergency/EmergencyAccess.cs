using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Kombit.Samples.CH.Emergency
{
    public sealed class EmergencyAccess : IDisposable
    {
        public const string AuthenticationType = "SamlSampleEmergency";
        private readonly EmergencySettings settings;
        private readonly EmergencyStateFile state;
        private readonly CredentialReader reader;
        private readonly WebAuthnChecks webauthn;
        private readonly IssuerConnection issuer;
        private readonly Func<DateTimeOffset> utcNow;
        private readonly Dictionary<string, AcceptedSamlLogin> normalLogins =
            new Dictionary<string, AcceptedSamlLogin>();
        private readonly Dictionary<string, RegistrationRelay> registrations =
            new Dictionary<string, RegistrationRelay>();
        private readonly Dictionary<string, KeyProof> proofs = new Dictionary<string, KeyProof>();
        private readonly Dictionary<string, Queue<long>> requests =
            new Dictionary<string, Queue<long>>();
        private long lastSynchronization;

        public EmergencyAccess(
            EmergencySettings configuration,
            EmergencyStateFile registry,
            CredentialReader credentialReader,
            WebAuthnChecks assertionChecks,
            IssuerConnection backend,
            Func<DateTimeOffset> clock
        )
        {
            settings = configuration;
            state = registry;
            reader = credentialReader;
            webauthn = assertionChecks;
            issuer = backend;
            utcNow = clock;
        }

        private long Now
        {
            get { return utcNow().ToUnixTimeSeconds(); }
        }

        public string RecordLogin(AcceptedSamlLogin login)
        {
            if (
                login == null
                || login.Issuer != settings.NormalSamlIssuer
                || string.IsNullOrEmpty(login.Subject)
                || login.Subject.Length > 1024
                || string.IsNullOrEmpty(login.AssertionId)
                || login.AssertionId.Length > 1024
                || login.RecordExpires <= Now
            )
            {
                throw new EmergencyFailure(403, "login_not_eligible");
            }
            lock (state.SyncRoot)
            {
                Prune();
                if (normalLogins.Count >= 2000)
                {
                    throw new EmergencyFailure(503, "login_capacity");
                }
                login.Handle = Wire.RandomId();
                login.RecordExpires = Math.Min(login.RecordExpires, Now + 86400);
                login.SessionExpires = Now + 172800;
                normalLogins.Add(login.Handle, login);
                return login.Handle;
            }
        }

        private AcceptedSamlLogin Login(string handle, string browser, bool reserve)
        {
            AcceptedSamlLogin login;
            if (
                handle == null
                || !normalLogins.TryGetValue(handle, out login)
                || login.Browser != browser
                || login.SessionExpires <= Now
                || (reserve && (login.Reserved || login.RecordExpires <= Now))
            )
            {
                throw new EmergencyFailure(409, "new_normal_login_required");
            }
            if (reserve)
            {
                login.Reserved = true;
            }
            return login;
        }

        public bool CanPrepare(string handle, string browser)
        {
            lock (state.SyncRoot)
            {
                try
                {
                    AcceptedSamlLogin login = Login(handle, browser, false);
                    return !login.Reserved && login.RecordExpires > Now;
                }
                catch (EmergencyFailure)
                {
                    return false;
                }
            }
        }

        public async Task<JObject> BeginRegistration(
            string handle,
            string browser,
            CancellationToken cancellation
        )
        {
            AcceptedSamlLogin login;
            lock (state.SyncRoot)
            {
                Prune();
                if (registrations.Count >= 1000)
                {
                    throw new EmergencyFailure(503, "registration_capacity");
                }
                login = Login(handle, browser, true);
            }
            JObject result = await issuer
                .Request(
                    HttpMethod.Post,
                    "emergency/enrollments",
                    new JObject { ["normal_token_reference"] = login.Reference() },
                    cancellation
                )
                .ConfigureAwait(false);
            string id = Wire.String(result, "enrollment_id", 128);
            if (Wire.String((JObject)result["publicKey"]["rp"], "id") != settings.RpId)
            {
                throw new EmergencyFailure(502, "issuer_response_rejected");
            }
            lock (state.SyncRoot)
            {
                registrations.Add(
                    id,
                    new RegistrationRelay
                    {
                        Id = id,
                        Login = login,
                        Deadline = Math.Min(login.RecordExpires, Wire.Number(result, "expires_at")),
                    }
                );
            }
            return result;
        }

        public async Task<JObject> FinishRegistration(
            string handle,
            string browser,
            string enrollment,
            JObject credential,
            CancellationToken cancellation
        )
        {
            RegistrationRelay relay;
            lock (state.SyncRoot)
            {
                AcceptedSamlLogin login = Login(handle, browser, false);
                if (
                    !registrations.TryGetValue(enrollment, out relay)
                    || relay.Login.Handle != login.Handle
                    || relay.Deadline <= Now
                )
                {
                    throw new EmergencyFailure(410, "registration_expired");
                }
                registrations.Remove(enrollment);
            }
            string authenticator = Wire.String(credential, "rawId", 2048);
            JObject issued = await issuer
                .Request(
                    HttpMethod.Post,
                    "emergency/enrollments/" + Uri.EscapeDataString(enrollment) + "/complete",
                    new JObject { ["credential"] = credential },
                    cancellation
                )
                .ConfigureAwait(false);
            RegisterPending(issued, relay.Login, null, authenticator);
            return issued;
        }

        public async Task CancelRegistration(
            string handle,
            string browser,
            string enrollment,
            CancellationToken cancellation
        )
        {
            lock (state.SyncRoot)
            {
                RegistrationRelay pending;
                if (
                    !registrations.TryGetValue(enrollment, out pending)
                    || pending.Login.Handle != Login(handle, browser, false).Handle
                )
                {
                    throw new EmergencyFailure(404, "registration_not_found");
                }
                registrations.Remove(enrollment);
            }
            await issuer
                .Request(
                    HttpMethod.Delete,
                    "emergency/enrollments/" + Uri.EscapeDataString(enrollment),
                    null,
                    cancellation
                )
                .ConfigureAwait(false);
        }

        public async Task<JObject> Renew(
            string handle,
            string browser,
            string binding,
            CancellationToken cancellation
        )
        {
            AcceptedSamlLogin login;
            lock (state.SyncRoot)
            {
                login = Login(handle, browser, false);
                state.Inspect(data => OwnedKey(data, binding, login.AccountKey));
                Login(handle, browser, true);
            }
            JObject issued = await issuer
                .Request(
                    HttpMethod.Post,
                    "emergency/renewals",
                    new JObject
                    {
                        ["normal_token_reference"] = login.Reference(),
                        ["binding_id"] = binding,
                    },
                    cancellation
                )
                .ConfigureAwait(false);
            RegisterPending(issued, login, binding, null);
            return issued;
        }

        private void RegisterPending(
            JObject issued,
            AcceptedSamlLogin login,
            string expectedBinding,
            string authenticator
        )
        {
            string compact = Wire.String(issued, "emergency_credential", 65536),
                binding = Wire.String(issued, "binding_id", 128);
            JObject credential = reader.Read(
                compact,
                state.Inspect(data => (string)data["trust"]),
                utcNow()
            );
            if (
                (string)credential["account"] != login.AccountKey
                || (string)credential["source_reference"] != login.AssertionId
                || (string)credential["id"] != Wire.String(issued, "ec_id", 128)
                || (long)credential["expires"] != Wire.Number(issued, "expires_at")
                || Wire.String(issued, "profile_version") != CredentialReader.Profile
                || (expectedBinding != null && binding != expectedBinding)
                || (authenticator != null && (string)credential["authenticator"] != authenticator)
            )
            {
                throw new EmergencyFailure(400, "issued_credential_mismatch");
            }
            state.Change(data =>
            {
                JObject keys = (JObject)data["keys"],
                    entries = (JObject)data["credentials"];
                if (entries.Count >= 10000)
                {
                    throw new EmergencyFailure(403, "local_policy_denied");
                }
                JObject key = keys[binding] as JObject;
                if (key == null)
                {
                    if (
                        expectedBinding != null
                        || keys.Count >= 10000
                        || keys.Properties()
                            .Any(item =>
                                (string)item.Value["authenticator"]
                                == (string)credential["authenticator"]
                            )
                    )
                    {
                        throw new EmergencyFailure(409, "key_conflict");
                    }
                    keys[binding] = new JObject
                    {
                        ["account"] = login.AccountKey,
                        ["authenticator"] = credential["authenticator"],
                        ["handle"] = credential["handle"],
                        ["cose"] = credential["cose"],
                        ["counter"] = credential["initial_counter"],
                        ["revision"] = 0L,
                        ["active_issued"] = 0L,
                        ["blocked"] = false,
                    };
                }
                else if (
                    (string)key["account"] != login.AccountKey
                    || (string)key["authenticator"] != (string)credential["authenticator"]
                    || (string)key["cose"] != (string)credential["cose"]
                    || (string)key["handle"] != (string)credential["handle"]
                    || (bool)key["blocked"]
                )
                {
                    throw new EmergencyFailure(403, "key_mismatch");
                }
                if (entries[(string)credential["id"]] != null)
                {
                    throw new EmergencyFailure(409, "credential_already_registered");
                }
                credential["binding"] = binding;
                credential["status"] = "pending";
                entries[(string)credential["id"]] = credential;
                Event(data, "credential_pending");
                return true;
            });
        }

        // Read-only local eligibility; safe to use while Identify is unavailable.
        public bool IsActiveForLogin(string compact)
        {
            try
            {
                JObject verified = reader.Read(compact, state.Inspect(data => (string)data["trust"]), utcNow());
                lock (state.SyncRoot)
                {
                    return state.Inspect(data => (string)Eligible(data, (string)verified["id"], "active")["digest"] == (string)verified["digest"]);
                }
            }
            catch (EmergencyFailure) { return false; }
        }

        /// <summary>
        ///     Activates a pending credential once the browser has stored it and read it back, without
        ///     a second WebAuthn ceremony. The caller must hold the normal login of the same account in
        ///     the same browser; possession of the authenticator is proven at emergency login.
        /// </summary>
        public JObject ActivateStored(string browser, string compact, string normalHandle)
        {
            JObject verified = reader.Read(
                compact,
                state.Inspect(data => (string)data["trust"]),
                utcNow()
            );
            lock (state.SyncRoot)
            {
                AcceptedSamlLogin login = Login(normalHandle, browser, false);
                return state.Change(data =>
                {
                    JObject entry = Eligible(data, (string)verified["id"], "pending");
                    if ((string)entry["digest"] != (string)verified["digest"])
                    {
                        throw new EmergencyFailure(403, "credential_not_registered");
                    }
                    if ((string)entry["account"] != login.AccountKey)
                    {
                        throw new EmergencyFailure(403, "account_mismatch");
                    }
                    JObject key = (JObject)data["keys"][(string)entry["binding"]];
                    if ((long)entry["issued"] <= (long)key["active_issued"])
                    {
                        throw new EmergencyFailure(409, "replacement_superseded");
                    }
                    foreach (
                        JObject old in ((JObject)data["credentials"])
                            .Properties()
                            .Select(item => (JObject)item.Value)
                            .Where(item =>
                                (string)item["binding"] == (string)entry["binding"]
                                && (string)item["status"] == "active"
                            )
                    )
                    {
                        old["status"] = "replaced";
                        old.Remove("raw");
                    }
                    entry["status"] = "active";
                    key["active_issued"] = entry["issued"];
                    key["revision"] = (long)key["revision"] + 1;
                    Event(data, "credential_activated");
                    return new JObject { ["ready"] = true };
                });
            }
        }

        public JObject StartProof(string browser, string compact, bool login, string normalHandle)
        {
            JObject verified = reader.Read(
                compact,
                state.Inspect(data => (string)data["trust"]),
                utcNow()
            );
            lock (state.SyncRoot)
            {
                Prune();
                if (proofs.Count >= 1000)
                {
                    throw new EmergencyFailure(503, "proof_capacity");
                }
                return state.Inspect(data =>
                {
                    JObject entry = Eligible(
                        data,
                        (string)verified["id"],
                        login ? "active" : "pending"
                    );
                    if ((string)entry["digest"] != (string)verified["digest"])
                    {
                        throw new EmergencyFailure(403, "credential_not_registered");
                    }
                    if (
                        !login
                        && Login(normalHandle, browser, false).AccountKey
                            != (string)entry["account"]
                    )
                    {
                        throw new EmergencyFailure(403, "account_mismatch");
                    }
                    JObject key = (JObject)data["keys"][(string)entry["binding"]];
                    KeyProof proof = new KeyProof
                    {
                        Id = Wire.RandomId(),
                        Browser = browser,
                        Purpose = login ? "login" : "activate",
                        Credential = (string)entry["id"],
                        Digest = (string)entry["digest"],
                        Binding = (string)entry["binding"],
                        Authenticator = (string)key["authenticator"],
                        Handle = (string)key["handle"],
                        Cose = (string)key["cose"],
                        Counter = (uint)key["counter"],
                        Revision = (long)key["revision"],
                        Deadline = Math.Min(Now + 120, (long)entry["expires"]),
                    };
                    proof.Options = webauthn.Create(proof.Authenticator);
                    proofs.Add(proof.Id, proof);
                    return new JObject
                    {
                        ["transaction_id"] = proof.Id,
                        ["expires_at"] = proof.Deadline,
                        ["publicKey"] = JObject.Parse(proof.Options.ToJson()),
                    };
                });
            }
        }

        public async Task<JObject> CompleteProof(
            string browser,
            string id,
            bool login,
            JObject response,
            string normalHandle
        )
        {
            KeyProof proof;
            lock (state.SyncRoot)
            {
                if (
                    !proofs.TryGetValue(id, out proof)
                    || proof.Browser != browser
                    || proof.Purpose != (login ? "login" : "activate")
                )
                {
                    throw new EmergencyFailure(410, "proof_unavailable");
                }
                proofs.Remove(id);
                if (proof.Deadline <= Now)
                {
                    throw new EmergencyFailure(410, "proof_expired");
                }
            }
            uint count = await webauthn.Verify(response, proof).ConfigureAwait(false);
            lock (state.SyncRoot)
            {
                return state.Change(data =>
                {
                    JObject entry = Eligible(data, proof.Credential, login ? "active" : "pending"),
                        key = (JObject)data["keys"][proof.Binding];
                    if (
                        proof.Deadline <= Now
                        || (long)key["revision"] != proof.Revision
                        || (uint)key["counter"] != proof.Counter
                        || (string)entry["digest"] != proof.Digest
                    )
                    {
                        throw new EmergencyFailure(409, "state_changed_retry");
                    }
                    if (!login)
                    {
                        if (
                            Login(normalHandle, browser, false).AccountKey
                                != (string)entry["account"]
                            || (long)entry["issued"] <= (long)key["active_issued"]
                        )
                        {
                            throw new EmergencyFailure(409, "replacement_superseded");
                        }
                        foreach (
                            JObject old in ((JObject)data["credentials"])
                                .Properties()
                                .Select(item => (JObject)item.Value)
                                .Where(item =>
                                    (string)item["binding"] == proof.Binding
                                    && (string)item["status"] == "active"
                                )
                        )
                        {
                            old["status"] = "replaced";
                            old.Remove("raw");
                        }
                        entry["status"] = "active";
                        key["active_issued"] = entry["issued"];
                        key["counter"] = (long)count;
                        key["revision"] = proof.Revision + 1;
                        Event(data, "credential_activated");
                        return new JObject { ["ready"] = true };
                    }
                    return CreateSession(data, proof, entry, key, count, browser);
                });
            }
        }

        private JObject CreateSession(
            JObject data,
            KeyProof proof,
            JObject entry,
            JObject key,
            uint count,
            string browser
        )
        {
            JObject sessions = (JObject)data["sessions"];
            foreach (
                JProperty expired in sessions
                    .Properties()
                    .Where(item => (long)item.Value["expires"] <= Now)
                    .ToArray()
            )
            {
                expired.Remove();
            }
            if (sessions.Count >= 2000)
            {
                throw new EmergencyFailure(503, "session_capacity");
            }
            long end = Math.Min(Now + settings.SessionMinutes * 60, (long)entry["expires"]);
            string session = Wire.RandomId();
            sessions[session] = new JObject
            {
                ["credential"] = proof.Credential,
                ["browser"] = browser,
                ["expires"] = end,
            };
            key["counter"] = (long)count;
            key["revision"] = proof.Revision + 1;
            Event(data, "session_created");
            return new JObject { ["session"] = session, ["expires"] = end };
        }

        /// <summary>
        ///     Starts usernameless emergency login: a one-time challenge that names no key. The browser
        ///     holds no emergency credential; the registered passkey identifies the key.
        /// </summary>
        /// <param name="bindings">
        ///     Optional binding IDs from the browser's non-secret marker. Active ones are named in the
        ///     challenge so the browser goes straight to that passkey; unknown, blocked, or inactive
        ///     ones are ignored. Without any, the challenge names no key.
        /// </param>
        public JObject StartDiscoverableLogin(string browser, IEnumerable<string> bindings = null)
        {
            lock (state.SyncRoot)
            {
                Prune();
                if (proofs.Count >= 1000)
                {
                    throw new EmergencyFailure(503, "proof_capacity");
                }
                List<string> named = (bindings ?? Enumerable.Empty<string>())
                    .Where(IsBindingActiveForLogin)
                    .Select(binding => state.Inspect(data => (string)data["keys"][binding]["authenticator"]))
                    .Distinct()
                    .ToList();
                KeyProof proof = new KeyProof
                {
                    Id = Wire.RandomId(),
                    Browser = browser,
                    Purpose = "discoverable",
                    Deadline = Now + 120,
                    // An authenticator may omit the user handle when the challenge names its key.
                    RequireUserHandle = named.Count == 0,
                    Options = webauthn.CreateDiscoverable(named),
                };
                proofs.Add(proof.Id, proof);
                return new JObject
                {
                    ["transaction_id"] = proof.Id,
                    ["expires_at"] = proof.Deadline,
                    ["publicKey"] = JObject.Parse(proof.Options.ToJson()),
                };
            }
        }

        /// <summary>
        ///     Completes usernameless emergency login. The passkey's credential ID selects the
        ///     registered key; its newest active credential supplies the session's claims. The
        ///     signature, user handle, user verification, and counter are checked against the key
        ///     stored in the registry. No Identify request is made.
        /// </summary>
        public async Task<JObject> CompleteDiscoverableLogin(string browser, string id, JObject response)
        {
            KeyProof proof;
            lock (state.SyncRoot)
            {
                if (
                    !proofs.TryGetValue(id, out proof)
                    || proof.Browser != browser
                    || proof.Purpose != "discoverable"
                )
                {
                    throw new EmergencyFailure(410, "proof_unavailable");
                }
                proofs.Remove(id);
                if (proof.Deadline <= Now)
                {
                    throw new EmergencyFailure(410, "proof_expired");
                }
            }
            string authenticator = Wire.String(response, "rawId", 2048);
            lock (state.SyncRoot)
            {
                state.Inspect(data =>
                {
                    JProperty match = ((JObject)data["keys"])
                        .Properties()
                        .FirstOrDefault(item =>
                            (string)item.Value["authenticator"] == authenticator
                            && !(bool)item.Value["blocked"]
                        );
                    JObject entry = match == null
                        ? null
                        : ((JObject)data["credentials"])
                            .Properties()
                            .Select(item => (JObject)item.Value)
                            .Where(item =>
                                (string)item["binding"] == match.Name
                                && (string)item["status"] == "active"
                                && (long)item["expires"] > Now
                            )
                            .OrderByDescending(item => (long)item["issued"])
                            .FirstOrDefault();
                    if (entry == null)
                    {
                        throw new EmergencyFailure(403, "credential_unavailable");
                    }
                    JObject key = (JObject)match.Value;
                    proof.Credential = (string)entry["id"];
                    proof.Digest = (string)entry["digest"];
                    proof.Binding = match.Name;
                    proof.Authenticator = (string)key["authenticator"];
                    proof.Handle = (string)key["handle"];
                    proof.Cose = (string)key["cose"];
                    proof.Counter = (uint)key["counter"];
                    proof.Revision = (long)key["revision"];
                    proof.Deadline = Math.Min(proof.Deadline, (long)entry["expires"]);
                    return true;
                });
            }
            uint count = await webauthn.Verify(response, proof).ConfigureAwait(false);
            lock (state.SyncRoot)
            {
                return state.Change(data =>
                {
                    JObject entry = Eligible(data, proof.Credential, "active"),
                        key = (JObject)data["keys"][proof.Binding];
                    if (
                        proof.Deadline <= Now
                        || (long)key["revision"] != proof.Revision
                        || (uint)key["counter"] != proof.Counter
                        || (string)entry["digest"] != proof.Digest
                    )
                    {
                        throw new EmergencyFailure(409, "state_changed_retry");
                    }
                    return CreateSession(data, proof, entry, key, count, browser);
                });
            }
        }

        /// <summary>
        ///     Read-only check for the sign-in page: true when the key with this binding ID exists,
        ///     is not blocked, and has an active, unexpired credential. Binding IDs are random and
        ///     reveal nothing else; no Identify request is made.
        /// </summary>
        public bool IsBindingActiveForLogin(string binding)
        {
            if (string.IsNullOrEmpty(binding) || binding.Length > 128)
            {
                return false;
            }
            lock (state.SyncRoot)
            {
                return state.Inspect(data =>
                {
                    JObject key = data["keys"][binding] as JObject;
                    return key != null
                        && !(bool)key["blocked"]
                        && ((JObject)data["credentials"])
                            .Properties()
                            .Select(item => (JObject)item.Value)
                            .Any(item =>
                                (string)item["binding"] == binding
                                && (string)item["status"] == "active"
                                && (long)item["expires"] > Now
                            );
                });
            }
        }

        private JObject Eligible(JObject data, string id, string expected)
        {
            JObject entry = data["credentials"][id] as JObject;
            if (
                entry == null
                || (string)entry["status"] != expected
                || (long)entry["expires"] <= Now
            )
            {
                throw new EmergencyFailure(403, "credential_unavailable");
            }
            JObject key = data["keys"][(string)entry["binding"]] as JObject;
            if (key == null || (bool)key["blocked"])
            {
                throw new EmergencyFailure(403, "credential_unavailable");
            }
            return entry;
        }

        private static JObject OwnedKey(JObject data, string id, string account)
        {
            JObject key = data["keys"][id] as JObject;
            if (key == null || (string)key["account"] != account)
            {
                throw new EmergencyFailure(404, "key_not_found");
            }
            if ((bool)key["blocked"])
            {
                throw new EmergencyFailure(403, "key_blocked");
            }
            return key;
        }

        /// <summary>
        ///     The registry record behind an emergency session, for display on the emergency home
        ///     page: the credential's identifiers, status, and the decrypted, signature-verified EC
        ///     (<c>raw</c>, null for credentials issued before it was kept). Null when the session
        ///     is unknown, expired, or belongs to another browser.
        /// </summary>
        public JObject SessionCredential(string session, string browser)
        {
            if (session == null)
            {
                return null;
            }
            return state.Inspect(data =>
            {
                JObject ticket = data["sessions"][session] as JObject;
                if (ticket == null || (string)ticket["browser"] != browser || (long)ticket["expires"] <= Now)
                {
                    return null;
                }
                JObject entry = data["credentials"][(string)ticket["credential"]] as JObject;
                if (entry == null)
                {
                    return null;
                }
                return new JObject
                {
                    ["ec_id"] = entry["id"],
                    ["binding_id"] = entry["binding"],
                    ["status"] = entry["status"],
                    ["issued"] = entry["issued"],
                    ["expires"] = entry["expires"],
                    ["session_expires"] = ticket["expires"],
                    ["raw"] = entry["raw"]?.DeepClone(),
                };
            });
        }

        public ClaimsPrincipal Authenticate(string session, string browser)
        {
            if (session == null)
            {
                return null;
            }
            return state.Inspect(data =>
            {
                JObject ticket = data["sessions"][session] as JObject;
                if (
                    ticket == null
                    || (string)ticket["browser"] != browser
                    || (long)ticket["expires"] <= Now
                )
                {
                    return null;
                }
                JObject entry;
                try
                {
                    entry = Eligible(data, (string)ticket["credential"], "active");
                }
                catch (EmergencyFailure)
                {
                    return null;
                }
                ClaimsIdentity identity = new ClaimsIdentity(
                    AuthenticationType,
                    "emergency_display",
                    "role"
                );
                identity.AddClaim(new Claim("emergency_display", "Prepared user"));
                identity.AddClaim(new Claim("emergency", "true"));
                identity.AddClaim(new Claim("local_assurance", "emergency-possession"));
                identity.AddClaim(new Claim("emergency_session", session));
                identity.AddClaim(
                    new Claim(
                        "emergency_expiry",
                        ((long)ticket["expires"]).ToString(
                            System.Globalization.CultureInfo.InvariantCulture
                        )
                    )
                );
                identity.AddClaims(SnapshotPolicy.Filter((JArray)entry["claims"]));
                string display =
                    identity.FindFirst("name")?.Value ?? identity.FindFirst(ClaimTypes.Name)?.Value;
                if (!string.IsNullOrWhiteSpace(display))
                {
                    identity.RemoveClaim(identity.FindFirst("emergency_display"));
                    identity.AddClaim(new Claim("emergency_display", display));
                }
                return new ClaimsPrincipal(identity);
            });
        }

        public void EndSession(string session)
        {
            if (session != null)
            {
                state.Change(data => ((JObject)data["sessions"]).Remove(session));
            }
        }

        public JObject Readiness(string normalHandle, string browser)
        {
            lock (state.SyncRoot)
            {
                AcceptedSamlLogin login = Login(normalHandle, browser, false);
                return state.Inspect(data => new JObject
                {
                    ["can_prepare"] = !login.Reserved && login.RecordExpires > Now,
                    ["credentials"] = new JArray(
                        ((JObject)data["credentials"])
                            .Properties()
                            .Select(property => (JObject)property.Value)
                            .Where(item => (string)item["account"] == login.AccountKey)
                            .Select(item => new JObject
                            {
                                ["ec_id"] = item["id"],
                                ["binding_id"] = item["binding"],
                                ["expires_at"] = item["expires"],
                                ["status"] =
                                    (bool)data["keys"][(string)item["binding"]]["blocked"]
                                        ? "blocked"
                                    : (long)item["expires"] <= Now ? "expired"
                                    : (string)item["status"],
                                ["renew_soon"] = (long)item["expires"] < Now + 259200,
                                // Half the credential lifetime has passed: renew silently after a normal login.
                                ["renew_due"] =
                                    2 * Now >= (long)item["issued"] + (long)item["expires"],
                            })
                    ),
                });
            }
        }

        public async Task RemoveKey(
            string handle,
            string browser,
            string binding,
            CancellationToken cancellation
        )
        {
            lock (state.SyncRoot)
            {
                AcceptedSamlLogin login = Login(handle, browser, false);
                state.Change(data =>
                {
                    JObject key = data["keys"][binding] as JObject;
                    if (key == null || (string)key["account"] != login.AccountKey)
                    {
                        throw new EmergencyFailure(404, "key_not_found");
                    }
                    BlockKey(data, binding);
                    foreach (JProperty credential in ((JObject)data["credentials"]).Properties().Where(property => (string)property.Value["binding"] == binding).ToArray())
                    {
                        credential.Remove();
                    }
                    ((JObject)data["keys"]).Remove(binding);
                    JArray queue = (JArray)data["pending_removals"];
                    if (!queue.Values<string>().Contains(binding))
                    {
                        queue.Add(binding);
                    }
                    Event(data, "key_removed");
                    return true;
                });
            }
            try
            {
                await ReportRemoval(binding, cancellation).ConfigureAwait(false);
            }
            catch (Exception exception) when (!(exception is OperationCanceledException)) { }
        }

        private static void BlockKey(JObject data, string id)
        {
            JObject key = data["keys"][id] as JObject;
            if (key != null)
            {
                key["blocked"] = true;
                key["revision"] = (long)key["revision"] + 1;
            }
            foreach (
                JObject entry in ((JObject)data["credentials"])
                    .Properties()
                    .Select(property => (JObject)property.Value)
                    .Where(item => (string)item["binding"] == id)
            )
            {
                entry["status"] = "blocked";
            }
            foreach (
                JProperty ticket in ((JObject)data["sessions"])
                    .Properties()
                    .Where(property =>
                        (string)data["credentials"][(string)property.Value["credential"]]["binding"]
                        == id
                    )
                    .ToArray()
            )
            {
                ticket.Remove();
            }
        }

        public async Task SynchronizeIfDue(CancellationToken cancellation)
        {
            lock (state.SyncRoot)
            {
                if (Now - lastSynchronization < 600)
                {
                    return;
                }
                lastSynchronization = Now;
            }
            try
            {
                await Synchronize(cancellation).ConfigureAwait(false);
            }
            catch (Exception exception) when (!(exception is OperationCanceledException)) { }
        }

        public async Task Synchronize(CancellationToken cancellation)
        {
            JObject keys = await issuer
                .Request(HttpMethod.Get, "emergency/signing-keys", null, cancellation)
                .ConfigureAwait(false);
            CredentialReader.CheckTrust(keys.ToString(Formatting.None));
            state.Change(data =>
            {
                data["trust"] = keys.ToString(Formatting.None);
                return true;
            });
            foreach (
                string id in state.Inspect(data =>
                    ((JArray)data["pending_removals"]).Values<string>().ToArray()
                )
            )
            {
                await ReportRemoval(id, cancellation).ConfigureAwait(false);
            }
            for (int page = 0; page < 100; page++)
            {
                long cursor = state.Inspect(data => (long)data["cursor"]);
                JObject feed = await issuer
                    .Request(
                        HttpMethod.Get,
                        "emergency/revocations?after="
                            + cursor.ToString(System.Globalization.CultureInfo.InvariantCulture),
                        null,
                        cancellation
                    )
                    .ConfigureAwait(false);
                bool more = (bool)feed["has_more"];
                state.Change(data =>
                {
                    if ((long)data["cursor"] != cursor)
                    {
                        throw new EmergencyFailure(409, "sync_changed");
                    }
                    JArray items = feed["events"] as JArray;
                    if (items == null || items.Count > 100)
                    {
                        throw Wire.Invalid();
                    }
                    long next = cursor;
                    foreach (JObject item in items)
                    {
                        long sequence = Wire.Number(item, "sequence");
                        if (sequence != next + 1)
                        {
                            throw new EmergencyFailure(409, "revocation_gap");
                        }
                        string kind = Wire.String(item, "kind"),
                            target = Wire.String(item, "id", 128);
                        if (kind == "binding")
                        {
                            BlockKey(data, target);
                        }
                        else if (kind == "ec")
                        {
                            JObject entry = data["credentials"][target] as JObject;
                            if (entry != null)
                            {
                                entry["status"] = "blocked";
                            }
                        }
                        else
                        {
                            throw Wire.Invalid();
                        }
                        next = sequence;
                    }
                    if (Wire.Number(feed, "cursor") != next || (more && next == cursor))
                    {
                        throw Wire.Invalid();
                    }
                    data["cursor"] = next;
                    if (!more)
                    {
                        Event(data, "online_sync_completed");
                    }
                    return true;
                });
                if (!more)
                {
                    return;
                }
            }
            throw new EmergencyFailure(409, "sync_more_pages_required");
        }

        private async Task ReportRemoval(string binding, CancellationToken cancellation)
        {
            await issuer
                .Request(
                    HttpMethod.Post,
                    "emergency/revocations",
                    new JObject { ["binding_id"] = binding },
                    cancellation
                )
                .ConfigureAwait(false);
            state.Change(data =>
            {
                foreach (
                    JToken item in ((JArray)data["pending_removals"])
                        .Where(item => (string)item == binding)
                        .ToArray()
                )
                {
                    item.Remove();
                }
                return true;
            });
        }

        public void CheckRate(string address)
        {
            lock (state.SyncRoot)
            {
                foreach (string key in requests.Keys.ToArray())
                {
                    while (requests[key].Count > 0 && requests[key].Peek() <= Now - 60)
                    {
                        requests[key].Dequeue();
                    }
                    if (requests[key].Count == 0)
                    {
                        requests.Remove(key);
                    }
                }
                string identity = Wire.Hash(address ?? "unknown");
                Queue<long> queue;
                if (!requests.TryGetValue(identity, out queue))
                {
                    if (requests.Count >= 4096)
                    {
                        throw new EmergencyFailure(429, "rate_limited");
                    }
                    requests.Add(identity, queue = new Queue<long>());
                }
                if (queue.Count >= 60)
                {
                    throw new EmergencyFailure(429, "rate_limited");
                }
                queue.Enqueue(Now);
            }
        }

        private void Prune()
        {
            foreach (
                string id in normalLogins
                    .Where(pair => pair.Value.SessionExpires <= Now)
                    .Select(pair => pair.Key)
                    .ToArray()
            )
            {
                normalLogins.Remove(id);
            }
            foreach (
                string id in registrations
                    .Where(pair => pair.Value.Deadline <= Now)
                    .Select(pair => pair.Key)
                    .ToArray()
            )
            {
                registrations.Remove(id);
            }
            foreach (
                string id in proofs
                    .Where(pair => pair.Value.Deadline <= Now)
                    .Select(pair => pair.Key)
                    .ToArray()
            )
            {
                proofs.Remove(id);
            }
        }

        private void Event(JObject data, string code)
        {
            JArray events = (JArray)data["events"];
            events.Add(
                Now.ToString(System.Globalization.CultureInfo.InvariantCulture) + " " + code
            );
            if (events.Count > 200)
            {
                events.RemoveAt(0);
            }
        }

        public void Dispose()
        {
            state.Dispose();
        }
    }
}
