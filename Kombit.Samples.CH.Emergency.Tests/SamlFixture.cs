using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Kombit.Samples.CH.Emergency.Tests
{
    public sealed class SamlFixture : HttpMessageHandler
    {
        public string DirectoryPath { get; private set; }
        public string Browser { get; private set; } = Wire.RandomId();
        public string Binding { get; private set; } = Wire.RandomId();
        public string CredentialId { get; private set; } = Wire.RandomId();
        public string UserHandle { get; private set; } = Wire.RandomId();
        public DateTimeOffset Time { get; set; } =
            DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        public EmergencySettings Settings { get; private set; }
        public EmergencyAccess Access { get; private set; }
        public CredentialReader Reader { get; private set; }
        public string Trust { get; private set; }
        public bool Offline { get; set; }
        public int Calls { get; private set; }
        private readonly RSA encryption = new RSACryptoServiceProvider(2048);
        private readonly RSA rsa = new RSACryptoServiceProvider(2048);
        private readonly ECDsaCng elliptic = new ECDsaCng(ECCurve.NamedCurves.nistP256);
        private readonly ECDsaCng signer = new ECDsaCng(ECCurve.NamedCurves.nistP256);
        private readonly bool useEc;
        private readonly byte[] entropy = Guid.NewGuid().ToByteArray();
        private readonly HttpClient http;
        private string reference;
        private readonly JArray feed = new JArray();

        public SamlFixture(bool ec = false)
        {
            useEc = ec;
            DirectoryPath = Path.Combine(
                Path.GetTempPath(),
                "SamlEmergencyTests",
                Guid.NewGuid().ToString("N")
            );
            Directory.CreateDirectory(DirectoryPath);
            string unique = Guid.NewGuid().ToString("N");
            Settings = new EmergencySettings
            {
                Origin = "https://saml.fixture.invalid",
                RpId = "saml.fixture.invalid",
                EmergencyIssuer = "https://issuer.fixture.invalid/emergency",
                IssuerRuntimeUrl = "https://issuer.fixture.invalid/runtime/",
                NormalSamlIssuer = "https://issuer.fixture.invalid/saml",
                Audience = "urn:saml:emergency:test",
                StateDirectory = Path.Combine(DirectoryPath, "registry"),
                PrivateEncryptionKeyFile = Path.Combine(DirectoryPath, "decryption.xml"),
                EncryptionKeyId = "test-encryption",
                InitialSigningKeysFile = Path.Combine(DirectoryPath, "trust.json"),
                BackendSecretVariable = "TEST_SAML_BACKEND_" + unique,
            };
            Environment.SetEnvironmentVariable(Settings.BackendSecretVariable, Wire.RandomId());
            using (SHA256 hash = SHA256.Create())
            {
                File.WriteAllBytes(
                    Settings.PrivateEncryptionKeyFile,
                    ProtectedData.Protect(
                        Encoding.UTF8.GetBytes(encryption.ToXmlString(true)),
                        hash.ComputeHash(
                            Encoding.UTF8.GetBytes(
                                "SamlSample.Emergency.EncryptionKey.v1|" + Settings.Audience
                            )
                        ),
                        DataProtectionScope.LocalMachine
                    )
                );
            }
            ECParameters key = signer.ExportParameters(false);
            Trust = new JObject
            {
                ["keys"] = new JArray(
                    new JObject
                    {
                        ["kty"] = "EC",
                        ["crv"] = "P-256",
                        ["alg"] = "ES256",
                        ["use"] = "sig",
                        ["kid"] = "test-signing",
                        ["x"] = Wire.Encode(key.Q.X),
                        ["y"] = Wire.Encode(key.Q.Y),
                    }
                ),
            }.ToString(Formatting.None);
            File.WriteAllText(Settings.InitialSigningKeysFile, Trust);
            Reader = new CredentialReader(Settings);
            http = new HttpClient(this, false);
            Restart();
        }

        public EmergencyStateFile OpenStore()
        {
            return new EmergencyStateFile(
                Settings,
                data => ProtectedData.Protect(data, entropy, DataProtectionScope.CurrentUser),
                data => ProtectedData.Unprotect(data, entropy, DataProtectionScope.CurrentUser),
                Reader
            );
        }

        public void Restart()
        {
            if (Access != null)
            {
                Access.Dispose();
            }
            Access = new EmergencyAccess(
                Settings,
                OpenStore(),
                Reader,
                new WebAuthnChecks(Settings),
                new IssuerConnection(Settings, http),
                () => Time
            );
        }

        public string Login(string qualifier = "normal-idp")
        {
            reference = Wire.RandomId();
            return Access.RecordLogin(
                new AcceptedSamlLogin
                {
                    Browser = Browser,
                    Issuer = Settings.NormalSamlIssuer,
                    AssertionId = reference,
                    Subject = "user",
                    Format = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
                    NameQualifier = qualifier,
                    SpNameQualifier = "normal-sp",
                    RecordExpires = Time.ToUnixTimeSeconds() + 600,
                }
            );
        }

        public async Task<JObject> Pending(string login)
        {
            JObject started = await Access.BeginRegistration(
                login,
                Browser,
                CancellationToken.None
            );
            return await Access.FinishRegistration(
                login,
                Browser,
                (string)started["enrollment_id"],
                new JObject { ["rawId"] = CredentialId },
                CancellationToken.None
            );
        }

        public async Task<JObject> Active()
        {
            string login = Login();
            JObject entry = await Pending(login);
            await Prove(entry, false, login, 1);
            return entry;
        }

        public async Task<JObject> Prove(
            JObject entry,
            bool login,
            string normalHandle,
            uint counter
        )
        {
            JObject pending = Access.StartProof(
                Browser,
                (string)entry["emergency_credential"],
                login,
                normalHandle
            );
            return await Access.CompleteProof(
                Browser,
                (string)pending["transaction_id"],
                login,
                Assertion((JObject)pending["publicKey"], counter),
                normalHandle
            );
        }

        public JObject Assertion(JObject options, uint counter, string mutation = "valid")
        {
            JObject client = new JObject
            {
                ["type"] = mutation == "type" ? "webauthn.create" : "webauthn.get",
                ["challenge"] =
                    mutation == "challenge" ? Wire.RandomId() : (string)options["challenge"],
                ["origin"] = mutation == "origin" ? "https://wrong.invalid" : Settings.Origin,
            };
            if (mutation == "crossOrigin")
                client["crossOrigin"] = true;
            if (mutation == "topOrigin")
                client["topOrigin"] = "https://wrong.invalid";
            byte flags =
                mutation == "up" ? (byte)4
                : mutation == "uv" ? (byte)1
                : mutation == "backup" ? (byte)13
                : mutation == "backedUp" ? (byte)29
                : (byte)5;
            byte[] data,
                signature,
                clientBytes = Encoding.UTF8.GetBytes(client.ToString(Formatting.None));
            using (SHA256 hash = SHA256.Create())
            {
                data = hash.ComputeHash(
                        Encoding.UTF8.GetBytes(mutation == "rp" ? "wrong.invalid" : Settings.RpId)
                    )
                    .Concat(
                        new[]
                        {
                            flags,
                            (byte)(counter >> 24),
                            (byte)(counter >> 16),
                            (byte)(counter >> 8),
                            (byte)counter,
                        }
                    )
                    .ToArray();
                byte[] signed = data.Concat(hash.ComputeHash(clientBytes)).ToArray();
                signature = useEc
                    ? Der(elliptic.SignData(signed, HashAlgorithmName.SHA256))
                    : rsa.SignData(signed, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
            if (mutation == "signature")
                signature[0] ^= 1;
            return new JObject
            {
                ["id"] = mutation == "id" ? Wire.RandomId() : CredentialId,
                ["rawId"] = CredentialId,
                ["type"] = "public-key",
                ["response"] = new JObject
                {
                    ["clientDataJSON"] = Wire.Encode(clientBytes),
                    ["authenticatorData"] = Wire.Encode(data),
                    ["signature"] = Wire.Encode(signature),
                    ["userHandle"] = mutation == "handle" ? Wire.RandomId() : UserHandle,
                },
            };
        }

        public JObject Issue(string mutation = "valid")
        {
            ECParameters ec = elliptic.ExportParameters(false);
            RSAParameters r = rsa.ExportParameters(false);
            long now = Time.ToUnixTimeSeconds();
            string id = Wire.RandomId();
            JObject jwk = useEc
                ? new JObject
                {
                    ["kty"] = "EC",
                    ["crv"] = "P-256",
                    ["x"] = Wire.Encode(ec.Q.X),
                    ["y"] = Wire.Encode(ec.Q.Y),
                    ["alg"] = "ES256",
                }
                : new JObject
                {
                    ["kty"] = "RSA",
                    ["n"] = Wire.Encode(r.Modulus),
                    ["e"] = Wire.Encode(r.Exponent),
                    ["alg"] = "RS256",
                };
            JObject payload = new JObject
            {
                ["iss"] = Settings.EmergencyIssuer,
                ["aud"] = Settings.Audience,
                ["sub"] = "user",
                ["jti"] = id,
                ["iat"] = now,
                ["nbf"] = now,
                ["exp"] = now + 3600,
                ["profile_version"] = CredentialReader.Profile,
                ["cnf"] = new JObject { ["jwk"] = jwk },
                ["webauthn"] = new JObject
                {
                    ["credential_id"] = CredentialId,
                    ["user_handle"] = UserHandle,
                    ["rp_id"] = Settings.RpId,
                    ["origin"] = Settings.Origin,
                    ["hardware_policy"] = "poc-uv-nonbackup",
                    ["cose_alg"] = useEc ? -7 : -257,
                    ["sign_count"] = 0,
                },
                ["source"] = new JObject
                {
                    ["protocol"] = "saml",
                    ["issuer"] = Settings.NormalSamlIssuer,
                    ["token_reference"] = reference ?? "synthetic-reference",
                    ["accepted_at"] = now,
                    ["name_id_format"] = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
                    ["name_qualifier"] = "normal-idp",
                    ["sp_name_qualifier"] = "normal-sp",
                },
                ["claims_snapshot"] = new JArray(
                    Claim(
                        "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod",
                        "normal-evidence"
                    ),
                    Claim(
                        "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationinstant",
                        "normal-evidence"
                    ),
                    Claim(
                        "http://schemas.microsoft.com/claims/authnmethodsreferences",
                        "normal-evidence"
                    ),
                    Claim(
                        "http://schemas.microsoft.com/claims/authnclassreference",
                        "normal-evidence"
                    ),
                    Claim("ROLE", "case-admin"),
                    Claim("name", "Synthetic User"),
                    Claim("department", "A"),
                    Claim("department", "B"),
                    Claim("email", "user@example.invalid"),
                    Claim("role", "read-only"),
                    Claim("role", "administrator"),
                    Claim(
                        "https://data.gov.dk/model/core/eid/privilegesIntermediate",
                        "PFByaXZpbGVnZUxpc3QvPg=="
                    ),
                    Claim("acr", "normal-high"),
                    Claim("access_token", "not-a-real-token"),
                    Claim("emergency_session", "untrusted")
                ),
            };
            JObject header = new JObject
            {
                ["alg"] = "ES256",
                ["kid"] = "test-signing",
                ["typ"] = "ch2-emergency-webauthn+jwt",
            };
            switch (mutation)
            {
                case "audience":
                    payload["aud"] = "wrong";
                    break;
                case "audience-array":
                    payload["aud"] = new JArray(Settings.Audience);
                    break;
                case "issuer":
                    payload["iss"] = "https://wrong.invalid";
                    break;
                case "expired":
                    payload["iat"] = now - 4000;
                    payload["nbf"] = now - 4000;
                    payload["exp"] = now - 1;
                    break;
                case "lifetime":
                    payload["exp"] = now + 1209601;
                    break;
                case "profile":
                    payload["profile_version"] = "other";
                    break;
                case "source":
                    payload["source"]["issuer"] = "other";
                    break;
                case "rp":
                    payload["webauthn"]["rp_id"] = "wrong.invalid";
                    break;
                case "origin":
                    payload["webauthn"]["origin"] = "https://wrong.invalid";
                    break;
                case "hardware":
                    payload["webauthn"]["hardware_policy"] = "trusted-hardware";
                    break;
                case "type":
                    header["typ"] = "JWT";
                    break;
                case "key":
                    header["kid"] = "unknown";
                    break;
                case "external":
                    header["jku"] = "https://wrong.invalid/keys";
                    break;
                case "critical":
                    header["crit"] = new JArray("unknown");
                    break;
                case "none":
                    header["alg"] = "none";
                    break;
            }
            string json = payload.ToString(Formatting.None);
            if (mutation == "duplicate")
                json = "{\"sub\":\"other\"," + json.Substring(1);
            string signingInput =
                Wire.Encode(Encoding.UTF8.GetBytes(header.ToString(Formatting.None)))
                + "."
                + Wire.Encode(Encoding.UTF8.GetBytes(json));
            string signed =
                signingInput
                + "."
                + (
                    mutation == "none"
                        ? ""
                        : Wire.Encode(
                            signer.SignData(
                                Encoding.ASCII.GetBytes(signingInput),
                                HashAlgorithmName.SHA256
                            )
                        )
                );
            string encrypted = new JsonWebTokenHandler().EncryptToken(
                signed,
                new EncryptingCredentials(
                    new RsaSecurityKey(encryption) { KeyId = Settings.EncryptionKeyId },
                    SecurityAlgorithms.RsaOAEP,
                    SecurityAlgorithms.Aes256CbcHmacSha512
                ),
                new Dictionary<string, object>
                {
                    ["typ"] = "ch2-emergency-webauthn+jwt",
                    ["cty"] = "JWT",
                }
            );
            if (mutation == "tampered")
            {
                string[] pieces = encrypted.Split('.');
                byte[] tag = Wire.Decode(pieces[4]);
                tag[0] ^= 1;
                pieces[4] = Wire.Encode(tag);
                encrypted = string.Join(".", pieces);
            }
            return new JObject
            {
                ["ec_id"] = id,
                ["binding_id"] = Binding,
                ["expires_at"] = now + 3600,
                ["profile_version"] = CredentialReader.Profile,
                ["emergency_credential"] = encrypted,
            };
        }

        private static JObject Claim(string type, string value)
        {
            return new JObject
            {
                ["type"] = type,
                ["value"] = value,
                ["value_type"] = ClaimValueTypes.String,
            };
        }

        private static byte[] Der(byte[] signature)
        {
            byte[] r = signature.Take(32).SkipWhile(value => value == 0).ToArray(),
                s = signature.Skip(32).SkipWhile(value => value == 0).ToArray();
            if (r.Length == 0 || r[0] >= 128)
                r = new byte[] { 0 }
                    .Concat(r)
                    .ToArray();
            if (s.Length == 0 || s[0] >= 128)
                s = new byte[] { 0 }
                    .Concat(s)
                    .ToArray();
            return new byte[] { 48, (byte)(r.Length + s.Length + 4), 2, (byte)r.Length }
                .Concat(r)
                .Concat(new byte[] { 2, (byte)s.Length })
                .Concat(s)
                .ToArray();
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken
        )
        {
            Calls++;
            if (Offline)
                throw new HttpRequestException("Synthetic offline fixture.");
            string path = request.RequestUri.AbsolutePath;
            JObject body =
                request.Content == null
                    ? null
                    : Wire.Object(await request.Content.ReadAsStringAsync());
            JObject result;
            if (path.EndsWith("signing-keys", StringComparison.Ordinal))
                result = JObject.Parse(Trust);
            else if (path.EndsWith("revocations", StringComparison.Ordinal))
            {
                if (request.Method == HttpMethod.Get)
                    result = new JObject
                    {
                        ["events"] = feed.DeepClone(),
                        ["cursor"] = feed.Count,
                        ["has_more"] = false,
                    };
                else
                {
                    feed.Add(
                        new JObject
                        {
                            ["sequence"] = feed.Count + 1,
                            ["kind"] = "binding",
                            ["id"] = body["binding_id"],
                            ["created_at"] = Time.ToUnixTimeSeconds(),
                        }
                    );
                    return new HttpResponseMessage(HttpStatusCode.NoContent);
                }
            }
            else if (request.Method == HttpMethod.Delete)
                return new HttpResponseMessage(HttpStatusCode.NoContent);
            else if (path.EndsWith("complete", StringComparison.Ordinal))
                result = Issue();
            else
            {
                reference = (string)body["normal_token_reference"]["token_reference"];
                result = path.EndsWith("renewals", StringComparison.Ordinal)
                    ? Issue()
                    : new JObject
                    {
                        ["enrollment_id"] = Wire.RandomId(),
                        ["expires_at"] = Time.ToUnixTimeSeconds() + 300,
                        ["publicKey"] = new JObject
                        {
                            ["rp"] = new JObject { ["id"] = Settings.RpId },
                        },
                    };
            }
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    result.ToString(Formatting.None),
                    Encoding.UTF8,
                    "application/json"
                ),
            };
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                Access.Dispose();
                http.Dispose();
                encryption.Dispose();
                rsa.Dispose();
                elliptic.Dispose();
                signer.Dispose();
                Environment.SetEnvironmentVariable(Settings.BackendSecretVariable, null);
                string prefix =
                    Path.GetFullPath(Path.Combine(Path.GetTempPath(), "SamlEmergencyTests"))
                    + Path.DirectorySeparatorChar;
                if (
                    Path.GetFullPath(DirectoryPath)
                        .StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
                )
                    Directory.Delete(DirectoryPath, true);
            }
            base.Dispose(disposing);
        }
    }
}
