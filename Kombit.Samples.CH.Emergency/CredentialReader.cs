using System;
using System.IO;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using PeterO.Cbor;

namespace Kombit.Samples.CH.Emergency
{
    public sealed class CredentialReader
    {
        public const string Profile = "us39805-ec-v1";
        private const string Type = "ch2-emergency-webauthn+jwt";
        private readonly EmergencySettings settings;
        public CredentialReader(EmergencySettings configuration) { settings = configuration; }
        public JObject Read(string encrypted, string trust, DateTimeOffset time)
        {
            try
            {
                if (encrypted == null || encrypted.Length > 65536) { throw Wire.Invalid(); }
                string[] outerParts = encrypted.Split('.');
                if (outerParts.Length != 5) { throw Wire.Invalid(); }
                JObject outer = Decode(outerParts[0]);
                Wire.Fields(outer, "alg", "enc", "kid", "cty", "typ");
                if (Wire.String(outer, "alg") != "RSA-OAEP" || Wire.String(outer, "enc") != "A256CBC-HS512" || Wire.String(outer, "kid") != settings.EncryptionKeyId
                    || Wire.String(outer, "cty") != "JWT" || (outer["typ"] != null && (string)outer["typ"] != Type)) { throw Wire.Invalid(); }
                string signed;
                using (RSA rsa = OpenPrivateKey())
                {
                    signed = new JsonWebTokenHandler().DecryptToken(new JsonWebToken(encrypted), new TokenValidationParameters
                    {
                        TokenDecryptionKey = new RsaSecurityKey(rsa) { KeyId = settings.EncryptionKeyId },
                        CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
                    });
                }
                string[] innerParts = signed.Split('.');
                if (innerParts.Length != 3) { throw Wire.Invalid(); }
                JObject header = Decode(innerParts[0]), payload = Decode(innerParts[1]);
                Wire.Fields(header, "alg", "kid", "typ");
                if (Wire.String(header, "alg") != "ES256" || Wire.String(header, "typ") != Type) { throw Wire.Invalid(); }
                string keyId = Wire.String(header, "kid", 128);
                JObject keys = CheckTrust(trust);
                JObject jwk = keys["keys"].OfType<JObject>().Single(key => (string)key["kid"] == keyId);
                SecurityToken validated;
                new JwtSecurityTokenHandler { MapInboundClaims = false }.ValidateToken(signed, new TokenValidationParameters
                {
                    IssuerSigningKey = new JsonWebKey(jwk.ToString(Formatting.None)), ValidateIssuerSigningKey = true, RequireSignedTokens = true,
                    ValidAlgorithms = new[] { "ES256" }, ValidateIssuer = true, ValidIssuer = settings.EmergencyIssuer,
                    ValidateAudience = true, ValidAudience = settings.Audience, ValidateLifetime = true, RequireExpirationTime = true, ClockSkew = TimeSpan.Zero,
                    LifetimeValidator = (nbf, exp, token, validation) => nbf.HasValue && exp.HasValue && nbf.Value <= time.UtcDateTime && exp.Value > time.UtcDateTime
                }, out validated);
                if (Wire.String(payload, "aud") != settings.Audience || Wire.String(payload, "iss") != settings.EmergencyIssuer || Wire.String(payload, "profile_version") != Profile) { throw Wire.Invalid(); }
                long issued = Wire.Number(payload, "iat"), expires = Wire.Number(payload, "exp"), nbfTime = Wire.Number(payload, "nbf"), now = time.ToUnixTimeSeconds();
                if (issued > now || nbfTime < issued || nbfTime > now || expires <= now || expires <= issued || expires - issued > 1209600) { throw Wire.Invalid(); }
                JObject source = payload["source"] as JObject, webauthn = payload["webauthn"] as JObject;
                if (Wire.String(source, "protocol") != "saml" || Wire.String(source, "issuer") != settings.NormalSamlIssuer
                    || Wire.String(webauthn, "rp_id") != settings.RpId || Wire.String(webauthn, "origin") != settings.Origin || Wire.String(webauthn, "hardware_policy") != "poc-uv-nonbackup") { throw Wire.Invalid(); }
                long accepted = Wire.Number(source, "accepted_at"), count = Wire.Number(webauthn, "sign_count");
                if (accepted > issued || accepted < issued - 600 || count < 0 || count > uint.MaxValue) { throw Wire.Invalid(); }
                string subject = Wire.String(payload, "sub");
                string account = AcceptedSamlLogin.Account(settings.NormalSamlIssuer, subject, Wire.NullableString(source, "name_id_format"), Wire.NullableString(source, "name_qualifier"), Wire.NullableString(source, "sp_name_qualifier"));
                JArray claims = payload["claims_snapshot"] as JArray;
                if (claims == null || claims.Count > 200) { throw Wire.Invalid(); }
                foreach (JObject claim in claims)
                {
                    Wire.Fields(claim, "type", "value", "value_type", "name_format");
                    Wire.String(claim, "type"); Wire.String(claim, "value_type");
                    if (claim["value"].Type != JTokenType.String || ((string)claim["value"]).Length > 16384) { throw Wire.Invalid(); }
                }
                return new JObject
                {
                    ["id"] = Wire.String(payload, "jti", 128), ["account"] = account, ["subject"] = subject,
                    ["source_reference"] = Wire.String(source, "token_reference"), ["issued"] = issued, ["expires"] = expires,
                    ["authenticator"] = Wire.Encode(Wire.Decode(Wire.String(webauthn, "credential_id", 2048), 1024)),
                    ["handle"] = Wire.Encode(Wire.Decode(Wire.String(webauthn, "user_handle", 128), 64)),
                    ["cose"] = Wire.Encode(ToCose((JObject)payload["cnf"]["jwk"], Wire.Number(webauthn, "cose_alg"))),
                    ["initial_counter"] = count, ["digest"] = Wire.Hash(encrypted), ["claims"] = claims.DeepClone()
                };
            }
            catch (Exception exception) when (!(exception is EmergencyFailure)) { throw new EmergencyFailure(400, "credential_rejected"); }
        }
        public static JObject CheckTrust(string json)
        {
            JObject root = Wire.Object(json); Wire.Fields(root, "keys");
            JArray keys = root["keys"] as JArray;
            if (keys == null || keys.Count < 1 || keys.Count > 8) { throw Wire.Invalid(); }
            System.Collections.Generic.HashSet<string> ids = new System.Collections.Generic.HashSet<string>(StringComparer.Ordinal);
            foreach (JObject key in keys)
            {
                Wire.Fields(key, "kty", "crv", "x", "y", "kid", "alg", "use");
                if (Wire.String(key, "kty") != "EC" || Wire.String(key, "crv") != "P-256" || Wire.String(key, "alg") != "ES256" || Wire.String(key, "use") != "sig"
                    || !ids.Add(Wire.String(key, "kid", 128)) || Wire.Decode(Wire.String(key, "x"), 32).Length != 32 || Wire.Decode(Wire.String(key, "y"), 32).Length != 32) { throw Wire.Invalid(); }
            }
            return root;
        }
        public string KeyIdentity()
        {
            using (RSA key = OpenPrivateKey())
            {
                RSAParameters publicKey = key.ExportParameters(false);
                return Wire.Hash(Wire.Encode(publicKey.Modulus) + "." + Wire.Encode(publicKey.Exponent));
            }
        }
        private RSA OpenPrivateKey()
        {
            if (new FileInfo(settings.PrivateEncryptionKeyFile).Length > 32768) { throw Wire.Invalid(); }
            RSA rsa = new RSACryptoServiceProvider { PersistKeyInCsp = false };
            try
            {
                using (SHA256 hash = SHA256.Create())
                {
                    byte[] entropy = hash.ComputeHash(Encoding.UTF8.GetBytes("SamlSample.Emergency.EncryptionKey.v1|" + settings.Audience));
                    rsa.FromXmlString(new UTF8Encoding(false, true).GetString(ProtectedData.Unprotect(File.ReadAllBytes(settings.PrivateEncryptionKeyFile), entropy, DataProtectionScope.LocalMachine)));
                }
                if (rsa.KeySize < 2048 || rsa.KeySize > 4096 || rsa.ExportParameters(true).D == null) { throw Wire.Invalid(); }
                return rsa;
            }
            catch { rsa.Dispose(); throw; }
        }
        private static JObject Decode(string text) { return Wire.Object(new UTF8Encoding(false, true).GetString(Wire.Decode(text))); }
        private static byte[] ToCose(JObject key, long algorithm)
        {
            CBORObject cose = CBORObject.NewMap();
            if (algorithm == -7)
            {
                Wire.Fields(key, "kty", "crv", "x", "y", "alg");
                byte[] x = Wire.Decode(Wire.String(key, "x"), 32), y = Wire.Decode(Wire.String(key, "y"), 32);
                if (Wire.String(key, "kty") != "EC" || Wire.String(key, "crv") != "P-256" || Wire.String(key, "alg") != "ES256" || x.Length != 32 || y.Length != 32) { throw Wire.Invalid(); }
                cose.Add(1, 2); cose.Add(3, -7); cose.Add(-1, 1); cose.Add(-2, x); cose.Add(-3, y);
            }
            else if (algorithm == -257)
            {
                Wire.Fields(key, "kty", "n", "e", "alg");
                byte[] modulus = Wire.Decode(Wire.String(key, "n"), 512), exponent = Wire.Decode(Wire.String(key, "e"), 4);
                if (Wire.String(key, "kty") != "RSA" || Wire.String(key, "alg") != "RS256" || modulus.Length < 256) { throw Wire.Invalid(); }
                cose.Add(1, 3); cose.Add(3, -257); cose.Add(-1, modulus); cose.Add(-2, exponent);
            }
            else { throw Wire.Invalid(); }
            return cose.EncodeToBytes();
        }
    }
}
