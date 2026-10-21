using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Kombit.Samples.CH.Emergency
{
    public sealed class WebAuthnChecks
    {
        private readonly Fido2Configuration configuration;
        private readonly Fido2 verifier;
        private readonly string diagnosticPath;
        public WebAuthnChecks(EmergencySettings settings)
        {
            configuration = new Fido2Configuration { ServerDomain = settings.RpId, ServerName = "SAML sample emergency access", Origin = settings.Origin };
            verifier = new Fido2(configuration, null);
            diagnosticPath = System.IO.Path.Combine(settings.StateDirectory, "proof-diagnostic.json");
        }
        public AssertionOptions Create(string credential)
        {
            return AssertionOptions.Create(configuration, Wire.Decode(Wire.RandomId()), new[] { new PublicKeyCredentialDescriptor(Wire.Decode(credential)) }, UserVerificationRequirement.Required, new AuthenticationExtensionsClientInputs());
        }
        public async Task<uint> Verify(JObject input, KeyProof pending)
        {
            string stage = "shape";
            try
            {
                Wire.Fields(input, "id", "rawId", "type", "response", "clientExtensionResults", "authenticatorAttachment");
                if (Wire.String(input, "type") != "public-key" || Wire.String(input, "id", 2048) != pending.Authenticator || Wire.String(input, "rawId", 2048) != pending.Authenticator) { throw Wire.Invalid(); }
                JObject response = input["response"] as JObject;
                Wire.Fields(response, "clientDataJSON", "authenticatorData", "signature", "userHandle");
                stage = "authenticator-data";
                byte[] data = Wire.Decode(Wire.String(response, "authenticatorData", 16384));
                if (data.Length < 37 || (data[32] & 5) != 5 || (data[32] & 24) != 0) { throw Wire.Invalid(); }
                stage = "client-data";
                JObject client = Wire.Object(new UTF8Encoding(false, true).GetString(Wire.Decode(Wire.String(response, "clientDataJSON", 16384))));
                if (client.Property("topOrigin") != null || (client["crossOrigin"] != null && (client["crossOrigin"].Type != JTokenType.Boolean || (bool)client["crossOrigin"]))) { throw Wire.Invalid(); }
                stage = "user-handle";
                string handle = Wire.NullableString(response, "userHandle");
                if (handle != null && handle != pending.Handle) { throw Wire.Invalid(); }
                stage = "deserialize";
                AuthenticatorAssertionRawResponse raw = JsonConvert.DeserializeObject<AuthenticatorAssertionRawResponse>(input.ToString(Formatting.None), new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None, MetadataPropertyHandling = MetadataPropertyHandling.Ignore, MaxDepth = 24 });
                stage = "cryptographic-verification";
                await verifier.MakeAssertionAsync(raw, pending.Options, Wire.Decode(pending.Cose), pending.Counter,
                    item => Task.FromResult(item.UserHandle != null && item.UserHandle.SequenceEqual(Wire.Decode(pending.Handle)) && item.CredentialId.SequenceEqual(Wire.Decode(pending.Authenticator)))).ConfigureAwait(false);
                stage = "counter";
                uint count = ((uint)data[33] << 24) | ((uint)data[34] << 16) | ((uint)data[35] << 8) | data[36];
                if ((count > 0 || pending.Counter > 0) && count <= pending.Counter) { throw Wire.Invalid(); }
                return count;
            }
            catch (Exception exception)
            {
                // Fixed diagnostic codes only; never store challenges, assertions, signatures, or claims.
                try
                {
                    string text = exception.Message.ToLowerInvariant();
                    string reason = text.Contains("signature") ? "signature" : text.Contains("userhandle") || text.Contains("user handle") ? "user-handle" : text.Contains("challenge") ? "challenge" : text.Contains("origin") ? "origin" : text.Contains("counter") ? "counter" : text.Contains("assembly") ? "dependency" : "other";
                    System.IO.File.WriteAllText(diagnosticPath, JsonConvert.SerializeObject(new { stage, exception = exception.GetType().Name, inner = exception.InnerException?.GetType().Name, reason }));
                }
                catch (Exception) { }
                throw new EmergencyFailure(400, "key_proof_rejected");
            }
        }
    }
}
