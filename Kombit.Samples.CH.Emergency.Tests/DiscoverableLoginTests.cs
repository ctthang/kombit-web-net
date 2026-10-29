using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json.Linq;

namespace Kombit.Samples.CH.Emergency.Tests
{
    [TestClass]
    public class DiscoverableLoginTests
    {
        private static async Task<JObject> Login(SamlFixture fixture, uint counter, string mutation = "valid")
        {
            JObject challenge = fixture.Access.StartDiscoverableLogin(fixture.Browser);
            return await fixture.Access.CompleteDiscoverableLogin(
                fixture.Browser,
                (string)challenge["transaction_id"],
                fixture.Assertion((JObject)challenge["publicKey"], counter, mutation)
            );
        }

        private static async Task<JObject> ActiveWithoutBrowserCopy(SamlFixture fixture)
        {
            string login = fixture.Login();
            JObject issued = await fixture.Pending(login);
            // Server-side activation; the browser never stores the credential.
            fixture.Access.ActivateStored(fixture.Browser, (string)issued["emergency_credential"], login);
            return issued;
        }

        [TestMethod]
        public void StartDiscoverableLogin_NamesNoKeyAndRequiresUserVerification()
        {
            using (var fixture = new SamlFixture())
            {
                JObject options = (JObject)fixture.Access.StartDiscoverableLogin(fixture.Browser)["publicKey"];

                Assert.AreEqual(0, ((JArray)options["allowCredentials"] ?? new JArray()).Count);
                Assert.AreEqual("required", (string)options["userVerification"]);
            }
        }

        [TestMethod]
        public async Task CompleteDiscoverableLogin_RegisteredPasskey_CreatesSessionWithSnapshotClaims()
        {
            using (var fixture = new SamlFixture())
            {
                await ActiveWithoutBrowserCopy(fixture);

                JObject ticket = await Login(fixture, 1);

                var principal = fixture.Access.Authenticate((string)ticket["session"], fixture.Browser);
                Assert.IsNotNull(principal);
                Assert.AreEqual("emergency-possession", principal.FindFirst("local_assurance").Value);
            }
        }

        [TestMethod]
        public async Task CompleteDiscoverableLogin_UsesNewestActiveCredentialAfterRenewal()
        {
            using (var fixture = new SamlFixture())
            {
                JObject first = await ActiveWithoutBrowserCopy(fixture);
                fixture.Time = fixture.Time.AddMinutes(5);
                string login = fixture.Login();
                JObject renewed = await fixture.Access.Renew(login, fixture.Browser, fixture.Binding, CancellationToken.None);
                fixture.Access.ActivateStored(fixture.Browser, (string)renewed["emergency_credential"], login);

                JObject ticket = await Login(fixture, 1);

                Assert.IsNotNull(fixture.Access.Authenticate((string)ticket["session"], fixture.Browser));
                Assert.IsFalse(fixture.Access.IsActiveForLogin((string)first["emergency_credential"]));
                Assert.IsTrue(fixture.Access.IsActiveForLogin((string)renewed["emergency_credential"]));
            }
        }

        [DataTestMethod]
        [DataRow("uv")]
        [DataRow("nohandle")]
        [DataRow("handle")]
        [DataRow("signature")]
        [DataRow("challenge")]
        [DataRow("origin")]
        public async Task CompleteDiscoverableLogin_InvalidAssertion_IsRejected(string mutation)
        {
            using (var fixture = new SamlFixture())
            {
                await ActiveWithoutBrowserCopy(fixture);

                EmergencyFailure failure = await Assert.ThrowsExactlyAsync<EmergencyFailure>(() => Login(fixture, 1, mutation));
                Assert.AreEqual("key_proof_rejected", failure.ErrorCode);
            }
        }

        [TestMethod]
        public async Task CompleteDiscoverableLogin_UnknownPasskey_IsRejected()
        {
            using (var fixture = new SamlFixture())
            {
                EmergencyFailure failure = await Assert.ThrowsExactlyAsync<EmergencyFailure>(() => Login(fixture, 1));
                Assert.AreEqual("credential_unavailable", failure.ErrorCode);
            }
        }

        [TestMethod]
        public async Task CompleteDiscoverableLogin_PendingCredential_IsRejected()
        {
            using (var fixture = new SamlFixture())
            {
                await fixture.Pending(fixture.Login());

                EmergencyFailure failure = await Assert.ThrowsExactlyAsync<EmergencyFailure>(() => Login(fixture, 1));
                Assert.AreEqual("credential_unavailable", failure.ErrorCode);
            }
        }

        [TestMethod]
        public async Task CompleteDiscoverableLogin_RemovedKey_IsRejected()
        {
            using (var fixture = new SamlFixture())
            {
                await ActiveWithoutBrowserCopy(fixture);
                await fixture.Access.RemoveKey(fixture.Login(), fixture.Browser, fixture.Binding, CancellationToken.None);

                await Assert.ThrowsExactlyAsync<EmergencyFailure>(() => Login(fixture, 1));
                Assert.IsFalse(fixture.Access.IsBindingActiveForLogin(fixture.Binding));
            }
        }

        [TestMethod]
        public async Task CompleteDiscoverableLogin_ReplayedCounter_IsRejected()
        {
            using (var fixture = new SamlFixture())
            {
                await ActiveWithoutBrowserCopy(fixture);
                await Login(fixture, 5);

                await Assert.ThrowsExactlyAsync<EmergencyFailure>(() => Login(fixture, 5));
            }
        }

        [TestMethod]
        public async Task CompleteDiscoverableLogin_ChallengeIsOneTimeAndBrowserBound()
        {
            using (var fixture = new SamlFixture())
            {
                await ActiveWithoutBrowserCopy(fixture);
                JObject challenge = fixture.Access.StartDiscoverableLogin(fixture.Browser);
                string id = (string)challenge["transaction_id"];
                JObject assertion = fixture.Assertion((JObject)challenge["publicKey"], 1);

                EmergencyFailure other = await Assert.ThrowsExactlyAsync<EmergencyFailure>(
                    () => fixture.Access.CompleteDiscoverableLogin(Wire.RandomId(), id, assertion));
                Assert.AreEqual("proof_unavailable", other.ErrorCode);

                await fixture.Access.CompleteDiscoverableLogin(fixture.Browser, id, assertion);
                EmergencyFailure replay = await Assert.ThrowsExactlyAsync<EmergencyFailure>(
                    () => fixture.Access.CompleteDiscoverableLogin(fixture.Browser, id, assertion));
                Assert.AreEqual("proof_unavailable", replay.ErrorCode);
            }
        }

        [TestMethod]
        public async Task StartDiscoverableLogin_MarkedBinding_NamesOnlyThatActiveKey()
        {
            using (var fixture = new SamlFixture())
            {
                await ActiveWithoutBrowserCopy(fixture);

                JArray named = (JArray)fixture.Access
                    .StartDiscoverableLogin(fixture.Browser, new[] { fixture.Binding, Wire.RandomId() })["publicKey"]["allowCredentials"];

                Assert.AreEqual(1, named.Count, "unknown bindings are ignored");
                Assert.AreEqual(fixture.CredentialId, (string)named[0]["id"]);
            }
        }

        [TestMethod]
        public async Task StartDiscoverableLogin_RemovedBinding_NamesNoKey()
        {
            using (var fixture = new SamlFixture())
            {
                await ActiveWithoutBrowserCopy(fixture);
                await fixture.Access.RemoveKey(fixture.Login(), fixture.Browser, fixture.Binding, CancellationToken.None);

                JToken named = fixture.Access
                    .StartDiscoverableLogin(fixture.Browser, new[] { fixture.Binding })["publicKey"]["allowCredentials"];

                Assert.AreEqual(0, ((JArray)named ?? new JArray()).Count);
            }
        }

        [TestMethod]
        public async Task CompleteDiscoverableLogin_NamedKeyWithoutUserHandle_IsAccepted()
        {
            using (var fixture = new SamlFixture())
            {
                await ActiveWithoutBrowserCopy(fixture);
                JObject challenge = fixture.Access.StartDiscoverableLogin(fixture.Browser, new[] { fixture.Binding });

                JObject ticket = await fixture.Access.CompleteDiscoverableLogin(
                    fixture.Browser,
                    (string)challenge["transaction_id"],
                    fixture.Assertion((JObject)challenge["publicKey"], 1, "nohandle")
                );

                Assert.IsNotNull(fixture.Access.Authenticate((string)ticket["session"], fixture.Browser));
            }
        }

        [TestMethod]
        public async Task CompleteDiscoverableLogin_NamedKeyStillRequiresUserVerification()
        {
            using (var fixture = new SamlFixture())
            {
                await ActiveWithoutBrowserCopy(fixture);
                JObject challenge = fixture.Access.StartDiscoverableLogin(fixture.Browser, new[] { fixture.Binding });

                await Assert.ThrowsExactlyAsync<EmergencyFailure>(() => fixture.Access.CompleteDiscoverableLogin(
                    fixture.Browser,
                    (string)challenge["transaction_id"],
                    fixture.Assertion((JObject)challenge["publicKey"], 1, "uv")
                ));
            }
        }

        [TestMethod]
        public async Task SessionCredential_KeepsDecryptedCredentialForTheSessionBrowserOnly()
        {
            using (var fixture = new SamlFixture())
            {
                await ActiveWithoutBrowserCopy(fixture);
                string session = (string)(await Login(fixture, 1))["session"];

                JObject record = fixture.Access.SessionCredential(session, fixture.Browser);

                Assert.AreEqual(fixture.Binding, (string)record["binding_id"]);
                JObject raw = (JObject)record["raw"];
                Assert.AreEqual("RSA-OAEP", (string)raw["jwe_header"]["alg"]);
                Assert.AreEqual("ES256", (string)raw["jws_header"]["alg"]);
                Assert.AreEqual((string)record["ec_id"], (string)raw["payload"]["jti"]);
                Assert.IsNotNull(raw["payload"]["cnf"]["jwk"]);
                Assert.IsNull(fixture.Access.SessionCredential(session, Wire.RandomId()));
                Assert.IsNull(fixture.Access.SessionCredential(null, fixture.Browser));
            }
        }

        [TestMethod]
        public async Task SessionCredential_AfterRenewal_ShowsTheRenewedCredential()
        {
            using (var fixture = new SamlFixture())
            {
                JObject first = await ActiveWithoutBrowserCopy(fixture);
                fixture.Time = fixture.Time.AddMinutes(5);
                string login = fixture.Login();
                JObject renewed = await fixture.Access.Renew(login, fixture.Browser, fixture.Binding, CancellationToken.None);
                fixture.Access.ActivateStored(fixture.Browser, (string)renewed["emergency_credential"], login);

                JObject record = fixture.Access.SessionCredential((string)(await Login(fixture, 1))["session"], fixture.Browser);

                Assert.AreEqual("active", (string)record["status"]);
                Assert.AreEqual((string)record["ec_id"], (string)record["raw"]["payload"]["jti"]);
                Assert.AreNotEqual((string)first["ec_id"], (string)record["ec_id"]);
            }
        }

        [TestMethod]
        public async Task IsBindingActiveForLogin_ReflectsRegistryState()
        {
            using (var fixture = new SamlFixture())
            {
                Assert.IsFalse(fixture.Access.IsBindingActiveForLogin(fixture.Binding));
                await ActiveWithoutBrowserCopy(fixture);

                Assert.IsTrue(fixture.Access.IsBindingActiveForLogin(fixture.Binding));
                Assert.IsFalse(fixture.Access.IsBindingActiveForLogin(Wire.RandomId()));
                Assert.IsFalse(fixture.Access.IsBindingActiveForLogin(null));
            }
        }
    }
}
