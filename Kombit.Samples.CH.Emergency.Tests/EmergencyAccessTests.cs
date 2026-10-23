using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json.Linq;

namespace Kombit.Samples.CH.Emergency.Tests
{
    [TestClass]
    public class EmergencyAccessTests
    {
        [TestMethod]
        public void BackendKey_UsesConfiguredPocTextWithoutEnvironment()
        {
            Assert.AreEqual("poc-key", new Kombit.Samples.CH.Emergency.EmergencySettings { ApiKey = "poc-key" }.BackendKey());
        }

        [DataTestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public async Task Lifecycle_OfflineRestart_EnforcesLocalSession(bool ec)
        {
            // Arrange
            using (SamlFixture fixture = new SamlFixture(ec))
            {
                JObject entry = await fixture.Active();
                fixture.Offline = true;
                int calls = fixture.Calls;
                // Act
                fixture.Restart();
                JObject ticket = await fixture.Prove(entry, true, null, 2);
                var principal = fixture.Access.Authenticate(
                    (string)ticket["session"],
                    fixture.Browser
                );
                // Assert
                Assert.AreEqual(2, principal.FindAll("department").Count());
                Assert.AreEqual("Synthetic User", principal.Identity.Name);
                Assert.IsNotNull(principal);
                Assert.IsTrue(principal.IsInRole("case-admin"));
                Assert.IsTrue(principal.Claims.Any(claim => claim.Value == "normal-evidence"));
                Assert.AreEqual(calls, fixture.Calls);
                Assert.IsNotNull(principal.FindFirst("acr"));
                Assert.IsNotNull(principal.FindFirst("access_token"));
                CollectionAssert.AreEquivalent(
                    new[] { "case-admin", "read-only", "administrator" },
                    principal.FindAll("role").Select(claim => claim.Value).ToArray()
                );
                Assert.AreEqual(
                    "PFByaXZpbGVnZUxpc3QvPg==",
                    principal
                        .FindFirst("https://data.gov.dk/model/core/eid/privilegesIntermediate")
                        .Value
                );
                Assert.AreEqual(
                    (string)ticket["session"],
                    principal.FindFirst("emergency_session").Value
                );
                Assert.IsNull(
                    fixture.Access.Authenticate((string)ticket["session"], "wrong-browser")
                );
                fixture.Access.EndSession((string)ticket["session"]);
                Assert.IsNull(
                    fixture.Access.Authenticate((string)ticket["session"], fixture.Browser)
                );
            }
        }

        [DataTestMethod]
        [DataRow("audience")]
        [DataRow("audience-array")]
        [DataRow("issuer")]
        [DataRow("expired")]
        [DataRow("lifetime")]
        [DataRow("profile")]
        [DataRow("source")]
        [DataRow("rp")]
        [DataRow("origin")]
        [DataRow("hardware")]
        [DataRow("type")]
        [DataRow("key")]
        [DataRow("external")]
        [DataRow("critical")]
        [DataRow("none")]
        [DataRow("duplicate")]
        [DataRow("tampered")]
        public void Credential_InvalidProfile_Rejects(string mutation)
        {
            // Arrange
            using (SamlFixture fixture = new SamlFixture())
            {
                string token = (string)fixture.Issue(mutation)["emergency_credential"];
                // Act and Assert
                Assert.ThrowsExactly<EmergencyFailure>(() =>
                    fixture.Reader.Read(token, fixture.Trust, fixture.Time)
                );
            }
        }

        [DataTestMethod]
        [DataRow("up")]
        [DataRow("invalid-backup-state")]
        [DataRow("type")]
        [DataRow("challenge")]
        [DataRow("origin")]
        [DataRow("rp")]
        [DataRow("id")]
        [DataRow("handle")]
        [DataRow("signature")]
        [DataRow("crossOrigin")]
        [DataRow("topOrigin")]
        public async Task Assertion_InvalidProof_ConsumesAttempt(string mutation)
        {
            // Arrange
            using (SamlFixture fixture = new SamlFixture())
            {
                string normal = fixture.Login();
                JObject entry = await fixture.Pending(normal);
                JObject options = fixture.Access.StartProof(
                    fixture.Browser,
                    (string)entry["emergency_credential"],
                    false,
                    normal
                );
                // Act and Assert
                await Assert.ThrowsExactlyAsync<EmergencyFailure>(() =>
                    fixture.Access.CompleteProof(
                        fixture.Browser,
                        (string)options["transaction_id"],
                        false,
                        fixture.Assertion((JObject)options["publicKey"], 1, mutation),
                        normal
                    )
                );
                await Assert.ThrowsExactlyAsync<EmergencyFailure>(() =>
                    fixture.Access.CompleteProof(
                        fixture.Browser,
                        (string)options["transaction_id"],
                        false,
                        fixture.Assertion((JObject)options["publicKey"], 1),
                        normal
                    )
                );
            }
        }

        [TestMethod]
        public async Task Renewal_QualifiedSubjectAndPendingState_ProtectExistingKey()
        {
            // Arrange
            using (SamlFixture fixture = new SamlFixture())
            {
                JObject old = await fixture.Active();
                fixture.Time = fixture.Time.AddSeconds(1);
                string wrong = fixture.Login("different-issuer-qualifier");
                // Act and Assert
                await Assert.ThrowsExactlyAsync<EmergencyFailure>(() =>
                    fixture.Access.Renew(
                        wrong,
                        fixture.Browser,
                        fixture.Binding,
                        CancellationToken.None
                    )
                );
                string normal = fixture.Login();
                JObject renewal = await fixture.Access.Renew(
                    normal,
                    fixture.Browser,
                    fixture.Binding,
                    CancellationToken.None
                );
                JObject ticket = await fixture.Prove(old, true, null, 2);
                Assert.ThrowsExactly<EmergencyFailure>(() =>
                    fixture.Access.StartProof(
                        fixture.Browser,
                        (string)renewal["emergency_credential"],
                        true,
                        null
                    )
                );
                await fixture.Prove(renewal, false, normal, 3);
                Assert.IsNull(
                    fixture.Access.Authenticate((string)ticket["session"], fixture.Browser)
                );
                Assert.ThrowsExactly<EmergencyFailure>(() =>
                    fixture.Access.StartProof(
                        fixture.Browser,
                        (string)old["emergency_credential"],
                        true,
                        null
                    )
                );
                Assert.IsNotNull(await fixture.Prove(renewal, true, null, 4));
            }
        }

        [TestMethod]
        public async Task Proofs_SameRevision_OnlyFirstCommits()
        {
            // Arrange
            using (SamlFixture fixture = new SamlFixture())
            {
                JObject entry = await fixture.Active();
                JObject a =fixture.Access.StartProof(
                        fixture.Browser,
                        (string)entry["emergency_credential"],
                        true,
                        null
                    ),
                    b = fixture.Access.StartProof(
                        fixture.Browser,
                        (string)entry["emergency_credential"],
                        true,
                        null
                    );
                // Act
                await fixture.Access.CompleteProof(
                    fixture.Browser,
                    (string)a["transaction_id"],
                    true,
                    fixture.Assertion((JObject)a["publicKey"], 2),
                    null
                );
                // Assert
                await Assert.ThrowsExactlyAsync<EmergencyFailure>(() =>
                    fixture.Access.CompleteProof(
                        fixture.Browser,
                        (string)b["transaction_id"],
                        true,
                        fixture.Assertion((JObject)b["publicKey"], 3),
                        null
                    )
                );
            }
        }

        [DataTestMethod]
        [DataRow("uv")][DataRow("backup")][DataRow("backedUp")]
        public async Task PocUp_AcceptsPresenceAndValidBackupStates(string mutation)
        {
            using (var fixture = new SamlFixture())
            {
                string login = fixture.Login(); var entry = await fixture.Pending(login);
                var challenge = fixture.Access.StartProof(fixture.Browser, (string)entry["emergency_credential"], false, login);
                Assert.AreEqual("preferred", (string)challenge["publicKey"]["userVerification"]);
                await fixture.Access.CompleteProof(fixture.Browser, (string)challenge["transaction_id"], false, fixture.Assertion((JObject)challenge["publicKey"], 1, mutation), login);
                Assert.AreEqual("active", (string)fixture.Access.Readiness(login, fixture.Browser)["credentials"][0]["status"]);
            }
        }
        [TestMethod]
        public async Task Remove_Offline_PersistsDeletionAndRemovalQueue()
        {
            // Arrange
            using (SamlFixture fixture = new SamlFixture())
            {
                JObject entry = await fixture.Active();
                string normal = fixture.Login();
                JObject ticket = await fixture.Prove(entry, true, null, 2);
                fixture.Offline = true;
                // Act
                await fixture.Access.RemoveKey(
                    normal,
                    fixture.Browser,
                    fixture.Binding,
                    CancellationToken.None
                );
                // Assert
                Assert.AreEqual(0, ((JArray)fixture.Access.Readiness(normal, fixture.Browser)["credentials"]).Count);
                Assert.ThrowsExactly<Kombit.Samples.CH.Emergency.EmergencyFailure>(() => fixture.Access.StartProof(fixture.Browser, (string)entry["emergency_credential"], true, null));
                Assert.IsNull(
                    fixture.Access.Authenticate((string)ticket["session"], fixture.Browser)
                );
                fixture.Restart();
                Assert.IsNull(
                    fixture.Access.Authenticate((string)ticket["session"], fixture.Browser)
                );
                Assert.AreEqual(0, ((JArray)fixture.Access.Readiness(fixture.Login(), fixture.Browser)["credentials"]).Count);
                fixture.Offline = false;
                int calls = fixture.Calls;
                await fixture.Access.SynchronizeIfDue(CancellationToken.None);
                // Signing keys, the queued removal report, and the revocation feed.
                Assert.AreEqual(calls + 3, fixture.Calls);
                await fixture.Access.SynchronizeIfDue(CancellationToken.None);
                Assert.AreEqual(calls + 3, fixture.Calls);
            }
        }

        [TestMethod]
        public async Task DisabledMarkerAndTransientEvidence_EndSessionsAndRequireNewLogin()
        {
            // Arrange
            using (SamlFixture fixture = new SamlFixture())
            {
                JObject active = await fixture.Active();
                string normal = fixture.Login();
                JObject ticket = await fixture.Prove(active, true, null, 2);
                // Act
                File.WriteAllText(
                    Path.Combine(fixture.Settings.StateDirectory, "support-disabled"),
                    "1"
                );
                fixture.Restart();
                // Assert
                Assert.IsNull(
                    fixture.Access.Authenticate((string)ticket["session"], fixture.Browser)
                );
                Assert.IsFalse(fixture.Access.CanPrepare(normal, fixture.Browser));
                Assert.IsNotNull(await fixture.Prove(active, true, null, 3));
                normal = fixture.Login();
                fixture.Time = fixture.Time.AddSeconds(601);
                await Assert.ThrowsExactlyAsync<EmergencyFailure>(() =>
                    fixture.Access.BeginRegistration(
                        normal,
                        fixture.Browser,
                        CancellationToken.None
                    )
                );
            }
        }

        [TestMethod]
        public void ProtectedStore_SecondWriterAndMissingState_Reject()
        {
            // Arrange
            using (SamlFixture fixture = new SamlFixture())
            {
                // Act and Assert
                Assert.ThrowsExactly<IOException>(() => fixture.OpenStore());
                fixture.Access.Dispose();
                File.Delete(Path.Combine(fixture.Settings.StateDirectory, "registry.bin"));
                Assert.ThrowsExactly<InvalidOperationException>(() => fixture.OpenStore());
            }
        }
    }
}
