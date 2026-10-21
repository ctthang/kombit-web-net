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
        [DataTestMethod]
        [DataRow(false, false)]
        [DataRow(true, false)]
        [DataRow(false, true)]
        [DataRow(true, true)]
        public async Task Lifecycle_OfflineRestartAndAcceptance_EnforcesLocalSession(
            bool ec,
            bool preserve
        )
        {
            // Arrange
            using (SamlFixture fixture = new SamlFixture(ec))
            {
                fixture.Settings.PreserveNormalClaims = preserve;
                JObject entry = await fixture.Active();
                string op = fixture.Access.SignInOperator(fixture.OperatorSecret);
                fixture.Access.SetAcceptance(op, true, 60);
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
                Assert.AreEqual(preserve ? 2 : 0, principal.FindAll("department").Count());
                Assert.AreEqual(
                    preserve ? "Synthetic User" : "Prepared user",
                    principal.Identity.Name
                );
                Assert.IsNotNull(principal);
                Assert.IsFalse(principal.IsInRole("case-admin"));
                Assert.IsFalse(principal.Claims.Any(claim => claim.Value == "normal-evidence"));
                Assert.AreEqual(calls, fixture.Calls);
                Assert.IsNull(principal.FindFirst("acr"));
                Assert.IsNull(principal.FindFirst("access_token"));
                CollectionAssert.AreEquivalent(
                    new[] { "read-only" },
                    principal.FindAll("role").Select(claim => claim.Value).ToArray()
                );
                Assert.AreEqual(
                    (string)ticket["session"],
                    principal.FindFirst("emergency_session").Value
                );
                Assert.IsNull(
                    fixture.Access.Authenticate((string)ticket["session"], "wrong-browser")
                );
                op = fixture.Access.SignInOperator(fixture.OperatorSecret);
                fixture.Access.SetAcceptance(op, false, 0);
                fixture.Access.SetAcceptance(op, true, 60);
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
        [DataRow("uv")]
        [DataRow("backup")]
        [DataRow("backedUp")]
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
                fixture.Access.SetAcceptance(
                    fixture.Access.SignInOperator(fixture.OperatorSecret),
                    true,
                    60
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
                fixture.Access.SetAcceptance(
                    fixture.Access.SignInOperator(fixture.OperatorSecret),
                    true,
                    60
                );
                JObject a = fixture.Access.StartProof(
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

        [TestMethod]
        public async Task Remove_Offline_PersistsBlockAndRemovalQueue()
        {
            // Arrange
            using (SamlFixture fixture = new SamlFixture())
            {
                JObject entry = await fixture.Active();
                string normal = fixture.Login();
                string op = fixture.Access.SignInOperator(fixture.OperatorSecret);
                fixture.Access.SetAcceptance(op, true, 60);
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
                Assert.IsNull(
                    fixture.Access.Authenticate((string)ticket["session"], fixture.Browser)
                );
                Assert.AreEqual(1, (int)fixture.Access.OperatorStatus(op)["queued_removals"]);
                fixture.Restart();
                Assert.IsNull(
                    fixture.Access.Authenticate((string)ticket["session"], fixture.Browser)
                );
                fixture.Offline = false;
                op = fixture.Access.SignInOperator(fixture.OperatorSecret);
                await fixture.Access.Synchronize(op, CancellationToken.None);
                Assert.AreEqual(0, (int)fixture.Access.OperatorStatus(op)["queued_removals"]);
            }
        }

        [TestMethod]
        public async Task DisabledMarkerAndTransientEvidence_RequireExplicitActivationAndNewLogin()
        {
            // Arrange
            using (SamlFixture fixture = new SamlFixture())
            {
                JObject active = await fixture.Active();
                string normal = fixture.Login();
                fixture.Access.SetAcceptance(
                    fixture.Access.SignInOperator(fixture.OperatorSecret),
                    true,
                    60
                );
                // Act
                File.WriteAllText(
                    Path.Combine(fixture.Settings.StateDirectory, "support-disabled"),
                    "1"
                );
                fixture.Restart();
                // Assert
                Assert.IsFalse(fixture.Access.Accepting);
                Assert.IsFalse(fixture.Access.CanPrepare(normal, fixture.Browser));
                fixture.Access.SetAcceptance(
                    fixture.Access.SignInOperator(fixture.OperatorSecret),
                    true,
                    60
                );
                Assert.IsNotNull(await fixture.Prove(active, true, null, 2));
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
