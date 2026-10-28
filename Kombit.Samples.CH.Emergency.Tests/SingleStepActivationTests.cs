using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json.Linq;

namespace Kombit.Samples.CH.Emergency.Tests
{
    [TestClass]
    public class SingleStepActivationTests
    {
        [TestMethod]
        public async Task ActivateStored_PendingCredential_IsActiveAndUsableForEmergencyLogin()
        {
            using (var fixture = new SamlFixture())
            {
                string login = fixture.Login();
                JObject entry = await fixture.Pending(login);
                string compact = (string)entry["emergency_credential"];

                JObject result = fixture.Access.ActivateStored(fixture.Browser, compact, login);

                Assert.IsTrue((bool)result["ready"]);
                Assert.IsTrue(fixture.Access.IsActiveForLogin(compact));
                Assert.AreEqual(
                    "active",
                    (string)fixture.Access.Readiness(login, fixture.Browser)["credentials"][0]["status"]
                );
                JObject ticket = await fixture.Prove(entry, true, null, 1);
                Assert.IsNotNull(fixture.Access.Authenticate((string)ticket["session"], fixture.Browser));
            }
        }

        [TestMethod]
        public async Task ActivateStored_AlreadyActive_IsRejected()
        {
            using (var fixture = new SamlFixture())
            {
                string login = fixture.Login();
                JObject entry = await fixture.Pending(login);
                string compact = (string)entry["emergency_credential"];
                fixture.Access.ActivateStored(fixture.Browser, compact, login);

                EmergencyFailure failure = Assert.ThrowsExactly<EmergencyFailure>(
                    () => fixture.Access.ActivateStored(fixture.Browser, compact, login)
                );
                Assert.AreEqual("credential_unavailable", failure.ErrorCode);
            }
        }

        [TestMethod]
        public async Task ActivateStored_DifferentAccount_IsRejected()
        {
            using (var fixture = new SamlFixture())
            {
                JObject entry = await fixture.Pending(fixture.Login());
                string other = fixture.Login("other-idp");

                EmergencyFailure failure = Assert.ThrowsExactly<EmergencyFailure>(
                    () => fixture.Access.ActivateStored(
                        fixture.Browser,
                        (string)entry["emergency_credential"],
                        other
                    )
                );
                Assert.AreEqual("account_mismatch", failure.ErrorCode);
                Assert.IsFalse(fixture.Access.IsActiveForLogin((string)entry["emergency_credential"]));
            }
        }

        [TestMethod]
        public async Task ActivateStored_WithoutNormalLogin_IsRejected()
        {
            using (var fixture = new SamlFixture())
            {
                JObject entry = await fixture.Pending(fixture.Login());

                EmergencyFailure failure = Assert.ThrowsExactly<EmergencyFailure>(
                    () => fixture.Access.ActivateStored(
                        fixture.Browser,
                        (string)entry["emergency_credential"],
                        null
                    )
                );
                Assert.AreEqual("new_normal_login_required", failure.ErrorCode);
            }
        }

        [TestMethod]
        public async Task Readiness_RenewDue_AfterHalfTheCredentialLifetime()
        {
            using (var fixture = new SamlFixture())
            {
                string login = fixture.Login();
                JObject entry = await fixture.Pending(login);
                fixture.Access.ActivateStored(fixture.Browser, (string)entry["emergency_credential"], login);
                Assert.IsFalse(
                    (bool)fixture.Access.Readiness(login, fixture.Browser)["credentials"][0]["renew_due"]
                );

                fixture.Time = DateTimeOffset.FromUnixTimeSeconds((long)entry["expires_at"] - 60);
                JObject item = (JObject)fixture.Access.Readiness(fixture.Login(), fixture.Browser)["credentials"]
                    .Single();

                Assert.IsTrue((bool)item["renew_due"]);
                Assert.AreEqual("active", (string)item["status"]);
            }
        }
    }
}
