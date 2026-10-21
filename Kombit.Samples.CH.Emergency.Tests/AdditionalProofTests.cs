using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json.Linq;

namespace Kombit.Samples.CH.Emergency.Tests
{
    [TestClass]
    public class AdditionalProofTests
    {
        [DataTestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public async Task NonDiscoverableKey_MissingOptionalUserHandle_Accepts(bool elliptic)
        {
            // Arrange
            using (SamlFixture fixture = new SamlFixture(elliptic))
            {
                string normal = fixture.Login();
                JObject issued = await fixture.Pending(normal);
                JObject challenge = fixture.Access.StartProof(
                    fixture.Browser,
                    (string)issued["emergency_credential"],
                    false,
                    normal
                );
                JObject assertion = fixture.Assertion((JObject)challenge["publicKey"], 1);
                assertion["response"]["userHandle"] = JValue.CreateNull();
                // Act
                await fixture.Access.CompleteProof(
                    fixture.Browser,
                    (string)challenge["transaction_id"],
                    false,
                    assertion,
                    normal
                );
                // Assert
                Assert.AreEqual(
                    "active",
                    (string)
                        fixture.Access.Readiness(normal, fixture.Browser)["credentials"][0][
                            "status"
                        ]
                );
            }
        }

        [TestMethod]
        public async Task BothCountersZero_FreshProofs_Accept()
        {
            // Arrange
            using (SamlFixture fixture = new SamlFixture())
            {
                string normal = fixture.Login();
                JObject issued = await fixture.Pending(normal);
                await fixture.Prove(issued, false, normal, 0);
                fixture.Access.SetAcceptance(
                    fixture.Access.SignInOperator(fixture.OperatorSecret),
                    true,
                    10
                );
                // Act and Assert
                Assert.IsNotNull(await fixture.Prove(issued, true, null, 0));
            }
        }

        [TestMethod]
        public async Task ReusedNonzeroCounter_NewChallenge_Rejects()
        {
            // Arrange
            using (SamlFixture fixture = new SamlFixture())
            {
                JObject issued = await fixture.Active();
                fixture.Access.SetAcceptance(
                    fixture.Access.SignInOperator(fixture.OperatorSecret),
                    true,
                    10
                );
                // Act and Assert
                await Assert.ThrowsExactlyAsync<EmergencyFailure>(() =>
                    fixture.Prove(issued, true, null, 1)
                );
            }
        }
    }
}
