using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Kombit.Samples.CH.Emergency.Tests
{
    [TestClass]
    public class PersistenceFailureTests
    {
        [TestMethod]
        public void StateWrite_Fails_DeniesCachedEmergencyAccess()
        {
            // Arrange
            using (SamlFixture fixture = new SamlFixture())
            {
                string operatorId = fixture.Access.SignInOperator(fixture.OperatorSecret);
                fixture.Access.SetAcceptance(operatorId, true, 60);
                using (
                    FileStream held = new FileStream(
                        Path.Combine(fixture.Settings.StateDirectory, "registry.bin"),
                        FileMode.Open,
                        FileAccess.Read,
                        FileShare.Read
                    )
                )
                {
                    // Act
                    Assert.ThrowsExactly<IOException>(() =>
                        fixture.Access.SetAcceptance(operatorId, false, 0)
                    );
                    // Assert
                    Assert.AreEqual(
                        503,
                        Assert
                            .ThrowsExactly<EmergencyFailure>(() =>
                            {
                                bool allowed = fixture.Access.Accepting;
                            })
                            .StatusCode
                    );
                }
            }
        }
    }
}
