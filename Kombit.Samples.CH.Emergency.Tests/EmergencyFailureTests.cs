using Kombit.Samples.CH.Emergency;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Kombit.Samples.CH.Emergency.Tests
{
    [TestClass]
    public class EmergencyFailureTests
    {
        [DataTestMethod]
        [DataRow("not_found")]
        [DataRow("https_origin_required")]
        [DataRow("csrf_or_origin_rejected")]
        [DataRow("normal_login_required")]
        [DataRow("new_normal_login_required")]
        [DataRow("login_not_eligible")]
        [DataRow("login_capacity")]
        [DataRow("registration_capacity")]
        [DataRow("registration_expired")]
        [DataRow("registration_not_found")]
        [DataRow("issuer_response_rejected")]
        [DataRow("issuer_request_failed_new_login_may_be_required")]
        [DataRow("issued_credential_mismatch")]
        [DataRow("local_policy_denied")]
        [DataRow("key_conflict")]
        [DataRow("key_mismatch")]
        [DataRow("credential_already_registered")]
        [DataRow("proof_capacity")]
        [DataRow("credential_not_registered")]
        [DataRow("account_mismatch")]
        [DataRow("proof_unavailable")]
        [DataRow("proof_expired")]
        [DataRow("state_changed_retry")]
        [DataRow("replacement_superseded")]
        [DataRow("session_capacity")]
        [DataRow("credential_unavailable")]
        [DataRow("key_not_found")]
        [DataRow("key_blocked")]
        [DataRow("sync_changed")]
        [DataRow("revocation_gap")]
        [DataRow("sync_more_pages_required")]
        [DataRow("rate_limited")]
        [DataRow("credential_rejected")]
        [DataRow("state_unavailable")]
        [DataRow("registry_capacity")]
        [DataRow("key_proof_rejected")]
        [DataRow("invalid_request")]
        [DataRow("method_not_allowed")]
        [DataRow("request_too_large")]
        [DataRow("emergency_unavailable")]
        [DataRow("normal_protocol_action_unavailable")]
        public void KnownFailures_ExplainTheProblemAndPreserveTheContract(string code)
        {
            var failure = new EmergencyFailure(403, code);

            Assert.AreEqual(403, failure.StatusCode);
            Assert.AreEqual(code, failure.ErrorCode);
            Assert.IsTrue(failure.Message.Length > 80);
            Assert.AreNotEqual(code, failure.Message);
            Assert.AreNotEqual(new EmergencyFailure(403, "unknown").Message, failure.Message);
            Assert.IsNull(failure.InnerException);
        }

        [DataTestMethod]
        [DataRow("unknown_failure")]
        [DataRow("<script>alert('private-token')</script>")]
        [DataRow("")]
        [DataRow(null)]
        public void UnknownFailures_UseSafeGenericGuidance(string code)
        {
            var failure = new EmergencyFailure(503, code);

            Assert.AreEqual(503, failure.StatusCode);
            Assert.AreEqual(code, failure.ErrorCode);
            Assert.AreEqual(new EmergencyFailure(503, "unknown").Message, failure.Message);
            StringAssert.Contains(failure.Message, "Contact an administrator");
            Assert.IsFalse(failure.Message.Contains("private-token"));
            Assert.IsFalse(failure.Message.Contains("<script>"));
        }

        [TestMethod]
        public void InnerCause_IsPreservedWithoutChangingThePublicMessage()
        {
            var cause = new System.InvalidOperationException("private-token");
            var failure = new EmergencyFailure(503, "emergency_unavailable", cause);

            Assert.AreSame(cause, failure.InnerException);
            Assert.AreEqual(503, failure.StatusCode);
            Assert.AreEqual("emergency_unavailable", failure.ErrorCode);
            Assert.AreEqual(new EmergencyFailure(503, "emergency_unavailable").Message, failure.Message);
            Assert.IsFalse(failure.Message.Contains("private-token"));
        }

        [TestMethod]
        public void CommonFailures_IncludeSpecificRecoveryGuidance()
        {
            StringAssert.Contains(
                new EmergencyFailure(409, "new_normal_login_required").Message,
                "Get a new normal login"
            );
            StringAssert.Contains(
                new EmergencyFailure(403, "https_origin_required").Message,
                "reverse-proxy HTTPS configuration"
            );
            StringAssert.Contains(
                new EmergencyFailure(502, "issuer_request_failed_new_login_may_be_required").Message,
                "endpoint and actual status"
            );
            StringAssert.Contains(
                new EmergencyFailure(503, "state_unavailable").Message,
                "application-pool file permissions"
            );
            StringAssert.Contains(
                new EmergencyFailure(429, "rate_limited").Message,
                "60 seconds"
            );
            StringAssert.Contains(
                new EmergencyFailure(403, "local_policy_denied").Message,
                "10,000 credential entries"
            );
            StringAssert.Contains(
                new EmergencyFailure(403, "credential_not_registered").Message,
                "digest differs"
            );
        }
    }
}
