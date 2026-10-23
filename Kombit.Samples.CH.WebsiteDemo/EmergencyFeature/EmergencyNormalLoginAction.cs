using System;
using System.Web;
using dk.nita.saml20;
using dk.nita.saml20.Actions;
using dk.nita.saml20.config;
using dk.nita.saml20.protocol;
using dk.nita.saml20.Session;
using Kombit.Samples.CH.Emergency;

namespace Kombit.Samples.CH.WebsiteDemo.EmergencyFeature
{
    [CLSCompliant(false)]
    public sealed class EmergencyNormalLoginAction : IAction
    {
        public string Name
        {
            get { return "EmergencyNormalLogin"; }
            set { }
        }

        public void LoginAction(
            AbstractEndpointHandler handler,
            HttpContext context,
            Saml20Assertion assertion
        )
        {
            if (!EmergencyWeb.Enabled)
            {
                return;
            }
            try
            {
                SessionStore.CurrentSession[EmergencyWeb.LoginHandle] = null;
                EmergencyWeb.ClearEmergency(context);
                IDPEndPoint endpoint = SAML20FederationConfig
                    .GetConfig()
                    .FindEndPoint(assertion.Issuer);
                if (
                    endpoint == null
                    || endpoint.OmitAssertionSignatureCheck
                    || assertion.Subject == null
                    || !assertion.Assertion.IssueInstant.HasValue
                )
                {
                    return;
                }
                string browser = EmergencyWeb.Browser(context, true, true);
                AcceptedSamlLogin login = new AcceptedSamlLogin
                {
                    Browser = browser,
                    Issuer = assertion.Issuer,
                    AssertionId = assertion.Id,
                    Subject = assertion.Subject.Value,
                    Format = assertion.Subject.Format,
                    NameQualifier = assertion.Subject.NameQualifier,
                    SpNameQualifier = assertion.Subject.SPNameQualifier,
                    RecordExpires =
                        new DateTimeOffset(
                            DateTime.SpecifyKind(
                                assertion.Assertion.IssueInstant.Value,
                                DateTimeKind.Utc
                            )
                        ).ToUnixTimeSeconds() + 86400,
                };
                SessionStore.CurrentSession[EmergencyWeb.LoginHandle] =
                    EmergencyWeb.Service.RecordLogin(login);
                EmergencyDiagnostics.Event(context, "normal_login_captured");
            }
            catch (Exception exception)
            {
                EmergencyDiagnostics.Log(context, 503, "normal_login_capture_failed", exception);
            }
        }

        public void LogoutAction(
            AbstractEndpointHandler handler,
            HttpContext context,
            bool idpInitiated
        ) { }

        public void SoapLogoutAction(
            AbstractEndpointHandler handler,
            HttpContext context,
            string userId
        ) { }
    }
}
