#region

using dk.nita.saml20.config;
using dk.nita.saml20.identity;
using dk.nita.saml20.Logging;
using dk.nita.saml20.protocol;
using dk.nita.saml20.session;
using dk.nita.saml20.Session;
using dk.nsi.seal;
using dk.nsi.seal.Factories;
using dk.nsi.seal.Model;
using dk.nsi.seal.Vault;
using Kombit.Samples.BasicPrivilegeProfileParser;
using Kombit.Samples.CH.WebsiteDemo.STS;
using Microsoft.IdentityModel.Tokens.Saml;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web;
using System.Web.UI;
using System.Xml;
using System.Xml.Linq;

#endregion

namespace Kombit.Samples.CH.WebsiteDemo
{
    public partial class WebForm1 : Page
    {
        protected void Page_PreInit(object sender, EventArgs e)
        {
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Globalization", "CA1303:Do not pass literals as localized parameters", MessageId = "System.Web.UI.Page.set_Title(System.String)", Justification = "This is a demo project and thus localization is not necessary.")]
        protected void Page_Load(object sender, EventArgs e)
        {
            Title = "My page on SP " + SAML20FederationConfig.GetConfig().ServiceProvider.ID;

            if (Request.QueryString["action"] == "sso")
            {
                // Example of logging required by the requirements BSA6/SSO6 ("Id of internal account that is matched to SAML Assertion")
                // Since FormsAuthentication is used in this sample, the user name to log can be found in context.User.Identity.Name.
                // This user will not be set until after a new redirect, so unfortunately we cannot just log it in our LogAction.LoginAction
                AuditLogging.logEntry(Direction.IN, Operation.LOGIN, "ServiceProvider login",
                    "SP internal user id: " +
                    (Context.User.Identity.IsAuthenticated ? Context.User.Identity.Name : "(not logged in)"));
            }
        }

        protected void Btn_Relogin_Click(object sender, EventArgs e)
        {
            Response.Redirect("/login.ashx?" + Saml20SignonHandler.IDPForceAuthn + "=true&ReturnUrl=" +
                              HttpContext.Current.Request.Url.AbsolutePath);
        }

        protected void Btn_Passive_Click(object sender, EventArgs e)
        {
            Response.Redirect("/login.ashx?" + Saml20SignonHandler.IDPIsPassive + "=true&ReturnUrl=" +
                              HttpContext.Current.Request.Url.AbsolutePath);
        }

        protected void Btn_ReloginNoForceAuthn_Click(object sender, EventArgs e)
        {
            Response.Redirect("/login.ashx?ReturnUrl=" + HttpContext.Current.Request.Url.AbsolutePath);
        }

        protected void Btn_ReloginNoForceAuthnNSISAssuranceLevelLow_Click(object sender, EventArgs e)
        {
            HandleReloginNoForceAuthnAssuranceLevel("Low");
        }

        protected void Btn_ReloginNoForceAuthnNSISAssuranceLevelSubstantial_Click(object sender, EventArgs e)
        {
            HandleReloginNoForceAuthnAssuranceLevel("Substantial");
        }

        protected void Btn_ReloginNoForceAuthnNSISAssuranceLevelHigh_Click(object sender, EventArgs e)
        {
            HandleReloginNoForceAuthnAssuranceLevel("High");
        }

        private void HandleReloginNoForceAuthnAssuranceLevel(string nsisAssuranceLevel)
        {
            var session = SessionStore.CurrentSession;
            if (session != null)
            {
                SessionStore.CurrentSession[SessionConstants.RequestedAssuranceLevel] = "https://data.gov.dk/concept/core/nsis/loa/" + nsisAssuranceLevel;
            }
            Response.Redirect("/login.ashx?ReturnUrl=" + HttpContext.Current.Request.Url.AbsolutePath);
        }

        protected void Btn_GetStsToken_Click(object sender, EventArgs e)
        {
            var identity = Saml20Identity.Current;
            if (!identity.HasAttribute(Constants.BootstrapTokenClaimType))
            {
                StsTokenResult.InnerHtml = "<span style='color:red'>bootstrapToken attribute not present in the current SAML assertion.</span>";
                return;
            }

            try
            {
                string base64Assertion = identity[Constants.BootstrapTokenClaimType][0].AttributeValue[0];
                byte[] assertionBytes = Convert.FromBase64String(base64Assertion);
                string assertionXml = Encoding.UTF8.GetString(assertionBytes);

                var assertion = OIOBSTSAMLAssertionFactory.CreateOIOBSTSAMLAssertion(XElement.Parse(assertionXml));
                var vault = new InMemoryCredentialVault(GetCertificateByThumbprint(ConfigurationManager.AppSettings["sisoRequestSigningCertificate"]));
                var domBuilder = new CustomOIOBSTSAMLAssertionToIDCardRequestDOMBuilder<OIOBSTSAMLAssertion>();
                domBuilder.ItSystemName = assertion.Issuer;
                domBuilder.Audience = "https://sts.sosi.dk/";
                if (assertion.BasicPrivileges != null && assertion.BasicPrivileges.Privileges != null && assertion.BasicPrivileges.Privileges.Count > 0)
                {
                    var first = assertion.BasicPrivileges.Privileges.First();
                    var key = first.Key;
                    domBuilder.UserRole = key + ":" + first.Value.First();
                }
                domBuilder.SigningVault = vault;
                domBuilder.SigningAlgorithm = SealSignedXml.SigningAlgorithm.Sha256;
                domBuilder.SubjectNameId = assertion.SubjectNameId;
                domBuilder.SetOIOSAMLAssertion(assertion);

                var requestDoc = domBuilder.Build();
                var assertionToIdCardRequest =
                    OIOSAMLFactory.CreateOIOBSTSAMLAssertionToIDCardRequestModelBuilder().Build(requestDoc.Document);

                var stsEndpoint = ConfigurationManager.AppSettings["sosiStsForBSTTokenExchangeUrl"];
                var idCard = (UserIdCard)SealUtilities.SignIn(assertionToIdCardRequest, stsEndpoint);

                // Persist the id card in session so the service call button can use it
                Session["IdCard"] = idCard;

                StsTokenResult.InnerHtml = string.Format(
                    "<p><strong>STS issued token (raw XML):</strong></p><pre>{0}</pre>",
                    HttpUtility.HtmlEncode(idCard.Xassertion));

                // Show the service call button now that we have a valid token
                Btn_CallService.Visible = true;
                ServiceCallResult.InnerHtml = string.Empty;
            }
            catch (Exception ex)
            {
                StsTokenResult.InnerHtml = string.Format(
                    "<span style='color:red'><strong>Error calling STS:</strong> {0}</span>",
                    HttpUtility.HtmlEncode(ex.Message));
            }
        }

        private static X509Certificate2 GetCertificateByThumbprint(string thumbprint)
        {
            using (var certStore = new X509Store(StoreName.My, StoreLocation.LocalMachine))
            {
                // Try to open the store.
                certStore.Open(OpenFlags.ReadOnly);

                // Find the certificate that matches the thumbprint.
                var certCollection = certStore.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);

                if (certCollection.Count == 0)
                {
                    throw new InvalidOperationException($"The specified certificate with thumbprint {thumbprint} was not found!");
                }

                // Check to see if our certificate was added to the collection. If not return null else return certificate.
                return certCollection.Count != 1 ? null : certCollection[0];
            }
        }

        private static SecurityToken Parse(XElement assertionXml)
        {
            if (assertionXml == null)
                throw new ArgumentNullException("assertionXml");

            var xmlDoc = new XmlDocument { PreserveWhitespace = true };
            xmlDoc.LoadXml(assertionXml.ToString());
            XmlElement assertionElement = xmlDoc.DocumentElement;

            try
            {
                var handler = new Saml2SecurityTokenHandler();

                using (var reader = new XmlNodeReader(assertionElement))
                {
                    return handler.ReadToken(reader);
                }
            }
            catch (Exception ex)
            {
                Logging.Instance.Warning(ex,
                    "Saml2SecurityTokenHandler could not deserialise bootstrap assertion; " +
                    "falling back to GenericXmlSecurityToken.");
                throw ex;
            }
        }

        protected void Btn_CallService_Click(object sender, EventArgs e)
        {
            var idCard = Session["IdCard"] as UserIdCard;
            if (idCard == null)
            {
                ServiceCallResult.InnerHtml = "<span style='color:red'>No issued token in session. Please click 'Exchange BST Token for SOSI ID Card' button first.</span>";
                return;
            }
            var serviceEndpoint = ConfigurationManager.AppSettings["ntsServiceEndpoint"];
            var serviceEndpointDnsIdentity = ConfigurationManager.AppSettings["ntsServiceEndpointDnsIdentity"];
            try
            {
                string serviceAddress = serviceEndpoint;
                string endpointDnsIdentity = serviceEndpointDnsIdentity;

                string response = ServiceCaller.Invoke(Parse(idCard.Xassertion), serviceAddress, endpointDnsIdentity);

                ServiceCallResult.InnerHtml = string.Format(
                    "<p><strong style='color:green'>Service call succeeded:</strong></p><pre>{0}</pre>",
                    HttpUtility.HtmlEncode(response));
            }
            catch (Exception ex)
            {
                ServiceCallResult.InnerHtml = string.Format(
                    "<p><strong style='color:red'>Service call failed:</strong></p><pre>{0}</pre>",
                    HttpUtility.HtmlEncode(ex.ToString()));
            }
        }

        protected void Btn_Logoff_Click(object sender, EventArgs e)
        {
            // Example of logging required by the requirements SLO1 ("Id of internal account that is matched to SAML Assertion")
            // Since FormsAuthentication is used in this sample, the user name to log can be found in context.User.Identity.Name
            AuditLogging.logEntry(Direction.OUT, Operation.LOGOUTREQUEST,
                "ServiceProvider logoff requested, local user id: " + HttpContext.Current.User.Identity.Name);
            Response.Redirect("logout.ashx");
        }

        /// <summary>
        ///     Render attribute value to UI with a specific format
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        protected static string RenderAttributeValue(string name, string value)
        {
            if (name == "https://data.gov.dk/model/core/eid/privilegesIntermediate")
            {
                //Below is the code to parse bpp value and handle the role validation process
                //var decodedBpp = Encoding.UTF8.GetString(Convert.FromBase64String(value));
                var bppGroupsList = PrivilegeGroupParser.Parse(value);
                return PrivilegeGroupParser.ToJsonString(bppGroupsList);
            }

            return value;
        }

        protected static void ValidateKombitAttributeProfile(Saml20Identity current)
        {
            if (current == null)
                throw new ArgumentNullException("current");

            var profile = ConfigurationManager.AppSettings["Profile"];


            StringBuilder missingClaimTypes = new StringBuilder();

            if (!current.HasAttribute("https://data.gov.dk/model/core/specVersion"))
            {
                missingClaimTypes.Append("https://data.gov.dk/model/core/specVersion,");
            }

            if (!current.HasAttribute("https://data.gov.dk/model/core/eid/privilegesIntermediate"))
            {
                missingClaimTypes.Append("https://data.gov.dk/model/core/eid/privilegesIntermediate,");
            }

            if (!current.HasAttribute("https://data.gov.dk/concept/core/nsis/loa"))
            {
                missingClaimTypes.Append("https://data.gov.dk/concept/core/nsis/loa,");
            }

            if (profile != "KOMBIT_WITHOUT_PERSONAL_DATA" && !current.HasAttribute("https://data.gov.dk/model/core/eid/email"))
            {
                missingClaimTypes.Append("https://data.gov.dk/model/core/eid/email,");
            }

            if (!current.HasAttribute("https://data.gov.dk/model/core/eid/professional/cvr"))
            {
                missingClaimTypes.Append("https://data.gov.dk/model/core/eid/professional/cvr,");
            }

            if (!current.HasAttribute("https://data.gov.dk/model/core/eid/professional/orgName"))
            {
                missingClaimTypes.Append("https://data.gov.dk/model/core/eid/professional/orgName,");
            }

            if (!current.HasAttribute("dk:gov:saml:attribute:KombitSpecVer"))
            {
                missingClaimTypes.Append("dk:gov:saml:attribute:KombitSpecVer,");
            }

            if (missingClaimTypes.Length > 0)
            {
                var errorMessage = missingClaimTypes.ToString().TrimEnd(',');
                throw new Exception(string.Format("Saml assertion does not meet Kombit profile. It is missing following claim types: {0}", errorMessage));
            }
        }
    }
}