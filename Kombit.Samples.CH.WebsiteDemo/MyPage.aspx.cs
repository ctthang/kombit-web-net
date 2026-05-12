#region

using System;
using System.Web;
using System.Web.UI;
using dk.nita.saml20.config;
using dk.nita.saml20.identity;
using dk.nita.saml20.Logging;
using dk.nita.saml20.protocol;
using dk.nita.saml20.Session;
using dk.nita.saml20.session;
using Kombit.Samples.BasicPrivilegeProfileParser;
using System.Collections.Generic;
using System.Text;
using System.Configuration;

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