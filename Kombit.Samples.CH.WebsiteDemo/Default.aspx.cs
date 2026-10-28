#region

using System;
using System.Configuration;
using System.Web.UI;
using dk.nita.saml20.config;
using dk.nita.saml20.identity;

#endregion

namespace Kombit.Samples.CH.WebsiteDemo
{
    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Microsoft.Naming",
        "CA1707:IdentifiersShouldNotContainUnderscores",
        Justification = "This class is derived from OIOSAML.Net 2.0 and thus we would like to leave this as-is."
    )]
    public partial class _Default : Page
    {
        /// <summary>
        ///     Indicates whether the certificate is incorrectly configured in web.config.
        /// </summary>
        protected bool certificateMissing;

        /// <summary>
        ///     True when the visitor has a normal SAML login session (not an emergency session).
        /// </summary>
        protected bool HasNormalSession
        {
            get
            {
                return Context.User != null
                    && Context.User.Identity.IsAuthenticated
                    && !EmergencyFeature.EmergencyWeb.IsEmergency(Context)
                    && Saml20Identity.IsInitialized();
            }
        }

        /// <summary>True when "Prepare emergency access" runs in place on this page.</summary>
        protected bool EmergencyAvailable { get; private set; }

        protected string EmergencyCsrf { get; private set; }

        protected void Page_Load(object sender, EventArgs e)
        {
            if (HasNormalSession)
            {
                EmergencyCsrf = EmergencyFeature.EmergencyWeb.WidgetToken(Context, "home_setup_unavailable");
                EmergencyAvailable = EmergencyCsrf != null;
            }
            try
            {
                FederationConfig.GetConfig().GetFirstValidCertificate();
                certificateMissing = false;
                // GetCertificate() throws an exception when the certificate can not be retrieved.
            }
            catch (ConfigurationErrorsException)
            {
                certificateMissing = true;
            }
        }
    }
}
