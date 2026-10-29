#region

using System;
using System.Collections.Generic;
using System.Web;
using System.Web.UI;
using dk.nita.saml20.config;
using Kombit.Samples.CH.WebsiteDemo.EmergencyFeature;

#endregion

namespace Kombit.Samples.CH.WebsiteDemo
{
    /// <summary>
    ///     Login options shown at login.ashx when the user must choose how to sign in.
    ///     Rendered by <see cref="SignonHandler" /> in place of the OIOSAML default chooser.
    /// </summary>
    public partial class LoginOptions : Page
    {
        protected IList<IdentityProviderOption> IdentityProviders { get; private set; }

        /// <summary>True when the emergency card may be offered; the browser script reveals it only for an active key.</summary>
        protected bool EmergencyAvailable { get; private set; }

        protected string EmergencyCsrf { get; private set; }

        /// <summary>
        ///     Sign-in URL of the only (or default) IdP when the page was shown just to offer emergency
        ///     login; the browser script continues there when this browser has no active key.
        /// </summary>
        protected string AutoContinueUrl { get; private set; }

        protected void Page_Load(object sender, EventArgs e)
        {
            Title = "Sign in";
            // Only IdPs configured in web.config are offered. Each link keeps the sign-in options the
            // caller asked for, such as My Page's ForceAuthn and passive re-login buttons.
            string autoContinueIdp = Context.Items[SignonHandler.AutoContinueIdpKey] as string;
            IdentityProviders = new List<IdentityProviderOption>();
            foreach (IDPEndPoint idp in ConfiguredIdentityProviders.All())
            {
                string loginUrl = ConfiguredIdentityProviders.LoginUrl(idp, Request);
                IdentityProviders.Add(
                    new IdentityProviderOption(
                        DisplayName(idp),
                        Address(idp.Id),
                        loginUrl,
                        idp.metadata != null
                    )
                );
                if (string.Equals(idp.Id, autoContinueIdp, StringComparison.Ordinal))
                {
                    AutoContinueUrl = loginUrl;
                }
            }
            OfferEmergencyLogin();
        }



        private void OfferEmergencyLogin()
        {
            EmergencyCsrf = EmergencyWeb.WidgetToken(Context, "login_options_unavailable");
            EmergencyAvailable = EmergencyCsrf != null;
        }

        private static string DisplayName(IDPEndPoint idp)
        {
            // OIOSAML fills Name with the entity ID from metadata; only a configured friendly name is used as-is.
            if (!string.IsNullOrEmpty(idp.Name) && !string.Equals(idp.Name, idp.Id, StringComparison.Ordinal))
            {
                return idp.Name;
            }
            Uri uri;
            return Uri.TryCreate(idp.Id, UriKind.Absolute, out uri) ? uri.Host : idp.Id;
        }

        private static string Address(string id)
        {
            Uri uri;
            return Uri.TryCreate(id, UriKind.Absolute, out uri) ? id : string.Empty;
        }


        protected sealed class IdentityProviderOption
        {
            public IdentityProviderOption(string name, string address, string loginUrl, bool available)
            {
                Name = name;
                Address = address;
                LoginUrl = loginUrl;
                Available = available;
            }

            public string Name { get; private set; }
            public string Address { get; private set; }
            public string LoginUrl { get; private set; }
            public bool Available { get; private set; }
        }
    }
}
