#region

using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using dk.nita.saml20.config;
using Kombit.Samples.CH.Emergency;
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

        protected void Page_Load(object sender, EventArgs e)
        {
            Title = "Sign in";
            string returnUrl = Request.QueryString["ReturnUrl"];
            string suffix = IsLocalUrl(returnUrl)
                ? "&ReturnUrl=" + HttpUtility.UrlEncode(returnUrl)
                : string.Empty;
            IdentityProviders = SAML20FederationConfig
                .GetConfig()
                .Endpoints.IDPEndPoints.Select(idp => new IdentityProviderOption(
                    DisplayName(idp),
                    Address(idp.Id),
                    idp.GetIDPLoginUrl(false, false, null, null) + suffix,
                    idp.metadata != null
                ))
                .ToList();
            OfferEmergencyLogin();
        }

        private void OfferEmergencyLogin()
        {
            if (!EmergencyWeb.Enabled || EmergencyWeb.IsEmergency(Context))
            {
                return;
            }
            try
            {
                EmergencyWeb.CheckTransport(Context);
                EmergencyCsrf = EmergencyWeb.Csrf(Context);
                EmergencyAvailable = true;
            }
            catch (EmergencyFailure)
            {
                // Wrong host or support unavailable: normal login stays the only option.
            }
            catch (Exception exception)
                when (!(exception is System.Threading.ThreadAbortException))
            {
                EmergencyDiagnostics.Log(Context, 503, "login_options_unavailable", exception);
            }
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

        private static bool IsLocalUrl(string url)
        {
            return !string.IsNullOrEmpty(url)
                && url.StartsWith("/", StringComparison.Ordinal)
                && !url.StartsWith("//", StringComparison.Ordinal)
                && !url.StartsWith("/\\", StringComparison.Ordinal);
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
