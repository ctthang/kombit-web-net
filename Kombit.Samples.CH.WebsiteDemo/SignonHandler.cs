#region

using System;
using System.Collections.Generic;
using System.Web;
using dk.nita.saml20.config;
using dk.nita.saml20.protocol;
using dk.nita.saml20.Session;
using Kombit.Samples.CH.WebsiteDemo.EmergencyFeature;

#endregion

namespace Kombit.Samples.CH.WebsiteDemo
{
    /// <summary>
    ///     SAML sign-on endpoint for login.ashx. It behaves exactly like the OIOSAML
    ///     <see cref="Saml20SignonHandler" />, except that the framework's built-in
    ///     identity provider chooser is replaced by the site's own login options page.
    /// </summary>
    public class SignonHandler : Saml20SignonHandler
    {
        private const string LoginOptionsPage = "~/LoginOptions.aspx";

        private static readonly string[] ProtocolParameters =
        {
            "SAMLart",
            "SAMLResponse",
            "cidp",
            "_saml_idp",
            "r",
        };

        protected override void Handle(HttpContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }
            string redirectUrl;
            if (NeedsLoginOptions(context, out redirectUrl))
            {
                // The framework's own chooser is shown after it has created the user's SAML
                // session; do the same, so the IdP links on the login options page find one.
                SessionStore.CreateSessionIfNotExists();
                context.Response.Cache.SetCacheability(HttpCacheability.NoCache);
                context.Response.Cache.SetNoStore();
                context.Server.Execute(LoginOptionsPage, true);
                return;
            }
            if (redirectUrl != null)
            {
                // The only (or default) configured IdP: continue to it explicitly, so IdPs that exist
                // only as metadata files never bring back the framework's own chooser.
                context.Response.Redirect(redirectUrl, false);
                context.ApplicationInstance.CompleteRequest();
                return;
            }
            if (IsOutgoingSignIn(context.Request))
            {
                // The base handler writes forceAuthn/isPassive/loa options into the session before
                // it creates the session, which fails for a browser that has none yet (for example a
                // direct login.ashx?cidp=... link). Create it first, as the framework does later anyway.
                SessionStore.CreateSessionIfNotExists();
            }
            base.Handle(context);
        }

        /// <summary>
        ///     True for a request that starts a sign-in: no SAML artifact, response, or SOAP message.
        ///     Incoming protocol messages keep the framework's own session checks.
        /// </summary>
        private static bool IsOutgoingSignIn(HttpRequest request)
        {
            return string.IsNullOrEmpty(request.Params["SAMLart"])
                && string.IsNullOrEmpty(request.Params["SAMLResponse"])
                && request.Headers["SOAPAction"] == null;
        }

        /// <summary>
        ///     Key in <see cref="HttpContext.Items" /> holding the IdP the login options page continues
        ///     to automatically when this browser turns out to have no active emergency key.
        /// </summary>
        public const string AutoContinueIdpKey = "LoginOptions.AutoContinueIdp";

        /// <summary>
        ///     Decides how a plain sign-in request (GET, no protocol message, chosen IdP, or common
        ///     domain discovery) continues. Only IdPs configured in web.config count; see
        ///     <see cref="ConfiguredIdentityProviders" />. Returns true to show the login options page:
        ///     several IdPs to choose from, or a single (or default) IdP while emergency login can be
        ///     offered in this browser. Otherwise <paramref name="redirectUrl" /> is the IdP to continue
        ///     to, or null to let the framework handle the request.
        /// </summary>
        private bool NeedsLoginOptions(HttpContext context, out string redirectUrl)
        {
            redirectUrl = null;
            HttpRequest request = context.Request;
            if (!string.Equals(request.HttpMethod, "GET", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
            foreach (string name in ProtocolParameters)
            {
                if (!string.IsNullOrEmpty(request.Params[name]))
                {
                    return false;
                }
            }
            SAML20FederationConfig config = SAML20FederationConfig.GetConfig();
            if (config.CommonDomain != null && config.CommonDomain.Enabled)
            {
                return false;
            }
            IList<IDPEndPoint> configured = ConfiguredIdentityProviders.All();
            if (configured.Count == 0)
            {
                return false;
            }
            // One configured IdP, or else the framework's own choice (a default IdP, the selection
            // URL, or the selection event). Null means the user must choose.
            IDPEndPoint chosen = configured.Count == 1 ? configured[0] : RetrieveIDP(context);
            if (chosen == null)
            {
                return true;
            }
            // Explicit re-authentication (forceAuthn, passive), a user who is already signed in, and
            // a browser without emergency support go straight to the IdP, as before.
            if (
                ConfiguredIdentityProviders.IsTrue(request.QueryString[IDPForceAuthn])
                || ConfiguredIdentityProviders.IsTrue(request.QueryString[IDPIsPassive])
                || (context.User != null && context.User.Identity.IsAuthenticated)
                || EmergencyWeb.WidgetToken(context, "login_options_unavailable") == null
            )
            {
                redirectUrl = ConfiguredIdentityProviders.LoginUrl(chosen, request);
                return false;
            }
            // Show the page: its script reveals the emergency card for an active key, or continues
            // to the IdP when this browser has none.
            context.Items[AutoContinueIdpKey] = chosen.Id;
            return true;
        }
    }
}