#region

using System;
using System.Web;
using dk.nita.saml20.config;
using dk.nita.saml20.protocol;
using dk.nita.saml20.Session;

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
            if (NeedsLoginOptions(context))
            {
                // The framework's own chooser is shown after it has created the user's SAML
                // session; do the same, so the IdP links on the login options page find one.
                SessionStore.CreateSessionIfNotExists();
                context.Response.Cache.SetCacheability(HttpCacheability.NoCache);
                context.Response.Cache.SetNoStore();
                context.Server.Execute(LoginOptionsPage, true);
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
        ///     True only when the framework would otherwise render its own chooser: a plain GET
        ///     with no protocol message or chosen IdP, no common domain discovery, and no single,
        ///     default, or configured IdP selection.
        /// </summary>
        private bool NeedsLoginOptions(HttpContext context)
        {
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
            return RetrieveIDP(context) == null;
        }
    }
}
