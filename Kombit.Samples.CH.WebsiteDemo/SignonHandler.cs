#region

using System;
using System.Web;
using dk.nita.saml20.config;
using dk.nita.saml20.protocol;

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
                context.Response.Cache.SetCacheability(HttpCacheability.NoCache);
                context.Response.Cache.SetNoStore();
                context.Server.Execute(LoginOptionsPage, true);
                return;
            }
            base.Handle(context);
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
