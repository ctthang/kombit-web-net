#region

using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Configuration;
using System.Xml;
using dk.nita.saml20.config;
using dk.nita.saml20.protocol;

#endregion

namespace Kombit.Samples.CH.WebsiteDemo
{
    /// <summary>
    ///     The identity providers listed in the <c>&lt;IDPEndPoints&gt;</c> element of the
    ///     <c>SAML20Federation</c> section in web.config. OIOSAML also loads every file in the metadata
    ///     folder as an IdP; those extra IdPs are ignored for the sign-in page and its single-IdP rule.
    /// </summary>
    public static class ConfiguredIdentityProviders
    {
        private const string SectionName = "SAML20Federation";

        private static readonly Lazy<IList<string>> ConfiguredIds = new Lazy<IList<string>>(ReadConfiguredIds);

        /// <summary>
        ///     Configured IdPs in web.config order. Falls back to every IdP the framework knows when
        ///     the section cannot be read or lists none.
        /// </summary>
        public static IList<IDPEndPoint> All()
        {
            List<IDPEndPoint> known = SAML20FederationConfig.GetConfig().Endpoints.IDPEndPoints;
            IList<string> ids = ConfiguredIds.Value;
            if (ids.Count == 0)
            {
                return known;
            }
            List<IDPEndPoint> configured = new List<IDPEndPoint>();
            foreach (string id in ids)
            {
                IDPEndPoint match = known.FirstOrDefault(idp => string.Equals(idp.Id, id, StringComparison.Ordinal));
                if (match != null)
                {
                    configured.Add(match);
                }
            }
            return configured.Count > 0 ? configured : (IList<IDPEndPoint>)known;
        }

        /// <summary>
        ///     Sign-in URL for an IdP that keeps the caller's sign-in options (forceAuthn, isPassive,
        ///     levelOfAssurance, profile, assuranceLevel) and a local ReturnUrl.
        /// </summary>
        public static string LoginUrl(IDPEndPoint idp, HttpRequest request)
        {
            if (idp == null)
            {
                throw new ArgumentNullException(nameof(idp));
            }
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }
            string url = idp.GetIDPLoginUrl(
                IsTrue(request.QueryString[Saml20AbstractEndpointHandler.IDPForceAuthn]),
                IsTrue(request.QueryString[Saml20AbstractEndpointHandler.IDPIsPassive]),
                Optional(request.QueryString["levelOfAssurance"]),
                Optional(request.QueryString["profile"])
            );
            string assuranceLevel = request.QueryString["assuranceLevel"];
            if (!string.IsNullOrEmpty(assuranceLevel))
            {
                url += "&assuranceLevel=" + HttpUtility.UrlEncode(assuranceLevel);
            }
            string returnUrl = request.QueryString["ReturnUrl"];
            if (IsLocalUrl(returnUrl))
            {
                url += "&ReturnUrl=" + HttpUtility.UrlEncode(returnUrl);
            }
            return url;
        }

        public static bool IsTrue(string value)
        {
            bool result;
            return bool.TryParse(value, out result) && result;
        }

        private static string Optional(string value)
        {
            return string.IsNullOrEmpty(value) ? null : value;
        }

        private static bool IsLocalUrl(string url)
        {
            return !string.IsNullOrEmpty(url)
                && url.StartsWith("/", StringComparison.Ordinal)
                && !url.StartsWith("//", StringComparison.Ordinal)
                && !url.StartsWith("/\\", StringComparison.Ordinal);
        }

        // web.config changes restart the application, so reading the section once is enough.
        private static IList<string> ReadConfiguredIds()
        {
            List<string> ids = new List<string>();
            try
            {
                System.Configuration.Configuration config = WebConfigurationManager.OpenWebConfiguration("~");
                string raw = config.GetSection(SectionName)?.SectionInformation.GetRawXml();
                if (string.IsNullOrEmpty(raw))
                {
                    return ids;
                }
                XmlDocument document = new XmlDocument { XmlResolver = null };
                using (XmlReader reader = XmlReader.Create(
                    new System.IO.StringReader(raw),
                    new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null }
                ))
                {
                    document.Load(reader);
                }
                XmlNamespaceManager ns = new XmlNamespaceManager(document.NameTable);
                ns.AddNamespace("s", document.DocumentElement.NamespaceURI);
                string prefix = string.IsNullOrEmpty(document.DocumentElement.NamespaceURI) ? string.Empty : "s:";
                foreach (XmlNode node in document.SelectNodes("/" + prefix + SectionName + "/" + prefix + "IDPEndPoints/" + prefix + "add", ns))
                {
                    string id = node.Attributes?["id"]?.Value;
                    if (!string.IsNullOrEmpty(id))
                    {
                        ids.Add(id);
                    }
                }
            }
            catch (Exception exception) when (!(exception is OutOfMemoryException))
            {
                // Unreadable section: fall back to every IdP the framework knows.
                System.Diagnostics.Trace.TraceWarning("Configured IdPs could not be read: " + exception.GetType().Name);
            }
            return ids;
        }
    }
}
