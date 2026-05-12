using System;
using System.IdentityModel.Tokens;
using System.Text;
using System.Xml;

namespace Kombit.Samples.CH.WebsiteDemo.STS
{
    /// <summary>
    /// Parses a base64-encoded SAML 2.0 Assertion (from the bootstrapToken attribute)
    /// into a <see cref="SecurityToken"/> suitable for use as an ActAs token in a WS-Trust RST.
    /// </summary>
    public static class BootstrapTokenParser
    {
        /// <summary>
        /// Decodes a base64 SAML Assertion string and attempts full deserialisation into a
        /// <see cref="Saml2SecurityToken"/>.  Falls back to a <see cref="GenericXmlSecurityToken"/>
        /// wrapping the raw XML element when full deserialisation is not possible.
        /// </summary>
        /// <param name="base64Assertion">Base64-encoded SAML 2.0 Assertion XML.</param>
        public static SecurityToken Parse(string base64Assertion)
        {
            if (string.IsNullOrEmpty(base64Assertion))
                throw new ArgumentNullException("base64Assertion");

            byte[]  assertionBytes = Convert.FromBase64String(base64Assertion);
            string  assertionXml   = Encoding.UTF8.GetString(assertionBytes);

            var xmlDoc = new XmlDocument { PreserveWhitespace = true };
            xmlDoc.LoadXml(assertionXml);
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
                return CreateGenericXmlSecurityToken(assertionElement);
            }
        }

        private static GenericXmlSecurityToken CreateGenericXmlSecurityToken(XmlElement assertionElement)
        {
            return new GenericXmlSecurityToken(
                assertionElement,
                null,
                DateTime.UtcNow,
                DateTime.UtcNow.AddHours(8),
                null,
                null,
                null);
        }
    }
}
