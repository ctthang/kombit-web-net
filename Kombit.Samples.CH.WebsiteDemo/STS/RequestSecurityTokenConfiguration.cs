using System;
using System.Collections.Generic;
using System.Configuration;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.Xml;

namespace Kombit.Samples.CH.WebsiteDemo.STS
{
    public class RequestSecurityTokenConfigurationSectionHandler : IConfigurationSectionHandler
    {
        public object Create(object parent, object configContext, XmlNode section)
        {
            var config = new RequestSecurityTokenConfiguration();
            config.LoadConfiguration(section);
            return config;
        }
    }

    public class RequestSecurityTokenConfiguration
    {
        private const string SectionName = "SecurityTokenRequest";

        public EndpointAddress StsEndpointAddress { get; private set; }
        public string StsEndpointIdentity { get; private set; }
        public X509Certificate2 StsEndpointCertificate { get; private set; }
        public string AppliesTo { get; private set; }
        public X509Certificate2 ClientCertificate { get; private set; }
        public IList<Claim> Claims { get; private set; }

        public static RequestSecurityTokenConfiguration Get()
        {
            return (RequestSecurityTokenConfiguration)ConfigurationManager.GetSection(SectionName);
        }

        public void LoadConfiguration(XmlNode section)
        {
            if (section == null) throw new ArgumentNullException("section");

            StsEndpointIdentity = GetChildElementInnerText(section, "StsEndpointIdentity", true);
            StsEndpointAddress = CreateEndpointAddress(
                GetChildElementInnerTextAsUri(section, "StsEndpointAddress", true),
                StsEndpointIdentity);

            StsEndpointCertificate = GetChildElementInnerTextAsX509Certificate(section, "StsEndpointCertificate", true);
            AppliesTo = GetChildElementInnerText(section, "AppliesTo", true);

            var clientCredentialElement = GetChildElementFromName(section, "ClientCredential", true);
            ClientCertificate = GetChildElementCertificateReferenceAsX509Certificate(clientCredentialElement);

            var claimsElement = GetChildElementFromName(section, "Claims", false);
            if (claimsElement != null)
            {
                var claimsNodeList = GetChildrenElementsFromName(claimsElement, "Claim", false);
                Claims = GetAllAdditionalClaims(claimsNodeList);
            }
        }

        private static IList<Claim> GetAllAdditionalClaims(XmlNodeList claimsNodeList)
        {
            var claims = new List<Claim>();
            if (claimsNodeList == null) return claims;
            foreach (XmlNode claimNode in claimsNodeList)
            {
                var claimElement = (XmlElement)claimNode;
                var claimType  = GetAttributeValueAsString(claimElement, "type",  true);
                var claimValue = GetAttributeValueAsString(claimElement, "value", true);
                claims.Add(new Claim(claimType, claimValue));
            }
            return claims;
        }

        private static XmlNodeList GetChildrenElementsFromName(XmlNode parentElement, string elementName, bool required)
        {
            if (parentElement == null) throw new ArgumentNullException("parentElement");
            if (elementName  == null) throw new ArgumentNullException("elementName");

            var nodes = parentElement.SelectNodes(elementName);
            if (nodes == null && required)
                throw new ApplicationException("Element must exist: " + elementName);
            return nodes;
        }

        private static XmlElement GetChildElementFromName(XmlNode parentElement, string elementName, bool required)
        {
            if (parentElement == null) throw new ArgumentNullException("parentElement");
            if (elementName  == null) throw new ArgumentNullException("elementName");

            var element = parentElement.SelectSingleNode(elementName);
            if (element == null)
            {
                if (required)
                    throw new ApplicationException("Element must exist: " + elementName);
                return null;
            }
            return (XmlElement)element;
        }

        private static string GetChildElementInnerText(XmlNode parentElement, string elementName, bool required)
        {
            var element = GetChildElementFromName(parentElement, elementName, required);
            if (element == null) return null;

            var innerText = element.InnerText;
            if (string.IsNullOrEmpty(innerText) && required)
                throw new ApplicationException("Element inner text cannot be empty: " + elementName);
            return innerText;
        }

        private static Uri GetChildElementInnerTextAsUri(XmlNode parentElement, string elementName, bool required)
        {
            var innerText = GetChildElementInnerText(parentElement, elementName, required);
            if (string.IsNullOrEmpty(innerText)) return null;

            Uri returnValue;
            if (!Uri.TryCreate(innerText, UriKind.Absolute, out returnValue))
                throw new ApplicationException("Value is not a valid Uri: " + innerText);
            return returnValue;
        }

        private static X509Certificate2 GetChildElementInnerTextAsX509Certificate(XmlNode parentElement, string elementName, bool required)
        {
            var innerText = GetChildElementInnerText(parentElement, elementName, required);
            if (string.IsNullOrEmpty(innerText)) return null;

            var bytes = Convert.FromBase64String(innerText);
            return new X509Certificate2(bytes);
        }

        private static X509Certificate2 GetChildElementCertificateReferenceAsX509Certificate(XmlElement parentElement)
        {
            var thumbprint   = GetAttributeValueAsString(parentElement, "thumbprint",    true);
            var storeLocation = GetAttributeValueAsString(parentElement, "storeLocation", true);
            var storeName    = GetAttributeValueAsString(parentElement, "storeName",     true);
            return LoadCertificate(storeName, storeLocation, thumbprint);
        }

        private static X509Certificate2 LoadCertificate(string storeName, string storeLocation, string thumbprint)
        {
            try
            {
                var _storeName     = (StoreName)    Enum.Parse(typeof(StoreName),     storeName);
                var _storeLocation = (StoreLocation)Enum.Parse(typeof(StoreLocation), storeLocation);
                var store = new X509Store(_storeName, _storeLocation);
                store.Open(OpenFlags.ReadOnly);
                return store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, true)[0];
            }
            catch (Exception ex)
            {
                Logging.Instance.Error(ex, "Cannot load client certificate.");
                return null;
            }
        }

        private static EndpointAddress CreateEndpointAddress(Uri serviceUrl, string dnsName)
        {
            return new EndpointAddress(serviceUrl, EndpointIdentity.CreateDnsIdentity(dnsName));
        }

        private static string GetAttributeValueAsString(XmlElement element, string attributeName, bool required)
        {
            if (element       == null) throw new ArgumentNullException("element");
            if (attributeName == null) throw new ArgumentNullException("attributeName");

            var attributeValue = element.GetAttribute(attributeName);
            if (string.IsNullOrEmpty(attributeValue) && required)
                throw new ApplicationException("Attribute is missing on element: " + element.Name + ". Attribute: " + attributeName);
            return attributeValue;
        }
    }
}
