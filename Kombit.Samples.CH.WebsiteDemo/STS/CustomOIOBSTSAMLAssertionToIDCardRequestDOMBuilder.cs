using dk.nsi.seal;
using dk.nsi.seal.Model;
using dk.nsi.seal.Model.DomBuilders;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Xml.Linq;
using static dk.nsi.seal.SealSignedXml;

namespace Kombit.Samples.CH.WebsiteDemo.STS
{
    public class CustomOIOBSTSAMLAssertionToIDCardRequestDOMBuilder<T> : OIOBSTSAMLAssertionToIDCardRequestDOMBuilder<T> where T : OIOBSTSAMLAssertion
    {
        public override XDocument Build()
        {
            XDocument xDocument = CreateDocument();
            if (SigningVault == null)
            {
                return xDocument;
            }
            return XDocument.Parse(SignSoapEnvelope(new SealSignedXml(xDocument), SigningVault.GetSystemCredentials(), SigningAlgorithm).OuterXml, LoadOptions.PreserveWhitespace);
        }

        public XmlDocument SignSoapEnvelope(SealSignedXml signedXml, X509Certificate2 cert, SigningAlgorithm signingAlgorithm)
        {
            string[] array = new string[4] { "#messageID", "#action", "#timestamp", "#body" };
            foreach (string uri in array)
            {
                Reference reference = new Reference
                {
                    Uri = uri,
                    DigestMethod = ToDigestString(signingAlgorithm)
                };
                reference.AddTransform(new XmlDsigExcC14NTransform());
                signedXml.AddReference(reference);
            }

            signedXml.SigningKey = cert.GetRSAPrivateKey();
            signedXml.SignedInfo.CanonicalizationMethod = new XmlDsigExcC14NTransform().Algorithm;
            signedXml.SignedInfo.SignatureMethod = ToSignatureString(signingAlgorithm);
            signedXml.KeyInfo = new KeyInfo();
            signedXml.KeyInfo.AddClause(new KeyInfoX509Data(cert));
            signedXml.ComputeSignature();
            XmlElement node = signedXml.GetXml();
            var xml = signedXml.xml;
            XmlElement obj = (xml.SelectSingleNode("/soap:Envelope/soap:Header/wsse:Security", MakeNsManager(xml.NameTable)) as XmlElement) ?? throw new InvalidOperationException("No Signature element found in /Envolope/Header/Security");
            obj.AppendChild(obj.OwnerDocument.ImportNode(node, deep: true));
            return xml;
        }

        internal static XmlNamespaceManager MakeNsManager(XmlNameTable nt)
        {
            XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(nt);
            foreach (KeyValuePair<string, string> item in NameSpaces.alias)
            {
                xmlNamespaceManager.AddNamespace(item.Value, item.Key);
            }

            return xmlNamespaceManager;
        }
    }
}