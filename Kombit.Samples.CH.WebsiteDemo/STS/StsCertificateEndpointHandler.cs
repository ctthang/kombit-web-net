using System;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Security;

namespace Kombit.Samples.CH.WebsiteDemo.STS
{
    public class StsCertificateEndpointHandler
    {
        /// <summary>
        /// Issues a security token from the STS using the configured client certificate,
        /// passing the bootstrap token as ActAs.
        /// </summary>
        public static SecurityToken GetSecurityToken(
            RequestSecurityTokenConfiguration rstConfiguration,
            SecurityToken bootstrapToken)
        {
            if (rstConfiguration == null) throw new ArgumentNullException("rstConfiguration");

            var rst = new RequestSecurityToken
            {
                AppliesTo   = new EndpointReference(rstConfiguration.AppliesTo),
                RequestType = RequestTypes.Issue,
                TokenType   = "urn:oasis:names:tc:SAML:2.0:assertion",
                KeyType     = KeyTypes.Symmetric,
                Issuer      = new EndpointReference(rstConfiguration.StsEndpointAddress.Uri.AbsoluteUri),
            };

            if (bootstrapToken != null)
                rst.ActAs = new SecurityTokenElement(bootstrapToken);

            if (rstConfiguration.ClientCertificate == null)
                throw new StsProcessException(
                    "Cannot execute negotiating token request to certificate endpoint without a client certificate.");

            try
            {
                var channel = CreateStsChannel(rstConfiguration.ClientCertificate, rstConfiguration.StsEndpointAddress);
                return channel.Issue(rst);
            }
            catch (Exception ex)
            {
                Logging.Instance.Error(ex, "There is an error responded from the WS-Trust service.");
                throw;
            }
        }

        /// <summary>
        /// Issues a security token without an ActAs token.
        /// </summary>
        public static SecurityToken GetSecurityToken(RequestSecurityTokenConfiguration rstConfiguration)
        {
            return GetSecurityToken(rstConfiguration, null);
        }

        private static IWSTrustChannelContract CreateStsChannel(
            X509Certificate2 clientCertificate,
            EndpointAddress  stsEndpointAddress)
        {
            var factory = new WSTrustChannelFactory(
                new StsCertificateEndpointBinding(),
                stsEndpointAddress);
            factory.TrustVersion = TrustVersion.WSTrust13;

            if (factory.Credentials != null)
                factory.Credentials.ClientCertificate.Certificate = clientCertificate;

            return factory.CreateChannel();
        }
    }
}
