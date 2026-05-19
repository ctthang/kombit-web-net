using System;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Security;

namespace Kombit.Samples.CH.WebsiteDemo.STS
{
    // -------------------------------------------------------------------------
    // WCF contract derived from WSDL at:
    //   http://test1.ekstern-test.nspop.dk:8080/nts/service-01172024?wsdl
    //
    // targetNamespace : http://web.nts.nsp.nsi.dk/
    // operation       : invoke
    // soapAction      : http://nspop.dk/nts/2024/01#invoke
    // style           : document / literal
    // -------------------------------------------------------------------------

    /// <summary>Request message for the NTS <c>invoke</c> operation (empty body).</summary>
    [System.ServiceModel.MessageContract(
        WrapperName      = "invoke",
        WrapperNamespace = "http://web.nts.nsp.nsi.dk/",
        IsWrapped        = true)]
    public class NtsInvokeRequest { }

    /// <summary>Response message for the NTS <c>invoke</c> operation (empty OK body).</summary>
    [System.ServiceModel.MessageContract(
        WrapperName      = "OK",
        WrapperNamespace = "http://web.nts.nsp.nsi.dk/",
        IsWrapped        = true)]
    public class NtsInvokeResponse { }

    /// <summary>WCF service contract matching NtsPortType in the WSDL.</summary>
    [ServiceContract(Namespace = "http://web.nts.nsp.nsi.dk/")]
    public interface INtsService
    {
        [OperationContract(
            Action      = "http://nspop.dk/nts/2024/01#invoke",
            ReplyAction = "*")]
        NtsInvokeResponse Invoke(NtsInvokeRequest request);
    }

    // -------------------------------------------------------------------------

    /// <summary>
    /// Calls the NTS service endpoint using an issued security token.
    /// </summary>
    public static class ServiceCaller
    {
        /// <summary>
        /// Invokes the NTS <c>invoke</c> operation at <paramref name="serviceAddress"/>
        /// using the supplied <paramref name="issuedToken"/> as the bearer credential.
        /// </summary>
        /// <param name="issuedToken">Security token previously issued by the STS.</param>
        /// <param name="serviceAddress">Absolute URI of the service endpoint (AppliesTo).</param>
        /// <param name="endpointDnsIdentity">
        ///     DNS name in the service endpoint certificate.
        ///     Leave empty/null to skip the DNS identity check.
        /// </param>
        /// <returns>"OK" on success.</returns>
        public static string Invoke(SecurityToken issuedToken, string serviceAddress, string endpointDnsIdentity)
        {
            if (issuedToken == null)    throw new ArgumentNullException("issuedToken");
            if (serviceAddress == null) throw new ArgumentNullException("serviceAddress");

            var serviceUri = new Uri(serviceAddress);

            EndpointAddress endpointAddress = string.IsNullOrEmpty(endpointDnsIdentity)
                ? new EndpointAddress(serviceUri)
                : new EndpointAddress(serviceUri, EndpointIdentity.CreateDnsIdentity(endpointDnsIdentity));

            // WS-Federation binding: issued token carried in the WS-Security header.
            // The test endpoint uses plain HTTP, so WSFederationHttpSecurityMode.Message
            // is used (not TransportWithMessageCredential).
            var binding = new WS2007FederationHttpBinding(WSFederationHttpSecurityMode.Message);
            binding.Security.Message.EstablishSecurityContext = false;
            binding.Security.Message.IssuedKeyType            = SecurityKeyType.SymmetricKey;

            var factory = new ChannelFactory<INtsService>(binding, endpointAddress);
            factory.Credentials.SupportInteractive = false;
            factory.Credentials.ServiceCertificate.Authentication.CertificateValidationMode =
                X509CertificateValidationMode.None;
            factory.Credentials.ServiceCertificate.Authentication.RevocationMode =
                X509RevocationMode.NoCheck;

            INtsService channel = factory.CreateChannelWithIssuedToken(issuedToken);

            try
            {
                NtsInvokeResponse response = channel.Invoke(new NtsInvokeRequest());
                return response != null ? "OK" : "(empty response)";
            }
            catch (Exception ex)
            {
                Logging.Instance.Error(ex, "NTS service call failed.");
                throw;
            }
            finally
            {
                var comm = channel as ICommunicationObject;
                if (comm != null)
                {
                    try   { comm.Close(); }
                    catch { comm.Abort(); }
                }
            }
        }
    }
}
