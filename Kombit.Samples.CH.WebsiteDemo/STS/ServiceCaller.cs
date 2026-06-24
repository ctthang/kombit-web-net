using dk.nsi.seal;
using dk.nsi.seal.dgwstypes;
using static dk.nsi.seal.MessageHeaders.IdCardMessageHeader;
using static dk.nsi.seal.MessageHeaders.XmlMessageHeader;
using System;
using System.ServiceModel;
using System.ServiceModel.Channels;

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
    /// Calls the NTS service endpoint using a DGWS <see cref="IdCard"/>.
    /// </summary>
    public static class ServiceCaller
    {
        /// <summary>
        /// Invokes the NTS <c>invoke</c> operation at <paramref name="serviceAddress"/>
        /// using the supplied DGWS <paramref name="idCard"/> placed in the SOAP
        /// security header via <see cref="IdCardMessageHeader"/> and a DGWS
        /// <see cref="Header"/> via <see cref="XmlMessageHeader"/>, as required
        /// by SEAL.NET / DGWS.
        /// </summary>
        /// <param name="idCard">STS-signed IdCard from the BST token exchange.</param>
        /// <param name="serviceAddress">Absolute URI of the NTS service endpoint.</param>
        /// <param name="endpointDnsIdentity">
        ///     DNS name in the service endpoint certificate.
        ///     Leave empty/null to skip the DNS identity check.
        /// </param>
        /// <returns>"OK" on success.</returns>
        public static string Invoke(IdCard idCard, string serviceAddress, string endpointDnsIdentity)
        {
            if (idCard == null)         throw new ArgumentNullException("idCard");
            if (serviceAddress == null) throw new ArgumentNullException("serviceAddress");

            var serviceUri = new Uri(serviceAddress);

            EndpointAddress endpointAddress = string.IsNullOrEmpty(endpointDnsIdentity)
                ? new EndpointAddress(serviceUri)
                : new EndpointAddress(serviceUri, EndpointIdentity.CreateDnsIdentity(endpointDnsIdentity));

            // Use BasicHttpBinding (SOAP 1.1). Switch to Transport security for HTTPS endpoints.
            bool useHttps = serviceUri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase);
            var binding = new BasicHttpBinding(
                useHttps ? BasicHttpSecurityMode.Transport : BasicHttpSecurityMode.None);

            // SealEndpointBehavior checks the response for DGWS fault details and
            // throws a descriptive exception when errors are found.
            var factory = new ChannelFactory<INtsService>(binding, endpointAddress);
            factory.Endpoint.EndpointBehaviors.Add(new SealEndpointBehavior());

            // DGWS header: SecurityLevel 4 = MOCES-authenticated user
            var dgwsHeader = new Header
            {
                SecurityLevel          = 4,
                SecurityLevelSpecified = true,
                Linking                = new Linking { MessageID = Guid.NewGuid().ToString("D") }
            };

            INtsService channel = factory.CreateChannel();
            try
            {
                using (new OperationContextScope((IContextChannel)channel))
                {
                    // Add the STS-signed IdCard and DGWS header into the outgoing SOAP headers.
                    // This avoids namespace mangling that occurs when they are passed as typed
                    // method arguments (see SEAL.NET troubleshooting: "Invalid ID-kort").
                    OperationContext.Current.OutgoingMessageHeaders.Add(IdCardHeader(idCard));
                    OperationContext.Current.OutgoingMessageHeaders.Add(XmlHeader(dgwsHeader));

                    NtsInvokeResponse response = channel.Invoke(new NtsInvokeRequest());
                    return response != null ? "OK" : "(empty response)";
                }
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
