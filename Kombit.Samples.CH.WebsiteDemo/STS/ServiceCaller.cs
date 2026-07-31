using dk.nsi.seal;
using dk.nsi.seal.dgwstypes;
using Kombit.Samples.CH.WebsiteDemo.NtsServiceReference;
using static dk.nsi.seal.MessageHeaders.IdCardMessageHeader;
using static dk.nsi.seal.MessageHeaders.XmlMessageHeader;
using System;
using System.ServiceModel;

namespace Kombit.Samples.CH.WebsiteDemo.STS
{
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
            if (idCard == null) throw new ArgumentNullException("idCard");
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
            var factory = new ChannelFactory<NtsPortType>(binding, endpointAddress);
            factory.Endpoint.EndpointBehaviors.Add(new SealEndpointBehavior());

            // DGWS header: SecurityLevel 4 = MOCES-authenticated user
            var dgwsHeader = new Header
            {
                SecurityLevel = 4,
                SecurityLevelSpecified = true,
                Linking = new Linking { MessageID = Guid.NewGuid().ToString("D") }
            };

            NtsPortType channel = factory.CreateChannel();
            try
            {
                using (new OperationContextScope((IContextChannel)channel))
                {
                    // Add the STS-signed IdCard and DGWS header into the outgoing SOAP headers.
                    // This avoids namespace mangling that occurs when they are passed as typed
                    // method arguments (see SEAL.NET troubleshooting: "Invalid ID-kort").
                    OperationContext.Current.OutgoingMessageHeaders.Add(IdCardHeader(idCard));
                    OperationContext.Current.OutgoingMessageHeaders.Add(XmlHeader(dgwsHeader));

                    invokeResponse response = channel.invoke(new invokeRequest(new invoke()));
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
                    try { comm.Close(); }
                    catch { comm.Abort(); }
                }
            }
        }
    }
}