using System.Net;
using System.ServiceModel;
using System.ServiceModel.Channels;

namespace Kombit.Samples.CH.WebsiteDemo.STS
{
    public class StsCertificateEndpointBinding : Binding
    {
        public override BindingElementCollection CreateBindingElements()
        {
            var elements = new BindingElementCollection();
            elements.Clear();
            elements.Add(CreateSecurityBindingElement());
            elements.Add(CreateMessageEncodingBindingElement());
            elements.Add(CreateTransportBindingElement());
            return elements.Clone();
        }

        private static BindingElement CreateTransportBindingElement()
        {
            return new HttpsTransportBindingElement
            {
                AuthenticationScheme     = AuthenticationSchemes.Anonymous,
                RequireClientCertificate = true,
                MaxReceivedMessageSize   = 0x200000L
            };
        }

        private static BindingElement CreateMessageEncodingBindingElement()
        {
            return new TextMessageEncodingBindingElement();
        }

        private static SecurityBindingElement CreateSecurityBindingElement()
        {
            var result = SecurityBindingElement.CreateCertificateOverTransportBindingElement();
            result.MessageSecurityVersion =
                MessageSecurityVersion
                    .WSSecurity11WSTrust13WSSecureConversation13WSSecurityPolicy12BasicSecurityProfile10;
            return result;
        }

        public override string Scheme
        {
            get
            {
                var element = CreateBindingElements().Find<TransportBindingElement>();
                return element == null ? string.Empty : element.Scheme;
            }
        }
    }
}
