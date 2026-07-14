using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Web;

namespace Kombit.Samples.CH.WebsiteDemo.STS
{
    public static class Utils
    {
        public static X509Certificate2 GetCertificateByThumbprint(string thumbprint)
        {
            using (var certStore = new X509Store(StoreName.My, StoreLocation.LocalMachine))
            {
                // Try to open the store.
                certStore.Open(OpenFlags.ReadOnly);

                // Find the certificate that matches the thumbprint.
                var certCollection = certStore.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);

                if (certCollection.Count == 0)
                {
                    throw new InvalidOperationException($"The specified certificate with thumbprint {thumbprint} was not found!");
                }

                // Check to see if our certificate was added to the collection. If not return null else return certificate.
                return certCollection.Count != 1 ? null : certCollection[0];
            }
        }
    }
}