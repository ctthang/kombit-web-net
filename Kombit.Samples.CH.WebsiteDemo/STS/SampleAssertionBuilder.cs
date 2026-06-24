using dk.nsi.seal;
using dk.nsi.seal.Model;
using dk.nsi.seal.Vault;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Web;

namespace Kombit.Samples.CH.WebsiteDemo.STS
{
    public static class SampleAssertionBuilder
    {
        private static OIOH2BSTSAMLAssertion BuildOIOH2BSTSAMLAssertion()
        {
            var bstBuilder = new OIOH2BSTSAMLAssertionBuilder();
            bstBuilder.SigningAlgorithm = SealSignedXml.SigningAlgorithm.Sha256;
            bstBuilder.SigningVault = new InMemoryCredentialVault(Utils.GetCertificateByThumbprint(ConfigurationManager.AppSettings["sisoRequestSigningCertificate"]));
            bstBuilder.Issuer = "https://i-seb.dkseb.dk/runtime/";
            bstBuilder.Audience = "https://sts.sosi.dk/";
            bstBuilder.NameId = "C=DK, OID.2.5.4.97=NTRDK-33257872, O=Sundhedsdatastyrelsen, SERIALNUMBER=UI:DK-O:G:4ebe6630-e2ee-483e-9a46-71caff105239, CN=signing-i-seb.dkseb.dk";
            bstBuilder.HolderOfKeyCertificate = Utils.GetCertificateByThumbprint(ConfigurationManager.AppSettings["sisoRequestSigningCertificate"]);
            bstBuilder.NotOnOrAfter = DateTime.UtcNow.AddHours(8);
            bstBuilder.Cvr = "33257872";
            bstBuilder.Uuid = "4ebe6630-e2ee-483e-9a46-71caff105239";
            bstBuilder.OrganizationName = "Sundhedsdatastyrelsen";
            bstBuilder.SigningAlgorithm = SealSignedXml.SigningAlgorithm.Sha256;
            bstBuilder.SetAssuranceLevel("NIST", "3");
            bstBuilder.Cpr = "0101010101";

            bstBuilder.ValidateBeforeBuild();
            OIOH2BSTSAMLAssertion assertion = bstBuilder.Build();
            return assertion;
        }

        private static OIOH3BSTSAMLAssertion BuildOIOH3BSTSAMLAssertion()
        {
            var bstBuilder = new OIOH3BSTSAMLAssertionBuilder();
            bstBuilder.SigningAlgorithm = SealSignedXml.SigningAlgorithm.Sha256;
            bstBuilder.SigningVault = new InMemoryCredentialVault(Utils.GetCertificateByThumbprint(ConfigurationManager.AppSettings["sisoRequestSigningCertificate"]));
            bstBuilder.Issuer = "https://i-seb.dkseb.dk/runtime/";
            bstBuilder.Audience = "https://sts.sosi.dk/";
            bstBuilder.NameId = "C=DK, OID.2.5.4.97=NTRDK-33257872, O=Sundhedsdatastyrelsen, SERIALNUMBER=UI:DK-O:G:4ebe6630-e2ee-483e-9a46-71caff105239, CN=signing-i-seb.dkseb.dk";
            bstBuilder.HolderOfKeyCertificate = Utils.GetCertificateByThumbprint(ConfigurationManager.AppSettings["sisoRequestSigningCertificate"]);
            bstBuilder.NotOnOrAfter = DateTime.UtcNow.AddHours(8);
            bstBuilder.Cvr = "33257872";
            bstBuilder.Uuid = "4ebe6630-e2ee-483e-9a46-71caff105239";
            bstBuilder.OrganizationName = "Sundhedsdatastyrelsen";
            bstBuilder.SigningAlgorithm = SealSignedXml.SigningAlgorithm.Sha256;
            bstBuilder.SetAssuranceLevel("NSIS", "Substantial");

            bstBuilder.ValidateBeforeBuild();

            return bstBuilder.Build();
        }
    }
}