using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Kombit.Samples.CH.Emergency
{
    public sealed class AcceptedSamlLogin
    {
        public string Handle { get; set; }
        public string Browser { get; set; }
        public string Issuer { get; set; }
        public string AssertionId { get; set; }
        public string Subject { get; set; }
        public string Format { get; set; }
        public string NameQualifier { get; set; }
        public string SpNameQualifier { get; set; }
        public long RecordExpires { get; set; }
        public long SessionExpires { get; set; }
        public bool Reserved { get; set; }
        public string AccountKey { get { return Account(Issuer, Subject, Format, NameQualifier, SpNameQualifier); } }
        public static string Account(string issuer, string subject, string format, string qualifier, string spQualifier)
        {
            return Wire.Hash(new JArray(issuer, subject, format, qualifier, spQualifier).ToString(Formatting.None));
        }
        public JObject Reference() { return new JObject { ["protocol"] = "saml", ["issuer"] = Issuer, ["token_reference"] = AssertionId }; }
    }
}
