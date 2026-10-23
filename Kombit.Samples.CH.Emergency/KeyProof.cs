using Fido2NetLib;

namespace Kombit.Samples.CH.Emergency
{
    public sealed class KeyProof
    {
        public string Id { get; set; }
        public string Browser { get; set; }
        public string Purpose { get; set; }
        public string Credential { get; set; }
        public string Digest { get; set; }
        public string Binding { get; set; }
        public string Authenticator { get; set; }
        public string Handle { get; set; }
        public string Cose { get; set; }
        public uint Counter { get; set; }
        public long Revision { get; set; }
        public long Deadline { get; set; }
        public AssertionOptions Options { get; set; }
    }
}
