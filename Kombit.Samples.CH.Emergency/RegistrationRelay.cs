namespace Kombit.Samples.CH.Emergency
{
    public sealed class RegistrationRelay
    {
        public string Id { get; set; }
        public AcceptedSamlLogin Login { get; set; }
        public long Deadline { get; set; }
    }
}
