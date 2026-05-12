using System;

namespace Kombit.Samples.CH.WebsiteDemo.STS
{
    public class StsProcessException : Exception
    {
        public StsProcessException(string message) : base(message)
        {
        }
    }
}
