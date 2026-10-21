using System;

namespace Kombit.Samples.CH.Emergency
{
    public sealed class EmergencyFailure : Exception
    {
        public int StatusCode { get; private set; }
        public string ErrorCode { get; private set; }

        public EmergencyFailure(int status, string code)
            : base(code)
        {
            StatusCode = status;
            ErrorCode = code;
        }
    }
}
