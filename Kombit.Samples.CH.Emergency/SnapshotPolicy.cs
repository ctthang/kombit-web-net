using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using Newtonsoft.Json.Linq;

namespace Kombit.Samples.CH.Emergency
{
    public static class SnapshotPolicy
    {
        public static IEnumerable<Claim> Filter(JArray snapshot)
        {
            foreach (JObject source in snapshot)
            {
                string type = (string)source["type"],
                    value = (string)source["value"],
                    lower = type.ToLowerInvariant();
                if (
                    lower.StartsWith("emergency", StringComparison.Ordinal)
                    || lower.StartsWith("local_", StringComparison.Ordinal)
                    || lower.Contains("token")
                    || lower.Contains("bootstrap")
                    || lower.Contains("assurance")
                    || lower.Contains("/loa")
                    || new[]
                    {
                        "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod",
                        "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationinstant",
                        "http://schemas.microsoft.com/claims/authnmethodsreferences",
                        "http://schemas.microsoft.com/claims/authnclassreference",
                        "acr",
                        "amr",
                        "sid",
                        "sub",
                        "iss",
                        "aud",
                        "jti",
                        "iat",
                        "nbf",
                        "exp",
                        "auth_time",
                        "session_state",
                    }.Contains(lower)
                )
                {
                    continue;
                }
                yield return new Claim(type, value, (string)source["value_type"]);
            }
        }
    }
}
