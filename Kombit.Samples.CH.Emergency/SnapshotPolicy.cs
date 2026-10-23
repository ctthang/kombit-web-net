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
                // Preserve normal claims while reserving local session-control names.
                if (lower.StartsWith("emergency", StringComparison.Ordinal) || lower.StartsWith("local_", StringComparison.Ordinal)) { continue; }
                yield return new Claim(type, value, (string)source["value_type"]);
            }
        }
    }
}
