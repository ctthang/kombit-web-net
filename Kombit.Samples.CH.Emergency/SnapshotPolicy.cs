using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using Newtonsoft.Json.Linq;

namespace Kombit.Samples.CH.Emergency
{
    public static class SnapshotPolicy
    {
        private const string BppType = "https://data.gov.dk/model/core/eid/privilegesIntermediate";

        public static IEnumerable<Claim> Filter(JArray snapshot, EmergencySettings settings)
        {
            foreach (JObject source in snapshot)
            {
                string type = (string)source["type"],
                    value = (string)source["value"],
                    lower = type.ToLowerInvariant();
                if (
                    !settings.PreserveNormalClaims
                    && !settings.ClaimTypes.Contains(type, StringComparer.Ordinal)
                )
                {
                    continue;
                }
                if (type == BppType)
                {
                    string restricted = Privileges(value, settings);
                    if (restricted != null)
                    {
                        yield return new Claim(type, restricted);
                    }
                    continue;
                }
                if (
                    lower.StartsWith("emergency", StringComparison.Ordinal)
                    || lower.StartsWith("local_", StringComparison.Ordinal)
                    || lower.Contains("token")
                    || lower.Contains("bootstrap")
                    || lower.Contains("assurance")
                    || lower.Contains("/loa")
                    || lower.Contains("privilege")
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
                if (
                    (
                        string.Equals(type, "role", StringComparison.OrdinalIgnoreCase)
                        || string.Equals(type, ClaimTypes.Role, StringComparison.OrdinalIgnoreCase)
                    ) && !settings.Roles.Contains(value, StringComparer.Ordinal)
                )
                {
                    continue;
                }
                yield return new Claim(type, value, (string)source["value_type"]);
            }
        }

        private static string Privileges(string encoded, EmergencySettings settings)
        {
            if (settings.Privileges.Length == 0 || settings.PrivilegeScopes.Length == 0)
            {
                return null;
            }
            byte[] bytes = Convert.FromBase64String(encoded);
            if (bytes.Length > 16384)
            {
                throw Wire.Invalid();
            }
            using (
                XmlReader reader = XmlReader.Create(
                    new MemoryStream(bytes),
                    new XmlReaderSettings
                    {
                        DtdProcessing = DtdProcessing.Prohibit,
                        XmlResolver = null,
                        MaxCharactersInDocument = 16384,
                    }
                )
            )
            {
                XDocument document = XDocument.Load(reader);
                XNamespace ns = "http://itst.dk/xml/ns/2006/01/privilege";
                if (document.Root == null || document.Root.Name != ns + "PrivilegeList")
                {
                    throw Wire.Invalid();
                }
                foreach (XElement group in document.Root.Elements().ToArray())
                {
                    if (
                        group.Name != ns + "PrivilegeGroup"
                        || !settings.PrivilegeScopes.Contains(
                            (string)group.Attribute("Scope"),
                            StringComparer.Ordinal
                        )
                    )
                    {
                        group.Remove();
                        continue;
                    }
                    foreach (XElement child in group.Elements().ToArray())
                    {
                        if (child.Name == ns + "Privilege")
                        {
                            if (
                                !settings.Privileges.Contains(child.Value, StringComparer.Ordinal)
                                || child.HasElements
                            )
                            {
                                child.Remove();
                            }
                        }
                        else if (child.Name != ns + "Constraint")
                        {
                            throw Wire.Invalid();
                        }
                    }
                    if (!group.Elements(ns + "Privilege").Any())
                    {
                        group.Remove();
                    }
                }
                return document.Root.HasElements
                    ? Convert.ToBase64String(
                        Encoding.UTF8.GetBytes(document.ToString(SaveOptions.DisableFormatting))
                    )
                    : null;
            }
        }
    }
}
