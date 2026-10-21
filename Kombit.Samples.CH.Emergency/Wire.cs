using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Kombit.Samples.CH.Emergency
{
    public static class Wire
    {
        public static JObject Object(string text)
        {
            if (text == null || Encoding.UTF8.GetByteCount(text) > 131072) { throw Invalid(); }
            using (JsonTextReader reader = new JsonTextReader(new StringReader(text)) { MaxDepth = 24, DateParseHandling = DateParseHandling.None })
            {
                JObject result = JObject.Load(reader, new JsonLoadSettings { DuplicatePropertyNameHandling = DuplicatePropertyNameHandling.Error });
                if (reader.Read()) { throw Invalid(); }
                if (result.DescendantsAndSelf().OfType<JProperty>().Any(property => property.Name.StartsWith("$", StringComparison.Ordinal))) { throw Invalid(); }
                return result;
            }
        }
        public static void Fields(JObject value, params string[] fields)
        {
            if (value == null || value.Properties().Any(property => !fields.Contains(property.Name, StringComparer.Ordinal))) { throw Invalid(); }
        }
        public static string String(JObject value, string field, int limit = 1024)
        {
            JToken token = value == null ? null : value[field];
            if (token == null || token.Type != JTokenType.String || string.IsNullOrEmpty((string)token) || ((string)token).Length > limit || ((string)token).Any(char.IsControl)) { throw Invalid(); }
            return (string)token;
        }
        public static string NullableString(JObject value, string field)
        {
            JToken token = value[field];
            return token == null || token.Type == JTokenType.Null ? null : String(value, field);
        }
        public static long Number(JObject value, string field)
        {
            if (value[field] == null || value[field].Type != JTokenType.Integer) { throw Invalid(); }
            return (long)value[field];
        }
        public static byte[] Decode(string value, int limit = 65536)
        {
            if (string.IsNullOrEmpty(value) || value.Length > limit * 2 || value.Any(c => !(c >= 'A' && c <= 'Z') && !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '-' && c != '_')) { throw Invalid(); }
            byte[] bytes = Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - value.Length % 4) % 4));
            if (bytes.Length > limit || Encode(bytes) != value) { throw Invalid(); }
            return bytes;
        }
        public static string Encode(byte[] bytes) { return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_'); }
        public static string RandomId()
        {
            byte[] bytes = new byte[32]; using (RandomNumberGenerator random = RandomNumberGenerator.Create()) { random.GetBytes(bytes); } return Encode(bytes);
        }
        public static string Hash(string value) { using (SHA256 hash = SHA256.Create()) { return Encode(hash.ComputeHash(Encoding.UTF8.GetBytes(value))); } }
        public static bool EqualSecret(string first, string second)
        {
            if (first == null || second == null) { return false; }
            byte[] left = Decode(Hash(first)), right = Decode(Hash(second)); int difference = 0;
            for (int i = 0; i < left.Length; i++) { difference |= left[i] ^ right[i]; }
            return difference == 0;
        }
        public static EmergencyFailure Invalid() { return new EmergencyFailure(400, "invalid_request"); }
    }
}
