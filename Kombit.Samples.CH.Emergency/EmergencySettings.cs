using System;
using System.IO;
using System.Linq;

namespace Kombit.Samples.CH.Emergency
{
    public sealed class EmergencySettings
    {
        public string Origin { get; set; }
        public string RpId { get; set; }
        public string EmergencyIssuer { get; set; }
        public string IssuerRuntimeUrl { get; set; }
        public string NormalSamlIssuer { get; set; }
        public string Audience { get; set; }
        public string StateDirectory { get; set; }
        public string PrivateEncryptionKeyFile { get; set; }
        public string EncryptionKeyId { get; set; }
        public string InitialSigningKeysFile { get; set; }
        public string BackendSecretVariable { get; set; } = "SAML_EMERGENCY_ISSUER_KEY";
        public int SessionMinutes { get; set; } = 480;

        public void Validate(string applicationDirectory)
        {
            Uri origin;
            if (
                !Uri.TryCreate(Origin, UriKind.Absolute, out origin)
                || origin.Scheme != "https"
                || origin.UserInfo.Length != 0
                || Origin != origin.GetLeftPart(UriPartial.Authority)
                || RpId != origin.Host
                || !Https(EmergencyIssuer)
                || !Https(IssuerRuntimeUrl)
                || !IssuerRuntimeUrl.EndsWith("/", StringComparison.Ordinal)
                || string.IsNullOrWhiteSpace(NormalSamlIssuer)
                || string.IsNullOrWhiteSpace(Audience)
                || string.IsNullOrWhiteSpace(EncryptionKeyId)
                || SessionMinutes < 1
                || SessionMinutes > 480
            )
            {
                throw new InvalidOperationException("Invalid emergency configuration.");
            }
            foreach (
                string path in new[]
                {
                    StateDirectory,
                    PrivateEncryptionKeyFile,
                    InitialSigningKeysFile,
                }
            )
            {
                CheckExternalPath(path, applicationDirectory);
            }
            Secret(BackendSecretVariable);
        }

        private static bool Https(string value)
        {
            Uri uri;
            return Uri.TryCreate(value, UriKind.Absolute, out uri)
                && uri.Scheme == "https"
                && uri.UserInfo.Length == 0
                && uri.Query.Length == 0
                && uri.Fragment.Length == 0;
        }

        public static void CheckExternalPath(string path, string applicationDirectory)
        {
            if (
                string.IsNullOrEmpty(path)
                || !Path.IsPathRooted(path)
                || path.StartsWith(@"\\", StringComparison.Ordinal)
                || path.Length < 3
                || path[1] != ':'
                || path[2] != '\\'
            )
            {
                throw new InvalidOperationException("External local storage is required.");
            }
            string full = Path.GetFullPath(path).TrimEnd('\\') + "\\";
            string application = Path.GetFullPath(applicationDirectory).TrimEnd('\\') + "\\";
            if (full.StartsWith(application, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    "Store emergency files outside the application."
                );
            }
            for (
                DirectoryInfo parent = new DirectoryInfo(Path.GetFullPath(path));
                parent != null;
                parent = parent.Parent
            )
            {
                if (
                    Directory.Exists(Path.Combine(parent.FullName, ".git"))
                    || File.Exists(Path.Combine(parent.FullName, ".git"))
                )
                {
                    throw new InvalidOperationException(
                        "Store emergency files outside source repositories."
                    );
                }
            }
        }

        public static string Secret(string variable)
        {
            string value = Environment.GetEnvironmentVariable(variable);
            if (
                value == null
                || value.Length < 32
                || value.Length > 512
                || value.Any(char.IsControl)
            )
            {
                throw new InvalidOperationException("Emergency secret is unavailable.");
            }
            return value;
        }
    }
}
