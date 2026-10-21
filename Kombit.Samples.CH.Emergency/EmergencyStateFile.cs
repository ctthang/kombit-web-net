using System;
using System.IO;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Kombit.Samples.CH.Emergency
{
    public sealed class EmergencyStateFile : IDisposable
    {
        private readonly FileStream owner;
        private readonly string filename;
        private readonly Func<byte[], byte[]> protect;
        private JObject current;
        private bool closed;
        private bool faulted;
        public object SyncRoot { get; private set; } = new object();
        public EmergencyStateFile(EmergencySettings settings, Func<byte[], byte[]> encrypt, Func<byte[], byte[]> decrypt, CredentialReader reader)
        {
            protect = encrypt;
            Directory.CreateDirectory(settings.StateDirectory);
            owner = new FileStream(Path.Combine(settings.StateDirectory, "exclusive.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            filename = Path.Combine(settings.StateDirectory, "registry.bin");
            string marker = Path.Combine(settings.StateDirectory, "initialized");
            try
            {
                string identity = Wire.Hash(new JArray(settings.EmergencyIssuer, settings.NormalSamlIssuer, settings.Origin, settings.RpId, settings.Audience, settings.EncryptionKeyId, reader.KeyIdentity()).ToString(Formatting.None));
                if (File.Exists(filename))
                {
                    if (new FileInfo(filename).Length > 16777216) { throw new InvalidOperationException(); }
                    current = JObject.Parse(Encoding.UTF8.GetString(decrypt(File.ReadAllBytes(filename))), new JsonLoadSettings { DuplicatePropertyNameHandling = DuplicatePropertyNameHandling.Error });
                    if ((int?)current["version"] != 1 || (string)current["identity"] != identity || !(current["keys"] is JObject) || !(current["credentials"] is JObject) || !(current["sessions"] is JObject)) { throw new InvalidOperationException(); }
                    CredentialReader.CheckTrust((string)current["trust"]);
                }
                else
                {
                    if (File.Exists(marker)) { throw new InvalidOperationException(); }
                    if (new FileInfo(settings.InitialSigningKeysFile).Length > 65536) { throw new InvalidOperationException(); }
                    string trust = File.ReadAllText(settings.InitialSigningKeysFile); CredentialReader.CheckTrust(trust);
                    current = new JObject { ["version"] = 1, ["identity"] = identity, ["trust"] = trust, ["acceptance"] = false, ["epoch"] = 0L, ["until"] = 0L,
                        ["cursor"] = 0L, ["last_sync"] = 0L, ["keys"] = new JObject(), ["credentials"] = new JObject(), ["sessions"] = new JObject(),
                        ["blocked_accounts"] = new JArray(), ["pending_removals"] = new JArray(), ["events"] = new JArray() };
                    Write(current);
                }
                string disabled = Path.Combine(settings.StateDirectory, "support-disabled");
                if (File.Exists(disabled))
                {
                    current["acceptance"] = false; current["epoch"] = (long)current["epoch"] + 1; current["sessions"] = new JObject(); Write(current); File.Delete(disabled);
                }
                File.WriteAllText(marker, "1");
            }
            catch { owner.Dispose(); throw; }
        }
        public T Inspect<T>(Func<JObject, T> read)
        {
            lock (SyncRoot) { if (closed) { throw new ObjectDisposedException(nameof(EmergencyStateFile)); } if (faulted) { throw new EmergencyFailure(503, "state_unavailable"); } return read(current); }
        }
        public T Change<T>(Func<JObject, T> apply)
        {
            lock (SyncRoot)
            {
                if (closed) { throw new ObjectDisposedException(nameof(EmergencyStateFile)); } if (faulted) { throw new EmergencyFailure(503, "state_unavailable"); }
                JObject next = (JObject)current.DeepClone();
                T result = apply(next); try { Write(next); } catch { faulted = true; throw; } current = next; return result;
            }
        }
        private void Write(JObject value)
        {
            byte[] data = protect(Encoding.UTF8.GetBytes(value.ToString(Formatting.None)));
            if (data.Length > 16777216) { throw new EmergencyFailure(503, "registry_capacity"); }
            string temporary = filename + "." + Wire.RandomId() + ".tmp";
            try
            {
                using (FileStream file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough)) { file.Write(data, 0, data.Length); file.Flush(true); }
                if (File.Exists(filename)) { File.Replace(temporary, filename, null); } else { File.Move(temporary, filename); }
            }
            finally { if (File.Exists(temporary)) { File.Delete(temporary); } }
        }
        public void Dispose() { lock (SyncRoot) { if (!closed) { closed = true; owner.Dispose(); } } }
    }
}
