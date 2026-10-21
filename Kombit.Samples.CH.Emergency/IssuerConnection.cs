using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Kombit.Samples.CH.Emergency
{
    public sealed class IssuerConnection
    {
        private readonly EmergencySettings settings;
        private readonly HttpClient client;

        public IssuerConnection(EmergencySettings configuration, HttpClient transport)
        {
            settings = configuration;
            client = transport;
        }

        public async Task<JObject> Request(
            HttpMethod method,
            string endpoint,
            JObject body,
            CancellationToken cancellation
        )
        {
            int? status = null;
            bool received = false;
            var timer = System.Diagnostics.Stopwatch.StartNew();
            try
            {
                using (
                    HttpRequestMessage request = new HttpRequestMessage(
                        method,
                        new Uri(new Uri(settings.IssuerRuntimeUrl), endpoint)
                    )
                )
                {
                    request.Headers.Add(
                        "X-Emergency-Client-Key",
                        EmergencySettings.Secret(settings.BackendSecretVariable)
                    );
                    if (body != null)
                    {
                        request.Content = new StringContent(
                            body.ToString(Formatting.None),
                            Encoding.UTF8,
                            "application/json"
                        );
                    }
                    using (
                        HttpResponseMessage response = await client
                            .SendAsync(
                                request,
                                HttpCompletionOption.ResponseHeadersRead,
                                cancellation
                            )
                            .ConfigureAwait(false)
                    )
                    {
                        status = (int)response.StatusCode;
                        if (!response.IsSuccessStatusCode)
                        {
                            throw new EmergencyFailure(
                                502,
                                "issuer_request_failed_new_login_may_be_required"
                            );
                        }
                        if (response.StatusCode == HttpStatusCode.NoContent)
                        {
                            received = true;
                            return new JObject();
                        }
                        using (
                            Stream stream = await response
                                .Content.ReadAsStreamAsync()
                                .ConfigureAwait(false)
                        )
                        using (MemoryStream bytes = new MemoryStream())
                        {
                            byte[] buffer = new byte[4096];
                            int count;
                            while (
                                (
                                    count = await stream
                                        .ReadAsync(buffer, 0, buffer.Length, cancellation)
                                        .ConfigureAwait(false)
                                ) > 0
                            )
                            {
                                if (bytes.Length + count > 131072)
                                {
                                    throw new EmergencyFailure(502, "issuer_response_rejected");
                                }
                                bytes.Write(buffer, 0, count);
                            }
                            var parsed = Wire.Object(
                                new UTF8Encoding(false, true).GetString(bytes.ToArray())
                            );
                            received = true;
                            return parsed;
                        }
                    }
                }
            }
            finally
            {
                IssuerCallTrace.Record(
                    method.Method,
                    endpoint,
                    status,
                    timer.ElapsedMilliseconds,
                    received
                );
            }
        }
    }
}
