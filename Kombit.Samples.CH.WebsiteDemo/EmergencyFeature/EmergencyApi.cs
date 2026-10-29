using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.SessionState;
using Kombit.Samples.CH.Emergency;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Kombit.Samples.CH.WebsiteDemo.EmergencyFeature
{
    public sealed class EmergencyApi : HttpTaskAsyncHandler, IRequiresSessionState
    {
        public override async Task ProcessRequestAsync(HttpContext context)
        {
            var requestTimer = System.Diagnostics.Stopwatch.StartNew();
            context.Response.Headers["X-Emergency-Reference"] = EmergencyDiagnostics.Reference(context);
            EmergencyDiagnostics.Event(context, "request_started");
            using (var issuerTrace = new IssuerCallTrace())
            {
                EmergencyWeb.Headers(context);
                try
                {
                    EmergencyWeb.CheckTransport(context);
                    if (context.Request.HttpMethod != "POST")
                    {
                        context.Response.Headers["Allow"] = "POST";
                        throw new EmergencyFailure(405, "method_not_allowed");
                    }
                    if (context.Request.ContentLength > 70000)
                    {
                        throw new EmergencyFailure(413, "request_too_large");
                    }
                    EmergencyAccess access = EmergencyWeb.Service;
                    access.CheckRate(context.Request.UserHostAddress);
                    string operation = context.Request.QueryString["op"];
                    EmergencyWeb.CheckCsrf(context, operation == "normal-login");
                    string browser = EmergencyWeb.Browser(context, false);
                    if (operation == "normal-login")
                    {
                        if (EmergencyWeb.IsEmergency(context))
                        {
                            throw new EmergencyFailure(403, "normal_login_required");
                        }
                        context.Response.Redirect(
                            VirtualPathUtility.ToAbsolute("~/login.ashx")
                                + "?ReturnUrl="
                                + Uri.EscapeDataString(
                                    VirtualPathUtility.ToAbsolute("~/Emergency.aspx")
                                ),
                            false
                        );
                        context.ApplicationInstance.CompleteRequest();
                        return;
                    }
                    JObject body = await Read(context);
                    JObject result;
                    CancellationToken cancellation = CancellationToken.None;
                    switch (operation)
                    {
                        case "enroll":
                            Wire.Fields(body);
                            result = await access.BeginRegistration(
                                EmergencyWeb.NormalHandle(context),
                                browser,
                                cancellation
                            );
                            break;
                        case "enroll-complete":
                        {
                            Wire.Fields(body, "id", "credential");
                            string normal = EmergencyWeb.NormalHandle(context);
                            JObject issued = await access.FinishRegistration(
                                normal,
                                browser,
                                Wire.String(body, "id", 128),
                                (JObject)body["credential"],
                                cancellation
                            );
                            result = Activate(access, browser, normal, issued);
                            break;
                        }
                        case "enroll-cancel":
                            Wire.Fields(body, "id");
                            await access.CancelRegistration(
                                EmergencyWeb.NormalHandle(context),
                                browser,
                                Wire.String(body, "id", 128),
                                cancellation
                            );
                            result = new JObject();
                            break;
                        case "renew":
                        {
                            Wire.Fields(body, "binding_id");
                            string normal = EmergencyWeb.NormalHandle(context);
                            JObject issued = await access.Renew(
                                normal,
                                browser,
                                Wire.String(body, "binding_id", 128),
                                cancellation
                            );
                            result = Activate(access, browser, normal, issued);
                            break;
                        }
                        case "status":
                            Wire.Fields(body);
                            string handle = EmergencyWeb.NormalHandle(context);
                            await access.SynchronizeIfDue(cancellation);
                            result = access.Readiness(handle, browser);
                            break;
                        case "login-status":
                            // Non-secret marker from this browser: is its key still usable?
                            Wire.Fields(body, "binding_id");
                            result = new JObject
                            {
                                ["active"] = access.IsBindingActiveForLogin(
                                    Wire.String(body, "binding_id", 128)
                                ),
                            };
                            break;
                        case "login-options":
                        {
                            // Optional binding IDs from this browser's marker; no credential is sent.
                            Wire.Fields(body, "binding_ids");
                            JArray marked = body["binding_ids"] as JArray;
                            if (body["binding_ids"] != null && (marked == null || marked.Count > 10))
                            {
                                throw Wire.Invalid();
                            }
                            result = access.StartDiscoverableLogin(
                                browser,
                                marked?.Select(item => item.Type == JTokenType.String ? (string)item : null)
                                    .Where(item => item != null && item.Length <= 128)
                                    .ToList()
                            );
                            break;
                        }
                        case "login-complete":
                            Wire.Fields(body, "transaction_id", "credential");
                            JObject ticket = await access.CompleteDiscoverableLogin(
                                browser,
                                Wire.String(body, "transaction_id", 128),
                                (JObject)body["credential"]
                            );
                            EmergencyWeb.IssueSession(context, (string)ticket["session"]);
                            result = new JObject
                            {
                                ["redirect"] = VirtualPathUtility.ToAbsolute(
                                    "~/EmergencyHome.aspx"
                                ),
                            };
                            break;
                        case "remove":
                            Wire.Fields(body, "binding_id");
                            await access.RemoveKey(
                                EmergencyWeb.NormalHandle(context),
                                browser,
                                Wire.String(body, "binding_id", 128),
                                cancellation
                            );
                            result = new JObject { ["removed"] = true };
                            break;
                        case "logout":
                            Wire.Fields(body);
                            EmergencyWeb.ClearEmergency(context);
                            result = new JObject
                            {
                                ["redirect"] = VirtualPathUtility.ToAbsolute(
                                    "~/EmergencyEnded.aspx"
                                ),
                            };
                            break;
                        default:
                            throw new EmergencyFailure(404, "not_found");
                    }
                    context.Response.ContentType = "application/json";
                    context.Response.Write(result.ToString(Formatting.None));
                }
                catch (EmergencyFailure failure)
                {
                    EmergencyWeb.Error(
                        context,
                        failure.StatusCode,
                        failure.ErrorCode,
                        failure,
                        issuerTrace.Snapshot()
                    );
                }
                catch (Exception exception)
                {
                    bool bad =
                        exception is JsonException
                        || exception is FormatException
                        || exception is InvalidCastException
                        || exception is OverflowException;
                    EmergencyWeb.Error(
                        context,
                        bad ? 400 : 503,
                        bad ? "invalid_request" : "emergency_unavailable",
                        exception,
                        issuerTrace.Snapshot()
                    );
                }
                finally
                {
                    EmergencyDiagnostics.Event(context, "request_completed", requestTimer.ElapsedMilliseconds, issuerTrace.Snapshot());
                    context.Response.Headers["X-Emergency-Issuer-Calls"] = Convert.ToBase64String(
                        Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(issuerTrace.Snapshot()))
                    );
                }
            }
        }

        /// <summary>
        ///     Activates a newly issued or renewed credential on the server and returns only
        ///     non-secret details. The emergency credential itself never reaches the browser; the
        ///     binding ID lets the sign-in page ask whether this browser's key is still usable.
        /// </summary>
        private static JObject Activate(EmergencyAccess access, string browser, string normal, JObject issued)
        {
            access.ActivateStored(browser, Wire.String(issued, "emergency_credential", 65536), normal);
            return new JObject
            {
                ["ready"] = true,
                ["binding_id"] = issued["binding_id"],
                ["ec_id"] = issued["ec_id"],
                ["expires_at"] = issued["expires_at"],
            };
        }

        private static async Task<JObject> Read(HttpContext context)
        {
            System.Net.Http.Headers.MediaTypeHeaderValue media;
            if (
                !System.Net.Http.Headers.MediaTypeHeaderValue.TryParse(
                    context.Request.ContentType,
                    out media
                )
                || !string.Equals(
                    media.MediaType,
                    "application/json",
                    StringComparison.OrdinalIgnoreCase
                )
                || (
                    !string.IsNullOrEmpty(media.CharSet)
                    && !string.Equals(media.CharSet, "utf-8", StringComparison.OrdinalIgnoreCase)
                )
            )
            {
                throw Wire.Invalid();
            }
            using (MemoryStream content = new MemoryStream())
            {
                byte[] buffer = new byte[4096];
                int count;
                while (
                    (count = await context.Request.InputStream.ReadAsync(buffer, 0, buffer.Length))
                    != 0
                )
                {
                    if (content.Length + count > 70000)
                    {
                        throw new EmergencyFailure(413, "request_too_large");
                    }
                    content.Write(buffer, 0, count);
                }
                return Wire.Object(new UTF8Encoding(false, true).GetString(content.ToArray()));
            }
        }
    }
}
