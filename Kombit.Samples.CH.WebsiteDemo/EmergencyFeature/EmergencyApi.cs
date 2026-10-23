using System;
using System.IO;
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
                            Wire.Fields(body, "id", "credential");
                            result = await access.FinishRegistration(
                                EmergencyWeb.NormalHandle(context),
                                browser,
                                Wire.String(body, "id", 128),
                                (JObject)body["credential"],
                                cancellation
                            );
                            break;
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
                            Wire.Fields(body, "binding_id");
                            result = await access.Renew(
                                EmergencyWeb.NormalHandle(context),
                                browser,
                                Wire.String(body, "binding_id", 128),
                                cancellation
                            );
                            break;
                        case "status":
                            Wire.Fields(body);
                            string handle = EmergencyWeb.NormalHandle(context);
                            await access.SynchronizeIfDue(cancellation);
                            result = access.Readiness(handle, browser);
                            break;
                        case "activate-options":
                            Wire.Fields(body, "emergency_credential");
                            result = access.StartProof(
                                browser,
                                Wire.String(body, "emergency_credential", 65536),
                                false,
                                EmergencyWeb.NormalHandle(context)
                            );
                            break;
                        case "activate-complete":
                            Wire.Fields(body, "transaction_id", "credential");
                            result = await access.CompleteProof(
                                browser,
                                Wire.String(body, "transaction_id", 128),
                                false,
                                (JObject)body["credential"],
                                EmergencyWeb.NormalHandle(context)
                            );
                            break;
                        case "login-options":
                            Wire.Fields(body, "emergency_credential");
                            result = access.StartProof(
                                browser,
                                Wire.String(body, "emergency_credential", 65536),
                                true,
                                null
                            );
                            break;
                        case "login-complete":
                            Wire.Fields(body, "transaction_id", "credential");
                            JObject ticket = await access.CompleteProof(
                                browser,
                                Wire.String(body, "transaction_id", 128),
                                true,
                                (JObject)body["credential"],
                                null
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
                    context.Response.Headers["X-Emergency-Issuer-Calls"] = Convert.ToBase64String(
                        Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(issuerTrace.Snapshot()))
                    );
                }
            }
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
