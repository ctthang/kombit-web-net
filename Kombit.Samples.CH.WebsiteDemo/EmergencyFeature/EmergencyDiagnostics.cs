using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Web;
using Kombit.Samples.CH.Emergency;
using log4net;
using log4net.Config;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Kombit.Samples.CH.WebsiteDemo.EmergencyFeature
{
    internal static class EmergencyDiagnostics
    {
        private static readonly object ReferenceKey = new object();
        private static readonly object Gate = new object();

        internal static string Log(
            HttpContext context,
            int status,
            string code,
            Exception exception = null,
            object[] issuerCalls = null
        )
        {
            string reference = Reference(context);
            try
            {
                ILog logger = LogManager.GetLogger(typeof(EmergencyDiagnostics));
                lock (Gate)
                {
                    if (!logger.Logger.Repository.Configured)
                        XmlConfigurator.Configure(logger.Logger.Repository);
                }
                var entry = new JObject
                {
                    ["event"] = "emergency_failure",
                    ["reference_id"] = reference,
                    ["timestamp_utc"] = DateTimeOffset.UtcNow.ToString("o"),
                    ["status"] = status,
                    ["error"] = code,
                    ["message"] = new EmergencyFailure(status, code).Message,
                    ["endpoint"] = Endpoint(context),
                    ["operation"] = Operation(context),
                    ["exceptions"] = Exceptions(exception),
                    ["issuer_calls"] = JArray.FromObject(issuerCalls ?? new object[0]),
                };
                string text = entry.ToString(Formatting.None);
                if (status >= 500)
                    logger.Error(text);
                else
                    logger.Warn(text);
            }
            catch (Exception)
            {
                // Logging failures must not interrupt authentication or replace the original error.
                try
                {
                    Trace.TraceError("Emergency diagnostic logging failed. Reference: " + reference);
                }
                catch (Exception) { }
            }
            return reference;
        }


        internal static string Reference(HttpContext context)
        {
            string reference = context == null ? null : context.Items[ReferenceKey] as string;
            if (reference == null)
            {
                reference = Guid.NewGuid().ToString("N");
                if (context != null) context.Items[ReferenceKey] = reference;
            }
            return reference;
        }
        internal static void Event(HttpContext context, string eventName, long elapsedMilliseconds = 0, object[] issuerCalls = null)
        {
            try
            {
                ILog logger = LogManager.GetLogger(typeof(EmergencyDiagnostics));
                lock (Gate) { if (!logger.Logger.Repository.Configured) XmlConfigurator.Configure(logger.Logger.Repository); }
                logger.Info(new JObject
                {
                    ["event"] = eventName, ["reference_id"] = Reference(context),
                    ["timestamp_utc"] = DateTimeOffset.UtcNow.ToString("o"),
                    ["endpoint"] = Endpoint(context), ["operation"] = Operation(context),
                    ["status"] = context == null ? 0 : context.Response.StatusCode,
                    ["elapsed_ms"] = elapsedMilliseconds,
                    ["issuer_calls"] = JArray.FromObject(issuerCalls ?? new object[0])
                }.ToString(Formatting.None));
            }
            catch (Exception) { /* Logging must not interrupt the request. */ }
        }

        private static string Endpoint(HttpContext context)
        {
            if (context == null)
                return "background";
            string file = System.IO.Path.GetFileName(context.Request.Path);
            switch (file.ToLowerInvariant())
            {
                case "emergency.aspx":
                case "emergencylogin.aspx":
                case "emergencyhome.aspx":
                case "emergencyended.aspx":
                case "emergencyapi.ashx":
                case "login.ashx":
                case "logout.ashx":
                case "mypage.aspx":
                    return file.ToLowerInvariant();
                default:
                    return "other";
            }
        }

        private static string Operation(HttpContext context)
        {
            if (context == null)
                return "none";
            string operation = context.Request.QueryString["op"];
            switch (operation)
            {
                case "normal-login":
                case "enroll":
                case "enroll-complete":
                case "enroll-cancel":
                case "renew":
                case "status":
                case "activate-options":
                case "activate-complete":
                case "login-options":
                case "login-complete":
                case "remove":
                case "logout":
                    return operation;
                default:
                    return operation == null ? "none" : "other";
            }
        }

        private static JArray Exceptions(Exception exception)
        {
            var result = new JArray();
            var pending = new Queue<Exception>();
            if (exception != null)
                pending.Enqueue(exception);
            while (pending.Count > 0 && result.Count < 8)
            {
                Exception current = pending.Dequeue();
                var frames = new JArray();
                StackFrame[] stack = new StackTrace(current, true).GetFrames();
                if (stack != null)
                {
                    for (int i = 0; i < stack.Length && i < 20; i++)
                    {
                        var method = stack[i].GetMethod();
                        frames.Add(
                            new JObject
                            {
                                ["method"] = method == null
                                    ? "unknown"
                                    : (method.DeclaringType == null ? "" : method.DeclaringType.FullName + ".")
                                        + method.Name,
                                ["line"] = stack[i].GetFileLineNumber(),
                            }
                        );
                    }
                }
                // Exception messages and Data can contain tokens, claims, or response bodies.
                result.Add(
                    new JObject
                    {
                        ["type"] = current.GetType().FullName,
                        ["hresult"] = current.HResult,
                        ["stack"] = frames,
                    }
                );
                var aggregate = current as AggregateException;
                if (aggregate != null)
                {
                    foreach (Exception inner in aggregate.InnerExceptions)
                    {
                        if (pending.Count + result.Count >= 8)
                            break;
                        pending.Enqueue(inner);
                    }
                }
                else if (current.InnerException != null)
                {
                    pending.Enqueue(current.InnerException);
                }
            }
            return result;
        }
    }
}
