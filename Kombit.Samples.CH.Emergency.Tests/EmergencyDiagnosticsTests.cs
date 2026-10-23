using System;
using System.IO;
using System.Linq;
using System.Web;
using Kombit.Samples.CH.WebsiteDemo.EmergencyFeature;
using log4net;
using log4net.Appender;
using log4net.Config;
using log4net.Core;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json.Linq;

namespace Kombit.Samples.CH.Emergency.Tests
{
    [TestClass]
    [DoNotParallelize]
    public class EmergencyDiagnosticsTests
    {
        private MemoryAppender appender;

        [TestInitialize]
        public void ConfigureLogging()
        {
            var repository = LogManager.GetRepository(typeof(EmergencyDiagnostics).Assembly);
            repository.ResetConfiguration();
            appender = new MemoryAppender();
            BasicConfigurator.Configure(repository, appender);
        }

        [TestCleanup]
        public void ResetLogging()
        {
            LogManager.GetRepository(typeof(EmergencyDiagnostics).Assembly).ResetConfiguration();
        }

        [TestMethod]
        public void LifecycleEvents_ShareFailureReferenceAndOmitQueryValues()
        {
            var context = Context();
            EmergencyDiagnostics.Event(context, "request_started");
            string reference = EmergencyDiagnostics.Log(context, 403, "normal_login_required");
            EmergencyDiagnostics.Event(context, "request_completed", 25);
            var events = appender.GetEvents();
            Assert.AreEqual(3, events.Length);
            Assert.IsTrue(events.All(e => (string)JObject.Parse(e.RenderedMessage)["reference_id"] == reference));
            Assert.AreEqual(25L, (long)JObject.Parse(events[2].RenderedMessage)["elapsed_ms"]);
            Assert.IsFalse(events.Any(e => e.RenderedMessage.Contains("private")));
        }
        private static HttpContext Context(string query = "op=enroll&secret=private-query")
        {
            return new HttpContext(
                new HttpRequest("", "https://app.invalid/EmergencyApi.ashx", query),
                new HttpResponse(new StringWriter())
            );
        }

        private static Exception Failure()
        {
            try
            {
                throw new InvalidOperationException(
                    "private-exception-message",
                    new IOException("private-inner-message")
                );
            }
            catch (Exception exception)
            {
                exception.Data["token"] = "private-data";
                return new EmergencyFailure(503, "emergency_unavailable", exception);
            }
        }

        [TestMethod]
        public void Logs_KeepReferenceAndOriginalCauseWithoutSensitiveValues()
        {
            HttpContext context = Context();
            context.Request.Cookies.Add(new HttpCookie("session", "private-cookie"));
            string reference = EmergencyDiagnostics.Log(
                context,
                503,
                "emergency_unavailable",
                Failure()
            );
            LoggingEvent entry = appender.GetEvents().Single();
            JObject json = JObject.Parse(entry.RenderedMessage);

            Assert.IsTrue(Guid.TryParseExact(reference, "N", out _));
            Assert.AreEqual(reference, (string)json["reference_id"]);
            Assert.AreEqual("emergencyapi.ashx", (string)json["endpoint"]);
            Assert.AreEqual("enroll", (string)json["operation"]);
            Assert.AreEqual(503, (int)json["status"]);
            Assert.AreEqual(Level.Error, entry.Level);
            Assert.AreEqual(3, ((JArray)json["exceptions"]).Count);
            Assert.AreEqual(
                typeof(InvalidOperationException).FullName,
                (string)json["exceptions"][1]["type"]
            );
            Assert.IsTrue(((JArray)json["exceptions"][1]["stack"]).Count > 0);
            StringAssert.Contains(entry.RenderedMessage, "EmergencyDiagnosticsTests.Failure");
            Assert.IsFalse(entry.RenderedMessage.Contains("private"));
            Assert.IsNull(entry.ExceptionObject);
        }

        [TestMethod]
        public void References_AreStablePerRequestAndDifferentAcrossRequests()
        {
            HttpContext context = Context();
            string first = EmergencyDiagnostics.Log(context, 403, "normal_login_required");
            string again = EmergencyDiagnostics.Log(context, 403, "normal_login_required");
            string other = EmergencyDiagnostics.Log(Context(), 403, "normal_login_required");

            Assert.AreEqual(first, again);
            Assert.AreNotEqual(first, other);
            Assert.IsTrue(appender.GetEvents().All(entry => entry.Level == Level.Warn));
        }

        [TestMethod]
        public void UnrecognizedRequestMetadata_IsNotLogged()
        {
            var context = new HttpContext(
                new HttpRequest("", "https://app.invalid/private-path.aspx", "op=private-operation"),
                new HttpResponse(new StringWriter())
            );
            EmergencyDiagnostics.Log(context, 400, "invalid_request");
            string text = appender.GetEvents().Single().RenderedMessage;
            JObject json = JObject.Parse(text);

            Assert.AreEqual("other", (string)json["endpoint"]);
            Assert.AreEqual("other", (string)json["operation"]);
            Assert.IsFalse(text.Contains("private"));
        }

        [TestMethod]
        public void Logs_IncludeSanitizedIssuerResults()
        {
            using (var trace = new IssuerCallTrace())
            {
                IssuerCallTrace.Record(
                    "POST",
                    "emergency/enrollments/private-binding/complete?token=private-token",
                    403,
                    12,
                    false
                );
                EmergencyDiagnostics.Log(
                    Context(),
                    502,
                    "issuer_request_failed_new_login_may_be_required",
                    Failure(),
                    trace.Snapshot()
                );
            }
            string text = appender.GetEvents().Single().RenderedMessage;
            JObject json = JObject.Parse(text);

            Assert.AreEqual(403, (int)json["issuer_calls"][0]["status"]);
            Assert.AreEqual(
                "emergency/enrollments/{id}/complete",
                (string)json["issuer_calls"][0]["endpoint"]
            );
            Assert.IsFalse(text.Contains("private"));
        }

        [TestMethod]
        public void ExceptionChains_AreBoundedAndIncludeAggregateCauses()
        {
            Exception exception = new IOException("private");
            for (int i = 0; i < 20; i++)
                exception = new InvalidOperationException("private", exception);
            EmergencyDiagnostics.Log(null, 503, "emergency_unavailable", exception);
            var aggregate = new AggregateException(
                new IOException("private"),
                new FormatException("private")
            );
            EmergencyDiagnostics.Log(null, 503, "emergency_unavailable", aggregate);
            LoggingEvent[] entries = appender.GetEvents();

            Assert.AreEqual(8, ((JArray)JObject.Parse(entries[0].RenderedMessage)["exceptions"]).Count);
            Assert.AreEqual(3, ((JArray)JObject.Parse(entries[1].RenderedMessage)["exceptions"]).Count);
            Assert.IsTrue(entries.All(entry => !entry.RenderedMessage.Contains("private")));
        }

        private sealed class BrokenPayload
        {
            public string Value
            {
                get { throw new InvalidOperationException("private-serialization-error"); }
            }
        }

        private sealed class BrokenAppender : AppenderSkeleton
        {
            protected override void Append(LoggingEvent loggingEvent)
            {
                throw new IOException("private-appender-error");
            }
        }

        [TestMethod]
        public void DiagnosticSerializationFailure_DoesNotChangeTheResponse()
        {
            HttpContext context = Context();
            context.Response.StatusCode = 403;
            string reference = EmergencyDiagnostics.Log(
                context,
                403,
                "normal_login_required",
                null,
                new object[] { new BrokenPayload() }
            );

            Assert.IsTrue(Guid.TryParseExact(reference, "N", out _));
            Assert.AreEqual(403, context.Response.StatusCode);
        }

        [TestMethod]
        public void AppenderFailure_DoesNotInterruptTheRequest()
        {
            var repository = LogManager.GetRepository(typeof(EmergencyDiagnostics).Assembly);
            repository.ResetConfiguration();
            BasicConfigurator.Configure(repository, new BrokenAppender());
            HttpContext context = Context();
            context.Response.StatusCode = 503;

            string reference = EmergencyDiagnostics.Log(context, 503, "emergency_unavailable");

            Assert.IsTrue(Guid.TryParseExact(reference, "N", out _));
            Assert.AreEqual(503, context.Response.StatusCode);
        }
    }
}
