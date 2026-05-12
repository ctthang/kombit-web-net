using Serilog;
using Serilog.Events;

namespace Kombit.Samples.CH.WebsiteDemo.STS
{
    /// <summary>
    ///     Provides a logger for STS operations.
    ///     Output goes to the Serilog static Log.Logger so the host application
    ///     can configure sinks once via Serilog configuration.
    /// </summary>
    internal static class Logging
    {
        public static readonly ILogger Instance = new LoggerConfiguration()
            .MinimumLevel.Debug()
            .WriteTo.Sink(new DiagnosticsSink())
            .CreateLogger();

        /// <summary>Forwards log events to System.Diagnostics.Trace.</summary>
        private sealed class DiagnosticsSink : Serilog.Core.ILogEventSink
        {
            public void Emit(LogEvent logEvent)
            {
                System.Diagnostics.Trace.WriteLine(
                    logEvent.RenderMessage(),
                    "STS [" + logEvent.Level + "]");

                if (logEvent.Exception != null)
                    System.Diagnostics.Trace.WriteLine(logEvent.Exception.ToString(), "STS [Exception]");
            }
        }
    }
}
