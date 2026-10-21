using System;
using System.Configuration;
using System.IO;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Web;
using System.Web.Configuration;
using System.Web.Security;
using dk.nita.saml20.identity;
using dk.nita.saml20.Session;
using Kombit.Samples.CH.Emergency;
using Newtonsoft.Json;

namespace Kombit.Samples.CH.WebsiteDemo.EmergencyFeature
{
    public static class EmergencyWeb
    {
        private const string BrowserCookie = "__Secure-SamlEmergencyBrowser";
        private const string SessionCookie = "__Secure-SamlEmergencySession";
        private const string OperatorCookie = "__Secure-SamlEmergencyOperator";
        public const string LoginHandle = "SamlEmergencyAcceptedLogin";
        private static readonly object Gate = new object();
        private static readonly HttpClient Backend = new HttpClient(
            new HttpClientHandler { AllowAutoRedirect = false }
        )
        {
            Timeout = TimeSpan.FromSeconds(8),
        };
        private static EmergencyAccess service;
        private static EmergencySettings settings;
        public static bool Enabled
        {
            get
            {
                return string.Equals(
                    ConfigurationManager.AppSettings["EmergencyCredential.Enabled"],
                    "true",
                    StringComparison.OrdinalIgnoreCase
                );
            }
        }

        [CLSCompliant(false)]
        public static EmergencySettings Settings
        {
            get
            {
                Ready();
                return settings;
            }
        }

        [CLSCompliant(false)]
        public static EmergencyAccess Service
        {
            get
            {
                Ready();
                return service;
            }
        }
        public static bool Accepting
        {
            get
            {
                try
                {
                    return Enabled && Service.Accepting;
                }
                catch (Exception)
                {
                    return false;
                }
            }
        }

        public static bool IsEmergency(HttpContext context)
        {
            return context.User != null
                && context.User.Identity != null
                && context.User.Identity.AuthenticationType == EmergencyAccess.AuthenticationType;
        }

        public static void Start()
        {
            if (Enabled)
            {
                return;
            }
            string directory = ConfigurationManager.AppSettings[
                "EmergencyCredential.StateDirectory"
            ];
            if (string.IsNullOrEmpty(directory))
            {
                return;
            }
            try
            {
                EmergencySettings.CheckExternalPath(directory, HttpRuntime.AppDomainAppPath);
                if (Directory.Exists(directory))
                {
                    File.WriteAllText(Path.Combine(directory, "support-disabled"), "1");
                }
            }
            catch (Exception)
            {
                System.Diagnostics.Trace.TraceWarning(
                    "Emergency disabled-state marker unavailable; local recovery required."
                );
            }
        }

        private static void Ready()
        {
            if (!Enabled)
            {
                throw new EmergencyFailure(404, "not_found");
            }
            lock (Gate)
            {
                if (service != null)
                {
                    return;
                }
                EmergencyStateFile pendingStore = null;
                try
                {
                    string file = ConfigurationManager.AppSettings[
                        "EmergencyCredential.SettingsFile"
                    ];
                    EmergencySettings.CheckExternalPath(file, HttpRuntime.AppDomainAppPath);
                    if (new FileInfo(file).Length > 65536)
                    {
                        throw new InvalidOperationException();
                    }
                    settings = Wire.Object(File.ReadAllText(file))
                        .ToObject<EmergencySettings>(
                            JsonSerializer.Create(
                                new JsonSerializerSettings
                                {
                                    TypeNameHandling = TypeNameHandling.None,
                                    MissingMemberHandling = MissingMemberHandling.Error,
                                }
                            )
                        );
                    settings.Validate(HttpRuntime.AppDomainAppPath);
                    if (
                        !string.Equals(
                            Path.GetFullPath(settings.StateDirectory),
                            Path.GetFullPath(
                                ConfigurationManager.AppSettings[
                                    "EmergencyCredential.StateDirectory"
                                ]
                            ),
                            StringComparison.OrdinalIgnoreCase
                        )
                    )
                    {
                        throw new InvalidOperationException();
                    }
                    MachineKeySection machine = (MachineKeySection)
                        WebConfigurationManager.GetSection("system.web/machineKey");
                    if (
                        machine.ValidationKey.StartsWith(
                            "AutoGenerate",
                            StringComparison.OrdinalIgnoreCase
                        )
                        || machine.DecryptionKey.StartsWith(
                            "AutoGenerate",
                            StringComparison.OrdinalIgnoreCase
                        )
                    )
                    {
                        throw new InvalidOperationException();
                    }
                    CredentialReader reader = new CredentialReader(settings);
                    string audience = settings.Audience;
                    pendingStore = new EmergencyStateFile(
                        settings,
                        bytes =>
                            MachineKey.Protect(bytes, "SamlSample.Emergency.State.v1", audience),
                        bytes =>
                            MachineKey.Unprotect(bytes, "SamlSample.Emergency.State.v1", audience),
                        reader
                    );
                    service = new EmergencyAccess(
                        settings,
                        pendingStore,
                        reader,
                        new WebAuthnChecks(settings),
                        new IssuerConnection(settings, Backend),
                        () => DateTimeOffset.UtcNow
                    );
                    pendingStore = null;
                }
                catch (Exception)
                {
                    if (pendingStore != null)
                    {
                        pendingStore.Dispose();
                    }
                    throw new EmergencyFailure(503, "emergency_unavailable");
                }
            }
        }

        public static void Stop()
        {
            lock (Gate)
            {
                if (service != null)
                {
                    service.Dispose();
                    service = null;
                }
                Backend.Dispose();
            }
        }

        public static void Begin(HttpContext context)
        {
            string path = context.Request.AppRelativeCurrentExecutionFilePath;
            bool feature = path.StartsWith("~/Emergency", StringComparison.OrdinalIgnoreCase);
            if (feature)
            {
                Headers(context);
                if (!Enabled)
                {
                    Error(context, 404, "not_found");
                    context.ApplicationInstance.CompleteRequest();
                    return;
                }
                try
                {
                    CheckTransport(context);
                }
                catch (EmergencyFailure failure)
                {
                    Error(context, failure.StatusCode, failure.ErrorCode);
                    context.ApplicationInstance.CompleteRequest();
                    return;
                }
            }
            if (!Enabled)
            {
                if (context.Request.Cookies[SessionCookie] != null)
                {
                    ClearCookie(context, SessionCookie);
                }
                return;
            }
            try
            {
                string ticket = ReadProtected(context, SessionCookie, "session");
                if (ticket == null)
                {
                    if (context.Request.Cookies[SessionCookie] != null)
                    {
                        ClearCookie(context, SessionCookie);
                        Ended(context);
                    }
                    return;
                }
                ClaimsPrincipal principal = Service.Authenticate(ticket, Browser(context, false));
                if (principal != null)
                {
                    context.Items["SamlEmergencyPrincipal"] = principal;
                }
                else
                {
                    ClearCookie(context, SessionCookie);
                    Ended(context);
                }
            }
            catch (Exception)
            {
                ClearCookie(context, SessionCookie);
                Ended(context);
            }
        }

        private static void Ended(HttpContext context)
        {
            if (
                context.Request.AppRelativeCurrentExecutionFilePath.Equals(
                    "~/MyPage.aspx",
                    StringComparison.OrdinalIgnoreCase
                )
            )
            {
                context.Response.Redirect(
                    VirtualPathUtility.ToAbsolute("~/EmergencyEnded.aspx"),
                    false
                );
                context.ApplicationInstance.CompleteRequest();
            }
        }

        public static bool Authenticate(HttpContext context)
        {
            ClaimsPrincipal principal = context.Items["SamlEmergencyPrincipal"] as ClaimsPrincipal;
            if (principal == null)
            {
                return false;
            }
            context.User = principal;
            Thread.CurrentPrincipal = principal;
            string path = context.Request.AppRelativeCurrentExecutionFilePath;
            if (
                path.Equals("~/login.ashx", StringComparison.OrdinalIgnoreCase)
                || path.Equals("~/logout.ashx", StringComparison.OrdinalIgnoreCase)
            )
            {
                Error(context, 403, "normal_protocol_action_unavailable");
                context.ApplicationInstance.CompleteRequest();
            }
            return true;
        }

        public static void Headers(HttpContext context)
        {
            context.Response.Cache.SetCacheability(HttpCacheability.NoCache);
            context.Response.Cache.SetNoStore();
            context.Response.Headers["X-Content-Type-Options"] = "nosniff";
            context.Response.Headers["X-Frame-Options"] = "DENY";
            context.Response.Headers["Referrer-Policy"] = "same-origin";
            context.Response.Headers["Content-Security-Policy"] =
                "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";
            context.Response.SuppressFormsAuthenticationRedirect = true;
            context.Response.TrySkipIisCustomErrors = true;
        }

        public static void CheckTransport(HttpContext context)
        {
            if (!Enabled)
            {
                throw new EmergencyFailure(404, "not_found");
            }
            if (
                !context.Request.IsSecureConnection
                || context.Request.Url.GetLeftPart(UriPartial.Authority) != Settings.Origin
            )
            {
                throw new EmergencyFailure(403, "https_origin_required");
            }
        }

        public static string Browser(HttpContext context, bool create, bool rotate = false)
        {
            string value =
                context.Items[BrowserCookie] as string
                ?? (
                    context.Request.Cookies[BrowserCookie] == null
                        ? null
                        : context.Request.Cookies[BrowserCookie].Value
                );
            if (rotate || (create && (value == null || value.Length != 43)))
            {
                value = Wire.RandomId();
                context.Items[BrowserCookie] = value;
                SetCookie(context, BrowserCookie, value);
            }
            return value;
        }

        public static string Csrf(HttpContext context)
        {
            string browser = Browser(context, true);
            if (
                (string)context.Session["SamlEmergencyCsrfBrowser"] != browser
                || context.Session["SamlEmergencyCsrf"] == null
            )
            {
                context.Session["SamlEmergencyCsrfBrowser"] = browser;
                context.Session["SamlEmergencyCsrf"] = Wire.RandomId();
            }
            return (string)context.Session["SamlEmergencyCsrf"];
        }

        public static void CheckCsrf(HttpContext context, bool normalLoginForm)
        {
            string token = normalLoginForm
                ? context.Request.Form["csrf"]
                : context.Request.Headers["X-Emergency-CSRF"];
            if (
                context.Request.Headers["Origin"] != Settings.Origin
                || Browser(context, false) == null
                || (string)context.Session["SamlEmergencyCsrfBrowser"] != Browser(context, false)
                || !Wire.EqualSecret(token, context.Session["SamlEmergencyCsrf"] as string)
            )
            {
                throw new EmergencyFailure(403, "csrf_or_origin_rejected");
            }
        }

        public static string NormalHandle(HttpContext context)
        {
            if (
                IsEmergency(context)
                || context.User == null
                || !context.User.Identity.IsAuthenticated
                || !Saml20Identity.IsInitialized()
                || SessionStore.CurrentSession == null
            )
            {
                throw new EmergencyFailure(401, "normal_login_required");
            }
            return SessionStore.CurrentSession[LoginHandle] as string;
        }

        public static void RejectNormalAction(HttpContext context)
        {
            if (IsEmergency(context))
            {
                throw new HttpException(
                    403,
                    "Normal token actions are unavailable in emergency mode."
                );
            }
        }

        public static void IssueSession(HttpContext context, string id)
        {
            FormsAuthentication.SignOut();
            if (SessionStore.CurrentSession != null)
            {
                SessionStore.CurrentSession["SamlAssertionLite"] = null;
                SessionStore.CurrentSession[LoginHandle] = null;
            }
            context.Session.Remove("IdCard");
            context.Session.Remove("SamlEmergencyCsrf");
            WriteProtected(context, SessionCookie, id, "session");
        }

        public static void ClearEmergency(HttpContext context)
        {
            string id = ReadProtected(context, SessionCookie, "session");
            try
            {
                if (id != null)
                {
                    Service.EndSession(id);
                }
            }
            finally
            {
                ClearCookie(context, SessionCookie);
            }
        }

        public static string OperatorId(HttpContext context)
        {
            string id = ReadProtected(context, OperatorCookie, "operator");
            Service.CheckOperator(id);
            return id;
        }

        public static void OperatorCookieSet(HttpContext context, string id)
        {
            WriteProtected(context, OperatorCookie, id, "operator");
        }

        public static void OperatorCookieClear(HttpContext context)
        {
            ClearCookie(context, OperatorCookie);
        }

        private static string ReadProtected(HttpContext context, string name, string purpose)
        {
            HttpCookie cookie = context.Request.Cookies[name];
            if (cookie == null || cookie.Value.Length > 2048)
            {
                return null;
            }
            try
            {
                byte[] plain = MachineKey.Unprotect(
                    Wire.Decode(cookie.Value, 1024),
                    "SamlSample.Emergency.Cookie.v1",
                    purpose,
                    Settings.Audience
                );
                return plain == null ? null : Encoding.UTF8.GetString(plain);
            }
            catch (Exception)
            {
                return null;
            }
        }

        private static void WriteProtected(
            HttpContext context,
            string name,
            string id,
            string purpose
        )
        {
            SetCookie(
                context,
                name,
                Wire.Encode(
                    MachineKey.Protect(
                        Encoding.UTF8.GetBytes(id),
                        "SamlSample.Emergency.Cookie.v1",
                        purpose,
                        Settings.Audience
                    )
                )
            );
        }

        private static void SetCookie(HttpContext context, string name, string value)
        {
            context.Response.Cookies.Set(
                new HttpCookie(name, value)
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict,
                    Path = VirtualPathUtility.ToAbsolute("~/"),
                }
            );
        }

        private static void ClearCookie(HttpContext context, string name)
        {
            context.Response.Cookies.Set(
                new HttpCookie(name, "")
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict,
                    Path = VirtualPathUtility.ToAbsolute("~/"),
                    Expires = DateTime.UtcNow.AddDays(-1),
                }
            );
        }

        public static void Error(HttpContext context, int status, string code)
        {
            context.Response.StatusCode = status;
            context.Response.ContentType = "application/json";
            context.Response.SuppressFormsAuthenticationRedirect = true;
            context.Response.TrySkipIisCustomErrors = true;
            context.Response.Write(
                new Newtonsoft.Json.Linq.JObject { ["error"] = code }.ToString(Formatting.None)
            );
        }
    }
}
