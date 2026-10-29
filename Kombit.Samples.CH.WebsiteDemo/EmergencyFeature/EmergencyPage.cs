using System;
using System.Linq;
using System.Security.Claims;
using System.Web;
using System.Web.UI;
using Kombit.Samples.CH.Emergency;

namespace Kombit.Samples.CH.WebsiteDemo.EmergencyFeature
{
    public class EmergencyPage : Page
    {
        public string Mode { get; private set; }
        public string CsrfToken { get; private set; }
        public ClaimsPrincipal EmergencyUser
        {
            get { return Context.User as ClaimsPrincipal; }
        }

        /// <summary>Registry record of the session's credential (home page only).</summary>
        public Newtonsoft.Json.Linq.JObject SessionCredential { get; private set; }

        /// <summary>The decrypted, signature-verified EC as indented JSON, or null when not kept.</summary>
        public string RawCredentialJson
        {
            get
            {
                Newtonsoft.Json.Linq.JToken raw = SessionCredential?["raw"];
                return raw == null || raw.Type == Newtonsoft.Json.Linq.JTokenType.Null
                    ? null
                    : raw.ToString(Newtonsoft.Json.Formatting.Indented);
            }
        }

        public string FormatTime(Newtonsoft.Json.Linq.JToken seconds)
        {
            return seconds == null || seconds.Type != Newtonsoft.Json.Linq.JTokenType.Integer
                ? string.Empty
                : DateTimeOffset.FromUnixTimeSeconds((long)seconds).ToString("u");
        }

        protected override void OnInit(EventArgs e)
        {
            base.OnInit(e);
            EmergencyWeb.Headers(Context);
            try
            {
                EmergencyWeb.CheckTransport(Context);
                EmergencyWeb.Service.CheckRate(Request.UserHostAddress);
                string file = System.IO.Path.GetFileName(Request.Path);
                Mode =
                    file.Equals("Emergency.aspx", StringComparison.OrdinalIgnoreCase) ? "prepare"
                    : file.Equals("EmergencyHome.aspx", StringComparison.OrdinalIgnoreCase) ? "home"
                    : "ended";
                if (Mode == "home" && !EmergencyWeb.IsEmergency(Context))
                {
                    Response.Redirect(ResolveUrl("~/EmergencyEnded.aspx"), true);
                }
                if (Mode == "home")
                {
                    Claim session = EmergencyUser.FindFirst("emergency_session");
                    SessionCredential = EmergencyWeb.Service.SessionCredential(
                        session?.Value,
                        EmergencyWeb.Browser(Context, false)
                    );
                }
                CsrfToken = EmergencyWeb.Csrf(Context);
            }
            catch (EmergencyFailure failure)
            {
                Response.Clear();
                EmergencyWeb.Error(Context, failure.StatusCode, failure.ErrorCode, failure);
                Response.End();
            }
            catch (Exception exception) when (!(exception is System.Threading.ThreadAbortException))
            {
                Response.Clear();
                EmergencyWeb.Error(Context, 503, "emergency_unavailable", exception);
                Response.End();
            }
        }
    }
}
