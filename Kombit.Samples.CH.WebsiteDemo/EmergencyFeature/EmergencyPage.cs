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
        public bool CanPrepare { get; private set; }
        public ClaimsPrincipal EmergencyUser
        {
            get { return Context.User as ClaimsPrincipal; }
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
                    : file.Equals("EmergencyLogin.aspx", StringComparison.OrdinalIgnoreCase)
                        ? "login"
                    : file.Equals("EmergencyHome.aspx", StringComparison.OrdinalIgnoreCase) ? "home"
                    : "ended";
                if (Mode == "prepare")
                {
                    CanPrepare = EmergencyWeb.Service.CanPrepare(
                        EmergencyWeb.NormalHandle(Context),
                        EmergencyWeb.Browser(Context, false)
                    );
                }
                if (Mode == "home" && !EmergencyWeb.IsEmergency(Context))
                {
                    Response.Redirect(ResolveUrl("~/EmergencyEnded.aspx"), true);
                }
                CsrfToken = EmergencyWeb.Csrf(Context);
            }
            catch (EmergencyFailure failure)
            {
                Response.Clear();
                EmergencyWeb.Error(Context, failure.StatusCode, failure.ErrorCode);
                Response.End();
            }
        }
    }
}
