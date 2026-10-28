#region

using System;
using System.Globalization;
using System.IO;
using System.Web;

#endregion

namespace Kombit.Samples.CH.WebsiteDemo
{
    [
        System.Diagnostics.CodeAnalysis.SuppressMessage(
            "Microsoft.Naming",
            "CA1704:IdentifiersShouldBeSpelledCorrectly",
            MessageId = "sp"
        ),
        System.Diagnostics.CodeAnalysis.SuppressMessage(
            "Microsoft.Naming",
            "CA1709:IdentifiersShouldBeCasedCorrectly",
            MessageId = "sp"
        )
    ]
    public partial class sp : System.Web.UI.MasterPage
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            siteStyle.Href = AssetUrl("~/css/Style.css");
        }

        /// <summary>
        ///     Returns the URL of a static site asset with a version query string derived from the
        ///     file's last write time, so browsers fetch the new file after each deployment.
        /// </summary>
        public string AssetUrl(string virtualPath)
        {
            string url = ResolveUrl(virtualPath);
            string file = Server.MapPath(virtualPath);
            return File.Exists(file)
                ? url
                    + "?v="
                    + File.GetLastWriteTimeUtc(file).Ticks.ToString(CultureInfo.InvariantCulture)
                : url;
        }
    }
}
