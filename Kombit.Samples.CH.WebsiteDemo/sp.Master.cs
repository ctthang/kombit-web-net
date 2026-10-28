#region

using System;

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
        ///     Returns the URL of a static site asset with a file-version query string.
        /// </summary>
        public string AssetUrl(string virtualPath)
        {
            return AssetVersion.Url(virtualPath);
        }
    }
}
