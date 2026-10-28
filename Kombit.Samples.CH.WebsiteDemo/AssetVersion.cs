#region

using System.Globalization;
using System.IO;
using System.Web;
using System.Web.Hosting;

#endregion

namespace Kombit.Samples.CH.WebsiteDemo
{
    /// <summary>
    ///     Builds URLs for static site assets with a version query string derived from the file's
    ///     last write time, so browsers fetch the new file after each deployment.
    /// </summary>
    public static class AssetVersion
    {
        public static string Url(string virtualPath)
        {
            string url = VirtualPathUtility.ToAbsolute(virtualPath);
            string file = HostingEnvironment.MapPath(virtualPath);
            return file != null && File.Exists(file)
                ? url
                    + "?v="
                    + File.GetLastWriteTimeUtc(file).Ticks.ToString(CultureInfo.InvariantCulture)
                : url;
        }
    }
}
