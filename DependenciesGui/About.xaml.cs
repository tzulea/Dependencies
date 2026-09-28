using System;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Documents;
using System.Windows.Navigation;

namespace Dependencies
{
    /// <summary>
    /// Logique d'interaction pour About.xaml
    /// </summary>
    public partial class About : Window
    {
        public About()
        {
            InitializeComponent();
            DataContext = this;
        }

        private void Uri_RequestNavigate(object sender, RequestNavigateEventArgs e)
        {
            Process.Start(e.Uri.ToString());
        }

        public string VersionStr
        {
            get
            {
                return Assembly.GetEntryAssembly().GetName().Version.ToString();
            }
        }

        private async void Uri_CheckUpdates(object sender, RequestNavigateEventArgs e)
        {
            string version = await GetLatestVersion("https://github.com/lucasg/Dependencies/releases/latest");
            UpdateCheck.Inlines.Clear();
            UpdateCheck.Inlines.Add("Latest version: ");
            var link = new Hyperlink()
            {
                NavigateUri = new Uri(version)
            };
            link.Inlines.Add(version);
            link.RequestNavigate += Uri_RequestNavigate;
            UpdateCheck.Inlines.Add(link);
        }

        // Based on https://stackoverflow.com/a/28424940/4928207
        private async Task<string> GetLatestVersion(string url)
        {
            try
            {
                using var handler = new HttpClientHandler { AllowAutoRedirect = false };
                using var client = new HttpClient(handler);
                using var request = new HttpRequestMessage(HttpMethod.Head, url);
                using var response = await client.SendAsync(request);

                switch (response.StatusCode)
                {
                    case HttpStatusCode.OK:
                        return url;
                    case HttpStatusCode.Redirect:
                    case HttpStatusCode.MovedPermanently:
                    case HttpStatusCode.RedirectKeepVerb:
                    case HttpStatusCode.RedirectMethod:
                        return response.Headers.Location?.ToString() ?? url;
                    default:
                        return url;
                }
            }
            catch
            {
            }
            return url;
        }
    }
}
