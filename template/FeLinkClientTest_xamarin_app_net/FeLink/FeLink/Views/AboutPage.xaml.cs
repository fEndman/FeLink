using System;
using System.ComponentModel;
using Xamarin.Essentials;
using Xamarin.Forms;
using Xamarin.Forms.PlatformConfiguration.AndroidSpecific;
using Xamarin.Forms.Xaml;

namespace FeLink.Views
{
    public partial class AboutPage : ContentPage
    {
        public AboutPage()
        {
            InitializeComponent();
        }

        private void ButtonGithub_Clicked(object sender, EventArgs e)
        {
            Browser.OpenAsync("https://github.com/fEndman/FeLink");
        }
    }
}