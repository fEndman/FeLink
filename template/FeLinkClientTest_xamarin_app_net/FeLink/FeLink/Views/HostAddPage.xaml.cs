using FeLink.Models;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xamarin.Forms;
using Xamarin.Forms.Xaml;
using ZXing.Mobile;
using ZXing.Net.Mobile.Forms;
using static FeLink.Models.Setting;

namespace FeLink.Views
{
	[XamlCompilation(XamlCompilationOptions.Compile)]
	public partial class HostAddPage : ContentPage
	{
		public HostAddPage ()
		{
			InitializeComponent();
        }

        private async void ButtonConnect_Clicked(object sender, EventArgs e)
        {
            var addr = EntryAddress.Text.Split(':');
            if (addr.Length < 2 || !ushort.TryParse(addr[1], out ushort port))
            {
                await DisplayAlert("", "地址输入错误", "OK");
                return;
            }

            var client = new FeLinkClient();
            if (!client.Connect(addr[0], port))
            {
                await DisplayAlert("", "连接失败", "OK");
                return;
            }

            var host = new Setting.HostInfo
            {
                Name = EntryName.Text == "" ? "基站" : EntryName.Text,
                HostAddress = addr[0],
                HostPort = port
            };
            var setting = (Setting)Shell.Current.BindingContext;
            foreach (var h in setting.Save.Hosts)
            {
                if (host == h)
                {
                    await DisplayAlert("", "已经连接到该基站了", "OK");
                    return;
                }
            }

            setting.Save.Hosts.Add(host);
            setting.Store();

            var flyoutItem = new FlyoutItem
            {
                Title = host.Name
            };
            flyoutItem.Items.Add(new ShellContent
            {
                Content = new HostPage(host, client)
            });
            Shell.Current.Items.Insert(0, flyoutItem);
            Shell.Current.CurrentItem = flyoutItem;
        }


        class FeLinkHostInfoQr
        {
            [JsonProperty(PropertyName = "name")]
            public string Name { get; set; } = "基站";
            [JsonProperty(PropertyName = "address")]
            public string Address { get; set; }
            [JsonProperty(PropertyName = "port")]
            public ushort Port { get; set; }
        }
        private void ImageButtonQR_Clicked(object sender, EventArgs e)
        {
            var qrPage = new ZXingScannerPage();
            qrPage.OnScanResult += (qr) =>
            {
                FeLinkHostInfoQr hostInfoQr;
                try
                {
                    hostInfoQr = JObject.Parse(qr.Text).ToObject<FeLinkHostInfoQr>();
                }
                catch
                {
                    return;
                }

                Device.BeginInvokeOnMainThread(() =>
                {
                    qrPage.IsScanning = false;
                    Navigation.PopAsync();
                    EntryAddress.Text = hostInfoQr.Address + ":" + hostInfoQr.Port.ToString();
                    EntryName.Text = hostInfoQr.Name;
                });
            };

            Navigation.PushAsync(qrPage);
        }
    }
}