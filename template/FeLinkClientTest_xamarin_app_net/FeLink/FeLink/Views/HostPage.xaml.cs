using FeLink.Models;
using FeLink.ViewModels;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using Xamarin.Forms;
using Xamarin.Forms.Xaml;

namespace FeLink.Views
{
    [XamlCompilation(XamlCompilationOptions.Compile)]
    public partial class HostPage : ContentPage
    {
        HostViewModel model;

        Setting.HostInfo host;

        public HostPage(Setting.HostInfo host, FeLinkClient client = null)
        {
            InitializeComponent();

            this.host = host;
            BindingContext = model = new HostViewModel(host, client);
        }

        private async void ToolbarItemLogin_Clicked(object sender, EventArgs e)
        {
            ShouldShutdown = false;
            if (model.IsConnected)
                await Navigation.PushAsync(new LoginPage(model.Host.User, model.Client, () => model.OnPropertyChanged(nameof(model.Username))));
            ShouldShutdown = true;
        }
        private void ToolbarItemShutdown_Clicked(object sender, EventArgs e)
        {
            model.Shutdown();
            var setting = (Setting)Shell.Current.BindingContext;
            setting.Save.Hosts.Remove(host);
            setting.Store();
            Shell.Current.Items.Remove(Shell.Current.CurrentItem);
        }

        private void CollectionViewPairedDevices_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (e.CurrentSelection.Count == 0)
                return;
            FeLinkDeviceUI dev = (FeLinkDeviceUI)e.CurrentSelection[0];
            Task.Run(() =>
            {
                if (dev != null && dev.Dev.State == FeLinkDevice.FeLinkState.Paired)
                    dev?.Dev.Connect();
            });
            CollectionViewPairedDevices.SelectedItem = null;
        }
        private void CollectionViewHandshakedDevices_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (e.CurrentSelection.Count == 0)
                return;
            FeLinkDeviceUI dev = (FeLinkDeviceUI)e.CurrentSelection[0];
            Task.Run(() =>
            {
                if (dev.Dev.State == FeLinkDevice.FeLinkState.Handshaked)
                    dev.Dev.Pair();
                else if (dev.Dev.State == FeLinkDevice.FeLinkState.Pairing)
                    dev.Dev.Unpair();
            });
            CollectionViewHandshakedDevices.SelectedItem = null;
        }

        protected override void OnAppearing()
        {
            model.ConnectAsync();
        }
        bool ShouldShutdown = true;
        protected override void OnDisappearing()
        {
            if (ShouldShutdown)
                model.Shutdown();
        }
    }
}