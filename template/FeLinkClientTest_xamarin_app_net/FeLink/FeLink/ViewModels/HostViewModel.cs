using FeLink.Models;
using FeLink.Views;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xamarin.Essentials;
using Xamarin.Forms;

namespace FeLink.ViewModels
{
    static class FeLinkDeviceTypes
    {

        public static ImageSource GetIcon(FeLinkDevice dev)
        {
            switch (dev.Type)
            {
                case 0x00000000:
                    return ImageSource.FromFile("lamp.png");
                default:
                    return new FontImageSource
                    {
                        Glyph = "?",
                        Color = Color.Black,
                        Size = 100
                    };
            }
        }

        public static View GetControl(FeLinkDevice dev, FeLinkDeviceUI ui)
        {
            switch (dev.Type)
            {
                case 0x00000000:
                    var sw = new Switch();
                    sw.Toggled += (s, e) =>
                        Task.Run(() =>
                        {
                            ui.IsRunning = true;
                            dev.SendData(Encoding.Default.GetBytes(e.Value ? "on" : "off"), 3);
                            ui.IsRunning = false;
                        });
                    sw.HorizontalOptions = LayoutOptions.End;
                    return sw;
                default:
                    return new BoxView
                    {
                        BackgroundColor = Color.Transparent,
                        WidthRequest = 0,
                        HeightRequest = 0
                    };
            }
        }
    }

    public class FeLinkDeviceUI
    {
        public string ID { get { return Dev.ID.ToString("X8"); } }
        public string Name { get { return Dev.Name; } }
        public ImageSource Icon { get; private set; }
        public bool IsRunning { get; set; }
        public View CustomControl { get; private set; }
        public Command UnpairCommand { get; set; }

        public FeLinkDevice Dev { get; private set; }

        public FeLinkDeviceUI(FeLinkDevice dev)
        {
            Dev = dev;
            Icon = FeLinkDeviceTypes.GetIcon(dev);
            if (dev.State == FeLinkDevice.FeLinkState.Connected)
                CustomControl = FeLinkDeviceTypes.GetControl(dev, this);
            else if (dev.State == FeLinkDevice.FeLinkState.Pairing)
                IsRunning = true;
            if (dev.State >= FeLinkDevice.FeLinkState.Paired)
                UnpairCommand = new Command(() => Dev.Unpair());
        }
    }

    public class HostViewModel : BaseViewModel
    {
        public ObservableCollection<FeLinkDeviceUI> PairedDevices { get; private set; }
        public ObservableCollection<FeLinkDeviceUI> HandshakedDevices { get; private set; }

        public bool IsConnected => Client.IsConnected;
        public bool IsDisconnected => !Client.IsConnected;
        public bool IsScanning { get; private set; } = false;
        public string Username { get { return Client.Username; } }
        public Command ScanCommand { get; private set; }

        public Setting.HostInfo Host { get; }
        public FeLinkClient Client { get; }

        public HostViewModel(Setting.HostInfo host, FeLinkClient client = null)
        {
            this.Host = host;
            Title = host.Name;

            Client = client ?? new FeLinkClient();

            PairedDevices = new ObservableCollection<FeLinkDeviceUI>();
            HandshakedDevices = new ObservableCollection<FeLinkDeviceUI>();

            Client.DevicesChangeHandler += (s, e) =>
            {
                PairedDevices.Clear();
                HandshakedDevices.Clear();
                foreach (var dev in Client.Devices)
                {
                    switch (dev.Value.State)
                    {
                        case FeLinkDevice.FeLinkState.Connected:
                            PairedDevices.Insert(0, new FeLinkDeviceUI(dev.Value));
                            break;
                        case FeLinkDevice.FeLinkState.Paired:
                            PairedDevices.Add(new FeLinkDeviceUI(dev.Value));
                            break;
                        default:
                            HandshakedDevices.Add(new FeLinkDeviceUI(dev.Value));
                            break;
                    }
                }
            };

            Client.HostDisconnectedHandler += (s, e) =>
            {
                PairedDevices.Clear();
                HandshakedDevices.Clear();

                ConnectAsync();
            };

            ScanCommand = new Command(() =>
            {
                Client.BaseScan();
                IsScanning = false;
                OnPropertyChanged(nameof(IsScanning));
            });
        }

        public async void ConnectAsync()
        {
            if (Client.IsConnected)
                return;

            await Task.Run(() =>
            {
                OnPropertyChanged(nameof(IsConnected));
                OnPropertyChanged(nameof(IsDisconnected));

                while (!Client.Connect(Host.HostAddress, Host.HostPort))
                    Thread.Sleep(1000);

                OnPropertyChanged(nameof(IsConnected));
                OnPropertyChanged(nameof(IsDisconnected));

                Client.Login(Host.User.Username, Host.User.Password);
                OnPropertyChanged(nameof(Username));
            });
        }

        public void Shutdown()
        {
            PairedDevices.Clear();
            HandshakedDevices.Clear();
            Client.Shutdown();
        }
    }
}
