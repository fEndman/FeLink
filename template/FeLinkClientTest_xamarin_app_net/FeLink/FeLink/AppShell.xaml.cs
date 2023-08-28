using FeLink.Models;
using FeLink.ViewModels;
using FeLink.Views;
using System;
using System.Linq;
using System.Collections.Generic;
using Xamarin.Forms;
using System.IO;

namespace FeLink
{
    public partial class AppShell : Xamarin.Forms.Shell
    {
        public Setting Setting { get; private set; }

        public AppShell()
        {
            InitializeComponent();

            Setting = Setting.Load(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "setting.json"));

            BindingContext = Setting;

            FlyoutItem flyoutItem = null;
            for (int i = Setting.Save.Hosts.Count - 1; i >= 0; i--)
            {
                var host = Setting.Save.Hosts[i];
                int j;
                for (j = i - 1; j >= 0; j--)
                {
                    if (host == Setting.Save.Hosts[j])
                    {
                        Setting.Save.Hosts.RemoveAt(i);
                        break;
                    }
                }
                if (j >= 0)
                    continue;

                flyoutItem = new FlyoutItem
                {
                    Title = host.Name
                };
                flyoutItem.Items.Add(new ShellContent
                {
                    Content = new HostPage(host)
                });
                Items.Insert(0, flyoutItem);
            }
            if (flyoutItem != null)
                CurrentItem = flyoutItem;
        }

        private async void OnMenuItemClicked(object sender, EventArgs e)
        {
            await Shell.Current.GoToAsync("//LoginPage");
        }
    }
}
