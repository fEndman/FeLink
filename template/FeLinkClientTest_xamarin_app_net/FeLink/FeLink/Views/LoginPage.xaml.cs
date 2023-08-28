using FeLink.Models;
using FeLink.ViewModels;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xamarin.Forms;
using Xamarin.Forms.Xaml;

namespace FeLink.Views
{
    [XamlCompilation(XamlCompilationOptions.Compile)]
    public partial class LoginPage : ContentPage
    {
        Setting.UserInfo user;
        FeLinkClient client;
        Action refreshUI;

        public LoginPage(Setting.UserInfo user, FeLinkClient client, Action refreshUI)
        {
            InitializeComponent();

            this.user = user;
            this.client = client;
            this.refreshUI = refreshUI;
            EntryUsername.Text = user.Username;
            EntryPassword.Text = user.Password;

            if (client.Username == "admin")
            {
                ToolbarItems.Add(new ToolbarItem
                {
                    Text = "新用户",
                    Command = new Command(() =>
                    {
                        Navigation.PushAsync(new RegisterPage(user, client, () =>
                        {
                            EntryUsername.Text = user.Username;
                            EntryPassword.Text = user.Password;
                        }));
                    })
                });
            }

            ButtonChangePassword.IsVisible = !client.IsUseOnly;
        }

        private void ButtonChangePassword_Clicked(object sender, EventArgs e)
        {
            Navigation.PushAsync(new PasswordChangePage(user, client, () =>
            {
                EntryUsername.Text = user.Username;
                EntryPassword.Text = user.Password;
            }));
        }

        private void ButtonLogin_Clicked(object sender, EventArgs e)
        {
            string username = EntryUsername.Text;
            string password = EntryPassword.Text;
            ButtonLogin.IsEnabled = false;
            Task.Run(() =>
            {
                if (!client.Login(username, password))
                {
                    Device.BeginInvokeOnMainThread(() =>
                    {
                        DisplayAlert("", "用户名或密码错误", "OK");
                        ButtonLogin.IsEnabled = true;
                    });
                    return;
                }
                user.Username = username;
                user.Password = password;
                var setting = (Setting)Shell.Current.BindingContext;
                setting.Store();
                Device.BeginInvokeOnMainThread(() =>
                {
                    refreshUI();
                    Navigation.PopAsync();
                });
            });
        }
    }
}