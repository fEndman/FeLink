using FeLink.Models;
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
    public partial class PasswordChangePage : ContentPage
    {
        Setting.UserInfo user;
        FeLinkClient client;
        Action refreshUI;

        public PasswordChangePage(Setting.UserInfo user, FeLinkClient client, Action refreshUI)
        {
            InitializeComponent();

            this.user = user;
            this.client = client;
            this.refreshUI = refreshUI;

            EntryUsername.Text = user.Username;
        }

        private void ButtonChangePassword_Clicked(object sender, EventArgs e)
        {
            if (EntryPasswordNew.Text != EntryPasswordNew2.Text)
            {
                DisplayAlert("", "两次密码输入不一致", "OK");
                return;
            }

            string username = EntryUsername.Text;
            string passwordOld = EntryPasswordOld.Text;
            string passwordNew = EntryPasswordNew.Text;
            ButtonChangePassword.IsEnabled = false;
            Task.Run(() =>
            {
                if (!client.ChangePassword(username, passwordOld, passwordNew))
                {
                    Device.BeginInvokeOnMainThread(() =>
                    {
                        DisplayAlert("", "用户名或密码错误", "OK");
                        ButtonChangePassword.IsEnabled = true;
                    });
                    return;
                }
                user.Username = username;
                user.Password = passwordNew;
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