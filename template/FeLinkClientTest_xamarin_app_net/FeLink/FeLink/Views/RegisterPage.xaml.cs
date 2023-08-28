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
    public partial class RegisterPage : ContentPage
    {
        Setting.UserInfo user;
        FeLinkClient client;
        Action refreshUI;

        public RegisterPage(Setting.UserInfo user, FeLinkClient client, Action refreshUI)
        {
            InitializeComponent();

            this.user = user;
            this.client = client;
            this.refreshUI = refreshUI;
        }

        private void ButtonRegister_Clicked(object sender, EventArgs e)
        {
            if (EntryPassword.Text != EntryPassword2.Text)
            {
                DisplayAlert("", "两次密码输入不一致", "OK");
                return;
            }

            string username = EntryUsername.Text;
            string password = EntryPassword.Text;
            ButtonRegister.IsEnabled = false;
            Task.Run(() =>
            {
                if (!client.Register(username, password, CheckBoxIsUseOnly.IsChecked))
                {
                    Device.BeginInvokeOnMainThread(() =>
                    {
                        DisplayAlert("", "注册失败", "OK");
                        ButtonRegister.IsEnabled = true;
                    });
                    return;
                }
                user.Username = username;
                user.Password = password;
                Device.BeginInvokeOnMainThread(() =>
                {
                    refreshUI();
                    Navigation.PopAsync();
                });
            });
        }
    }
}