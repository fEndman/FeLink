using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace FeLink.Models
{
    public class Setting
    {
        public class UserInfo
        {
            public string Username { get; set; } = "guest";
            public string Password { get; set; } = "";
        }
        public class HostInfo
        {
            public string Name { get; set; } = "FeLinkBase";
            public string HostAddress { get; set; } = string.Empty;
            public ushort HostPort { get; set; }
            public UserInfo User { get; set; } = new UserInfo();

            public static bool operator ==(HostInfo a, HostInfo b)
            {
                if (ReferenceEquals(a, null) || ReferenceEquals(b, null))
                    return ReferenceEquals(a, b);
                return a.HostAddress == b.HostAddress && a.HostPort == b.HostPort && a.User.Username == b.User.Username;
            }
            public static bool operator !=(HostInfo a, HostInfo b)
            {
                if (ReferenceEquals(a, null) || ReferenceEquals(b, null))
                    return ReferenceEquals(a, b);
                return a.HostAddress != b.HostAddress || a.HostPort != b.HostPort || a.User.Username != b.User.Username;
            }
            public override int GetHashCode()
            {
                return HostAddress.GetHashCode() + HostPort.GetHashCode() + User.GetHashCode();
            }
            public override bool Equals(object obj)
            {
                return ReferenceEquals(this, obj);
            }
        }
        public class SaveInfo
        {
            public List<HostInfo> Hosts { get; set; } = new List<HostInfo>();
        }

        public SaveInfo Save { get; private set; } = new SaveInfo();

        string filePath;

        public static Setting Load(string filePath)
        {
            var setting = new Setting
            {
                filePath = filePath
            };

            JObject json;
            try
            {
                json = JObject.Parse(File.ReadAllText(filePath, Encoding.UTF8));
                setting.Save = json.ToObject<SaveInfo>() ?? new SaveInfo();
            }
            catch
            {
                return setting;
            }

            return setting;
        }

        public void Store()
        {
            File.WriteAllText(filePath, JsonConvert.SerializeObject(Save));
        }
    }
}
