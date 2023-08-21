﻿using System.Net.Sockets;
using System.Text;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using System.Reflection;
using System.Net.Security;

namespace FeLink
{
    public class FeLinkDevice
    {
        public enum FeLinkState
        {
            Handshaked = 0,
            Pairing = 1,
            Paired = 2,
            Connected = 3,
        }

        public uint ID { get { return id; } }
        private uint id;
        public uint Type { get; }
        public ushort Version { get; }
        public string? Name { get; }
        public FeLinkState State { get; }
        public ushort Timeout
        {
            get { return timeout; }
            set
            {
                client?.DeviceSetTimeout(ID, value);
                timeout = value;
            }
        }
        public byte MaxRetrans
        {
            get { return maxRetrans; }
            set
            {
                client?.DeviceSetTimeout(ID, value);
                maxRetrans = value;
            }
        }
        public int PacketDelay { get { return packetDelay; } }
        private int packetDelay;
        public uint PacketCount { get { return packetCount; } }
        private uint packetCount;
        public uint PacketLoss { get { return packetLoss; } }
        private uint packetLoss;

        private ushort timeout;
        private byte maxRetrans;

        public FeLinkClient? Client { get { return client; } }
        private FeLinkClient? client;

        [JsonConstructor]
        public FeLinkDevice(
            uint id,
            uint type,
            ushort version,
            String name,
            FeLinkState state,
            ushort timeout,
            byte max_retrans,
            int tx_packet_delay,
            uint tx_packet_count,
            uint tx_packet_loss)
        {
            this.id = id;
            Type = type;
            Version = version;
            Name = name;
            State = state;
            this.timeout = timeout;
            this.maxRetrans = max_retrans;
            packetDelay = tx_packet_delay;
            packetCount = tx_packet_count;
            packetLoss = tx_packet_loss;
        }

        public void Pair()
        {
            client?.DevicePair(ID);
        }
        public bool Connect()
        {
            return client?.DeviceConnect(ID) ?? false;
        }
        public bool Unpair()
        {
            return client?.DeviceUnpair(ID) ?? false;
        }
        public bool SendData(byte[] data, uint paddingAlign = 0, bool isPlaindata = false)
        {
            return client?.DeviceSendData(ID, data, paddingAlign, isPlaindata) ?? false;
        }
    }

    public class FeLinkClient
    {
        public delegate void DisconnectedHandler(FeLinkClient sender);

        private static class Message
        {
            public static byte CheckSum8(byte[] bytes, int offset, int count)
            {
                byte chksum8 = 0;
                for (int i = 0; i < count; i++)
                    chksum8 += bytes[offset + i];
                return (byte)~chksum8;
            }
            public static uint Read32(byte[] src, int offset)
            {
                uint val = 0;
                val = src[offset + 3];
                val = val << 8 | src[offset + 2];
                val = val << 8 | src[offset + 1];
                val = val << 8 | src[offset + 0];
                return val;
            }
            public static void Write32(byte[] dest, int offset, uint data)
            {
                dest[offset + 0] = (byte)(data >> 0);
                dest[offset + 1] = (byte)(data >> 8);
                dest[offset + 2] = (byte)(data >> 16);
                dest[offset + 3] = (byte)(data >> 24);
            }

            public enum ClientCmd
            {
                Info = 0,
                Init = 1,
                Scan = 2,
                Pair = 3,
                Connect = 4,
                Unpair = 5,
                Data = 6,
                SetTimeout = 7,
                SetMaxRetrans = 8,
                Login = -1,
                Register = -2,
                ChangePassword = -3,
            }
            public enum HostCmd
            {
                Ack = 0,
                Info = 1,
                Confirm = -1,
            }

            public class ClientCmdInfo
            {
                public readonly ClientCmd ccmd = ClientCmd.Info;
                public ClientCmdInfo()
                {
                    return;
                }
            }
            public class ClientCmdInit
            {
                public readonly ClientCmd ccmd = ClientCmd.Init;
                public ClientCmdInit()
                {
                    return;
                }
            }
            public class ClientCmdScan
            {
                public readonly ClientCmd ccmd = ClientCmd.Scan;
                public ClientCmdScan()
                {
                    return;
                }
            }
            public class ClientCmdPair
            {
                public readonly ClientCmd ccmd = ClientCmd.Pair;
                public uint id;
                public ClientCmdPair(uint id)
                {
                    this.id = id;
                }
            }
            public class ClientCmdConnect
            {
                public readonly ClientCmd ccmd = ClientCmd.Connect;
                public uint id;
                public ClientCmdConnect(uint id)
                {
                    this.id = id;
                }
            }
            public class ClientCmdUnpair
            {
                public readonly ClientCmd ccmd = ClientCmd.Unpair;
                public uint id;
                public ClientCmdUnpair(uint id)
                {
                    this.id = id;
                }
            }
            public class ClientCmdData
            {
                public readonly ClientCmd ccmd = ClientCmd.Data;
                public uint id;
                public byte[] data;
                public uint count;
                public uint padding_align;
                public bool is_plaintext;
                public ClientCmdData(uint id, byte[] data, uint paddingAlign, bool isPlaintext)
                {
                    this.id = id;
                    this.data = data;
                    this.count = (uint)data.Length;
                    this.padding_align = paddingAlign;
                    this.is_plaintext = isPlaintext;
                }
            }
            public class ClientCmdSetTimeout
            {
                public readonly ClientCmd ccmd = ClientCmd.SetTimeout;
                public uint id;
                public ushort timeout;
                public ClientCmdSetTimeout(uint id, ushort Timeout)
                {
                    this.id = id;
                    this.timeout = Timeout;
                }
            }
            public class ClientCmdSetMaxRetrans
            {
                public readonly ClientCmd ccmd = ClientCmd.SetMaxRetrans;
                public uint id;
                public byte max_retrans;
                public ClientCmdSetMaxRetrans(uint id, byte maxRetrans)
                {
                    this.id = id;
                    this.max_retrans = maxRetrans;
                }
            }

            public class ClientCmdLogin
            {
                public readonly ClientCmd ccmd = ClientCmd.Login;
                public string username;
                public string password;
                public ClientCmdLogin(string username, string password)
                {
                    this.username = username;
                    this.password = password;
                }
            }
            public class ClientCmdRegister
            {
                public readonly ClientCmd ccmd = ClientCmd.Register;
                public string username;
                public string password;
                public bool is_use_only;
                public ClientCmdRegister(string username, string password, bool is_use_only)
                {
                    this.username = username;
                    this.password = password;
                    this.is_use_only = is_use_only;
                }
            }
            public class ClientCmdChangePassword
            {
                public readonly ClientCmd ccmd = ClientCmd.ChangePassword;
                public string username;
                public string old_password;
                public string new_password;
                public ClientCmdChangePassword(string username, string oldPassword, string newPassword)
                {
                    this.username = username;
                    this.old_password = oldPassword;
                    this.new_password = newPassword;
                }
            }

            public class HostCmdAck
            {
                public HostCmd hcmd = HostCmd.Ack;
                public uint id = 0;
                public int delay = -1;
                public uint count = 0;
                public uint loss = 0;
            }
            public class HostCmdConfirm
            {
                public HostCmd hcmd = HostCmd.Confirm;
                public bool is_success = false;
                public bool is_use_only = true;
            }
        }

        public string Host { get; private set; } = string.Empty;
        public ushort Port { get; private set; } = 0;
        public string Username { get; private set; } = "guest";
        public bool IsUseOnly { get; private set; } = true;
        public Dictionary<uint, FeLinkDevice> Devices { get; } = new();
        public int HostCmdTimeout { get; set; } = 500;
        public bool IsConnected { get; private set; } = false;

        public DisconnectedHandler HostDisconnectedHandler;

        private TcpClient? tcpClient;
        private SslStream? ssl;

        private Thread? rxThread;

        private ManualResetEvent HostCmdAckEvent = new(false);
        private ManualResetEvent HostCmdInfoEvent = new(false);
        private ManualResetEvent HostCmdConfirmEvent = new(false);
        private bool HostCmdConfirmIsSuccess = false;

        public FeLinkClient(DisconnectedHandler handler)
        {
            HostDisconnectedHandler = new(handler);
        }

        //private static bool ValidateServerCertificate(
        //    object sender,
        //    X509Certificate? certificate,
        //    X509Chain? chain,
        //    SslPolicyErrors sslPolicyErrors)
        //{
        //    if (sslPolicyErrors == SslPolicyErrors.None)
        //        return true;

        //    Console.WriteLine("Certificate error: {0}", sslPolicyErrors);

        //    // Do not allow this client to communicate with unauthenticated servers.
        //    return false;
        //}
        public void Connect(string host, ushort port)
        {
            tcpClient = new(host, port);
            ssl = new(tcpClient.GetStream(), false, (s, cert, chain, e) => { return true; });
            ssl.AuthenticateAsClient(host);

            Host = host;
            Port = port;

            IsConnected = true;
            if (rxThread != null && rxThread.ThreadState != ThreadState.Running)
                rxThread.Join();
            rxThread = new(new ThreadStart(ReceiveThread));
            rxThread.Start();
        }

        public bool Login(string username, string password)
        {
            Message.ClientCmdLogin msg = new(username, password);
            string msgJson = JsonConvert.SerializeObject(msg);
            if (!TransmitCmd(msgJson))
                return false;
            if (!HostCmdConfirmEvent.WaitOne(2000))
                return false;
            return HostCmdConfirmIsSuccess;
        }
        public bool Register(string username, string password, bool is_use_only)
        {
            Message.ClientCmdRegister msg = new(username, password, is_use_only);
            string msgJson = JsonConvert.SerializeObject(msg);
            if (!TransmitCmd(msgJson))
                return false;
            if (!HostCmdConfirmEvent.WaitOne(2000))
                return false;
            return HostCmdConfirmIsSuccess;
        }
        public bool ChangePassword(string username, string oldPassword, string newPassword)
        {
            Message.ClientCmdChangePassword msg = new(username, oldPassword, newPassword);
            string msgJson = JsonConvert.SerializeObject(msg);
            if (!TransmitCmd(msgJson))
                return false;
            if (!HostCmdConfirmEvent.WaitOne(2000))
                return false;
            return HostCmdConfirmIsSuccess;
        }

        public void Shutdown()
        {
            rxThread.Join();
            ssl?.Close();
            tcpClient.Close();
        }

        private void Disconnected(string err)
        {
            IsConnected = false;
            ssl?.Close();
            tcpClient.Close();
            HostDisconnectedHandler(this);
            Console.WriteLine("FeLink disconnected: " + err);
        }

        public void PrintDevices(uint sel = 0)
        {
            List<uint> devIdList = new(Devices.Keys);
            foreach (uint id in devIdList)
            {
                Console.WriteLine(
                    "{0} ID: {1} | Type: {2} | Name: {3}\t | State: {4}",
                    id == sel ? "->" : "  ",
                    Devices[id].ID.ToString("X8"),
                    Devices[id].Type.ToString("X8"),
                    Devices[id].Name,
                    Devices[id].State.ToString()
                );
            }
        }

        private bool TransmitCmd(string json)
        {
            if (IsConnected == false)
                return false;

            byte[] head = Encoding.ASCII.GetBytes("\0CMD\0\0\0\0");
            MemoryStream ms = new(8 + json.Length);

            Message.Write32(head, 4, (uint)json.Length);
            head[0] = Message.CheckSum8(head, 0, 8);

            ms.Write(head, 0, 8);
            ms.Write(Encoding.UTF8.GetBytes(json));
            try
            {
                ssl?.Write(ms.ToArray());
            }
            catch (Exception e)
            {
                rxThread.Join();
                Disconnected(e.Message);
                return false;
            }

            Console.WriteLine("C ({0}): {1}", Username, json);

            return true;
        }

        public bool UserInfo()
        {
            Message.ClientCmdInfo msg = new();
            string msgJson = JsonConvert.SerializeObject(msg);
            if (!TransmitCmd(msgJson))
                return false;
            return HostCmdInfoEvent.WaitOne(HostCmdTimeout);
        }
        public bool BaseInit()
        {
            Message.ClientCmdInit msg = new();
            string msgJson = JsonConvert.SerializeObject(msg);
            return TransmitCmd(msgJson);
        }
        public bool BaseScan()
        {
            Message.ClientCmdScan msg = new();
            string msgJson = JsonConvert.SerializeObject(msg);
            return TransmitCmd(msgJson);
        }
        public bool DevicePair(uint id)
        {
            Message.ClientCmdPair msg = new(id);
            string msgJson = JsonConvert.SerializeObject(msg);
            return TransmitCmd(msgJson);
        }
        public bool DeviceConnect(uint id)
        {
            Message.ClientCmdConnect msg = new(id);
            string msgJson = JsonConvert.SerializeObject(msg);
            if (!TransmitCmd(msgJson))
                return false;
            return HostCmdAckEvent.WaitOne(HostCmdTimeout);
        }
        public bool DeviceUnpair(uint id)
        {
            Message.ClientCmdUnpair msg = new(id);
            string msgJson = JsonConvert.SerializeObject(msg);
            return TransmitCmd(msgJson);
        }
        public bool DeviceSendData(uint id, byte[] data, uint padding_align = 0, bool isPlaintext = false)
        {
            if (data.Length > 0xFFFF)
                return false;
            Message.ClientCmdData msg = new(id, data, padding_align, isPlaintext);
            string msgJson = JsonConvert.SerializeObject(msg);
            if (!TransmitCmd(msgJson))
                return false;
            return HostCmdAckEvent.WaitOne(HostCmdTimeout);
        }
        public bool DeviceSetTimeout(uint id, ushort timeout)
        {
            Message.ClientCmdSetTimeout msg = new(id, timeout);
            string msgJson = JsonConvert.SerializeObject(msg);
            return TransmitCmd(msgJson);
        }
        public bool DeviceSetMaxRetrans(uint id, byte maxRetrans)
        {
            Message.ClientCmdSetMaxRetrans msg = new(id, maxRetrans);
            string msgJson = JsonConvert.SerializeObject(msg);
            return TransmitCmd(msgJson);
        }

        private void HostCmdAckHandler(JObject json)
        {
            Message.HostCmdAck? ack = json.ToObject<Message.HostCmdAck>();
            if (ack == null || json["id"] == null)
            {
                Console.WriteLine("FeLink host cmd error");
                return;
            }

            FieldInfo? devDelayField = typeof(FeLinkDevice).GetField("packetDelay", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.DeclaredOnly);
            devDelayField?.SetValue(Devices[ack.id], ack.delay);
            FieldInfo? devCountField = typeof(FeLinkDevice).GetField("packetCount", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.DeclaredOnly);
            devCountField?.SetValue(Devices[ack.id], ack.count);
            FieldInfo? devLossField = typeof(FeLinkDevice).GetField("packetLoss", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.DeclaredOnly);
            devLossField?.SetValue(Devices[ack.id], ack.loss);
            HostCmdAckEvent.Set();
            HostCmdAckEvent.Reset();
        }
        private void HostCmdInfoHandler(JObject json)
        {
            JToken? jsonIsUsaOnly = json["is_use_only"];
            if (jsonIsUsaOnly == null)
            {
                Console.WriteLine("FeLink host cmd error");
                return;
            }
            IsUseOnly = (bool)jsonIsUsaOnly;

            JToken? jsonUsername = json["username"];
            if (jsonUsername == null)
            {
                Console.WriteLine("FeLink host cmd error");
                return;
            }
            Username = (string?)jsonUsername ?? "null";

            if (json["devs"] == null)
                return;
            JToken? jsonDevs = json["devs"];
            if (jsonDevs == null)
            {
                Console.WriteLine("FeLink host cmd error");
                return;
            }
            List<JToken> jsonDevsList = jsonDevs.Children().ToList();

            List<uint> shouldBeRemoved = new();
            if (Devices.Count >= jsonDevsList.Count)
                shouldBeRemoved.AddRange(Devices.Keys);

            foreach (var jsonDev in jsonDevsList)
            {
                FeLinkDevice? dev = jsonDev.ToObject<FeLinkDevice>();
                if (dev == null || jsonDev["id"] == null)
                {
                    Console.WriteLine("FeLink host cmd error");
                    continue;
                }
                FieldInfo? devClientField = typeof(FeLinkDevice).GetField("client", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.DeclaredOnly);
                devClientField?.SetValue(dev, this);
                uint id = (uint)(jsonDev["id"] ?? 0);
                Devices[id] = dev;
                if (Devices.Count >= jsonDevsList.Count)
                    shouldBeRemoved.Remove(id);
            }

            foreach (var id in shouldBeRemoved)
                Devices.Remove(id);

            PrintDevices();
            HostCmdInfoEvent.Set();
            HostCmdInfoEvent.Reset();
        }
        private void HostCmdConfirmHandler(JObject json)
        {
            Message.HostCmdConfirm? confirm = json.ToObject<Message.HostCmdConfirm>();
            if (confirm == null)
            {
                Console.WriteLine("FeLink host cmd error");
                return;
            }
            HostCmdConfirmIsSuccess = confirm.is_success;
            IsUseOnly = confirm.is_use_only;
            HostCmdConfirmEvent.Set();
            HostCmdConfirmEvent.Reset();
        }

        private void ReceiveThread()
        {
            if (ssl == null)
                return;

            while (true)
            {
                byte[] head = new byte[8];
                int bytesRead;
                try
                {
                    bytesRead = ssl.Read(head, 0, 8);
                }
                catch (Exception e)
                {
                    Disconnected(e.Message);
                    return;
                }
                if (bytesRead <= 0)
                {
                    Disconnected("remote shutdown");
                    return;
                }
                if (bytesRead < 8)
                    continue;
                if (Message.CheckSum8(head, 0, 8) != 0)
                    continue;
                int len = (int)Message.Read32(head, 4);
                byte[] jsonbyteArray = new byte[len];
                try
                {
                    int left = len;
                    while (left > 0)
                    {
                        bytesRead = ssl.Read(jsonbyteArray, len - left, left);
                        left -= bytesRead;
                    }
                }
                catch (Exception e)
                {
                    Disconnected(e.Message);
                    return;
                }

                string jsonStr = Encoding.UTF8.GetString(jsonbyteArray);
                Console.WriteLine("H: " + jsonStr);
                JObject json;
                try
                {
                    json = JObject.Parse(jsonStr);
                }
                catch
                {
                    continue;
                }

                if (json["hcmd"] == null)
                {
                    Console.WriteLine("FeLink host cmd error");
                    continue;
                }
                Message.HostCmd cmd = (Message.HostCmd)(int)(json["hcmd"] ?? 0x7FFFFFFF);
                switch (cmd)
                {
                    case Message.HostCmd.Ack:
                        HostCmdAckHandler(json); break;
                    case Message.HostCmd.Info:
                        HostCmdInfoHandler(json); break;
                    case Message.HostCmd.Confirm:
                        HostCmdConfirmHandler(json); break;
                    default:
                        break;
                }
            }
        }
    }
}
