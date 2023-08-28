using FeLink;
using System.Buffers.Text;
using System.Text;

namespace FeLinkClientTest
{
    internal class Program
    {
        static void TestLed(FeLinkDevice dev)
        {
            Console.Write("Switch count:  ");
            if (!int.TryParse(Console.ReadLine() ?? "", out int count))
                return;

            DateTime start = DateTime.Now;
            int i;
            for (i = 0; i < count; i++)
                if (dev.SendData(Encoding.ASCII.GetBytes(i % 2 == 0 ? "off" : "on")) == false)
                    break;
            TimeSpan duration = DateTime.Now - start;

            Console.WriteLine("Switched LED {0} times, using {1:F3}s ({2:F0}Hz)",
                i,
                duration.TotalSeconds,
                i / duration.TotalSeconds
            );
        }

        static void TestBlock(FeLinkDevice dev, bool isPlaintext)
        {
            Console.Write("Block size:  ");
            if (!int.TryParse(Console.ReadLine() ?? "", out int blockSize))
                return;
            Console.Write("Block count: ");
            if (!int.TryParse(Console.ReadLine() ?? "", out int blockCount))
                return;

            byte[] block = new byte[blockSize];
            for (int j = 0; j < block.Length; j++)
                block[j] = 0xAA;
            DateTime start = DateTime.Now;
            int i;
            double delayTotal = 0;
            for (i = 0; i < blockCount; i++)
            {
                if (dev.SendData(block, 0, isPlaintext) == false)
                    break;
                if (dev.PacketDelay < 0)
                    break;
                delayTotal += dev.PacketDelay;
            }
            TimeSpan duration = DateTime.Now - start;

            Console.WriteLine("Send {0:F1}kB ({1}*{2}), took {3:F0}ms ({4}ms), {5:F2}kB/s ({6:F2}kB/s), average delay: {7:F1}ms ({8:F1}ms), loss rate: {9}/{10} ({11:F1}%)",
                blockSize * i / 1024.0,
                blockSize,
                i,
                duration.TotalMilliseconds,
                delayTotal,
                (blockSize * i / 1024.0) / (duration.TotalMilliseconds / 1000.0),
                (blockSize * i / 1024.0) / (delayTotal / 1000.0),
                duration.TotalMilliseconds / i,
                delayTotal / i,
                dev.PacketLoss,
                dev.PacketCount,
                (double)dev.PacketLoss / (double)dev.PacketCount * 100.0
            );
        }

        static void Main(string[] args)
        {
            FeLinkClient Client = new((s) => { Console.WriteLine("Disconnected"); });
            Client.Connect("192.168.3.113", 11300);

            int devSelected = 0;
            while (true)
            {
                string cmd = Console.ReadLine() ?? "";

                FeLinkDevice? dev = null;
                if (Client.Devices.Keys.Count > devSelected)
                {
                    uint id = Client.Devices.Keys.ToArray()[devSelected];
                    dev = Client.Devices[id];
                }

                switch (cmd)
                {
                    case "cc":
                        Client.Connect("192.168.3.113", 11300);
                        break;
                    case "init":
                        Client.BaseInit();
                        break;
                    case "sel":
                        Console.Write("index: ");
                        devSelected = int.Parse(Console.ReadLine() ?? "");
                        Client.PrintDevices(Client.Devices.Keys.ToArray()[devSelected]);
                        break;
                    case "i":
                        Client.UserInfo();
                        break;
                    case "s":
                        Client.BaseScan();
                        break;
                    case "p":
                        dev?.Pair();
                        break;
                    case "c":
                        dev?.Connect();
                        break;
                    case "up":
                        dev?.Unpair();
                        break;
                    case "t1":
                        if (dev != null)
                            TestLed(dev);
                        break;
                    case "t2":
                        if (dev != null)
                            TestBlock(dev, false);
                        break;
                    case "t3":
                        if (dev != null)
                            TestBlock(dev, true);
                        break;
                    case "login":
                        Console.Write("Enter username: ");
                        string username = Console.ReadLine() ?? "";
                        Console.Write("Enter password: ");
                        string password = Console.ReadLine() ?? "";
                        Client.Login(username, password);
                        break;
                    case "a":
                        Client.Login("admin", "123456");
                        break;
                    case "lf":
                        Client.Login("fjj", "fjjfjj");
                        break;
                    case "register":
                        Console.Write("Enter username: ");
                        username = Console.ReadLine() ?? "";
                        Console.Write("Enter password: ");
                        password = Console.ReadLine() ?? "";
                        Console.Write("Is use only?: ");
                        string isUseOnly = Console.ReadLine() ?? "";
                        Client.Register(username, password, isUseOnly.ToLower() == "t");
                        break;
                    case "rf":
                        Client.Register("fjj", "fjjfjj", false);
                        break;
                    case "passwd":
                        Console.Write("Enter username: ");
                        username = Console.ReadLine() ?? "";
                        Console.Write("Enter old password: ");
                        string oldPassword = Console.ReadLine() ?? "";
                        Console.Write("Enter new password: ");
                        string newPassword = Console.ReadLine() ?? "";
                        Client.ChangePassword(username, oldPassword, newPassword);
                        break;
                    default:
                        dev?.SendData(Encoding.Default.GetBytes(cmd));
                        break;
                }
            }
        }
    }
}