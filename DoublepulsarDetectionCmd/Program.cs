using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using DoublepulsarDetectionLib;
using System.Net;
using NLog;

namespace DoublepulsarDetectionCmd {
    class Program {
        static Logger _l = LogManager.GetCurrentClassLogger();

        private static void Check(string ip, bool clean = false) {
            DetectDoublePulsar dp = new DetectDoublePulsar();
            int infected, cleaned;
            _l.Info($"Checking [{ip}] {((clean) ? "with" : "without")} uninstall");
            dp.check_ip(ip, out infected, out cleaned, verbose: true, uninstall: clean);
        }

        static int Main(string[] args) {
            
            if (args.Length != 2) {
                int bitness;
                if (Environment.Is64BitProcess) {
                    bitness = 64;
                } else {
                    bitness = 32;
                }
                string aa = "Double Pulsar Detection Tool";
                string myname = $"{aa} - v{Assembly.GetExecutingAssembly().GetName().Version.ToString()} {bitness}bits";
                Console.WriteLine(myname);
                Console.WriteLine("------------------------------------------------");
                Console.WriteLine("Usage: DoublepuslarDetectionCmd.exe ip_address|ip_range --check|--uninstall");
                return -1;
            }
            string ip2 = args[0];
            int counter = 0;
            List<Task> tasks = new List<Task>();
            string input = ip2.Replace(",", " ").Replace(";", " ");
            bool clean = (args[1] == "--uninstall");
            foreach (string r in input.Split(null)) {
                if (string.IsNullOrWhiteSpace(r))
                    continue;
                try {
                    IPRange ips = new IPRange(r);
                    foreach (IPAddress ip in ips.GetAllIP()) {
                        Task t = new Task(() => { counter++; Check(ip.ToString(), clean); counter--; });
                        
                        tasks.Add(t);
                        t.Start();
                    }

                } catch (Exception ex) {
                    _l.Warn($"Exception occured for '{r}': {ex.Message}");
                }
            }
            Task.WaitAll(tasks.ToArray());
            return 0;
        }
    }
}
