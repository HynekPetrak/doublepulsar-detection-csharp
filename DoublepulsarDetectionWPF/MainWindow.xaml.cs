using NLog;
using NLog.Config;
using NLog.Targets.Wrappers;
using DoublepulsarDetectionWPF.Helper;
using System;
using System.Net;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using DoublepulsarDetectionLib;

namespace DoublepulsarDetectionWPF {
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window {
        Logger _l = LogManager.GetCurrentClassLogger();
        int counter = 0;
        public MainWindow() {
            InitializeComponent();
            Dispatcher.Invoke(() => {
                var target = new WpfRichTextBoxTarget {
                    Name = "RichText",
                    Layout =
                        "[${longdate:useUTC=false}] : [${level:uppercase=true}] : ${message} ${exception:innerFormat=tostring:maxInnerExceptionLevel=10:separator=,:format=tostring}",
                    ControlName = LogBox.Name,
                    FormName = GetType().Name,
                    AutoScroll = true,
                    MaxLines = 100000,
                    UseDefaultRowColoringRules = true,
                };
                var asyncWrapper = new AsyncTargetWrapper { Name = "RichTextAsync", WrappedTarget = target };

                LogManager.Configuration.AddTarget(asyncWrapper.Name, asyncWrapper);
                LogManager.Configuration.LoggingRules.Insert(0, new LoggingRule("*", LogLevel.Info, asyncWrapper));
                LogManager.ReconfigExistingLoggers();

            });
            DispatcherTimer dispatcherTimer = new System.Windows.Threading.DispatcherTimer();
            dispatcherTimer.Tick += new EventHandler(dispatcherTimer_Tick);
            dispatcherTimer.Interval = new TimeSpan(0, 0, 1);
            dispatcherTimer.Start();

            int bitness;
            if (Environment.Is64BitProcess) {
                bitness = 64;
            } else {
                bitness = 32;
            }
            string aa = "Double Pulsar Detection Tool";
            string myname = $"{aa} - v{Assembly.GetExecutingAssembly().GetName().Version.ToString()} {bitness}bits";
            this.Title = myname;
            _l.Info("Ready");
        }
        private bool zero_flag = false;
        private void dispatcherTimer_Tick(object sender, EventArgs e) {
            // code goes here
            if (counter > 0) {
                _l.Info($"Active checks: {counter}");
                zero_flag = true;
            } else if (zero_flag) {
                zero_flag = false;
                _l.Info($"No checks pending");
            }
        }
        private void Check(string ip, bool clean = false) {
            DetectDoublePulsar dp = new DetectDoublePulsar();
            int infected, cleaned;
            _l.Info($"Checking [{ip}] {((clean) ? "with" : "without")} uninstall");
            dp.check_ip(ip, out infected, out cleaned, verbose: true, uninstall: clean);
        }

        private void Action(bool clean) {
            string input = AddressBox.Text.Replace(",", " ").Replace(";", " ");
            foreach (string r in input.Split(null)) {
                if (string.IsNullOrWhiteSpace(r))
                    continue;
                try {
                    IPRange ips = new IPRange(r);
                    foreach (IPAddress ip in ips.GetAllIP()) {
                        new Task(() => { counter++; Check(ip.ToString(), clean); counter--; }).Start();
                    }
                } catch(Exception ex) {
                    _l.Warn($"Exception occured for '{r}': {ex.Message}");
                }
            }
        }

        private void DetectBtn_Click(object sender, RoutedEventArgs e) {
            Action(false);
        }

        private void CleanBtn_Click(object sender, RoutedEventArgs e) {
            Action(true);
        }
    }
}
