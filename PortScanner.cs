using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;

namespace PortScanner
{
    public class MainForm : Form
    {
        // ── Controls ──
        private TabControl tabControl;
        private TabPage tabScan, tabResults, tabAbout;

        // Scan tab
        private Label lblTarget, lblPortRange, lblTimeout, lblThreads, lblPreset;
        private TextBox txtTarget, txtPortStart, txtPortEnd, txtTimeout, txtThreads;
        private ComboBox cmbPreset;
        private CheckBox chkResolveHostnames, chkGrabBanners;
        private Button btnScan, btnStop, btnClear, btnExport;
        private ProgressBar progressBar;
        private Label lblStatus, lblProgress;

        // Results
        private ListView lvResults;
        private RichTextBox txtLog;

        // State
        private CancellationTokenSource cts;
        private bool isScanning = false;
        private int totalPorts, scannedPorts, openPorts;
        private readonly object lockObj = new object();
        private readonly ConcurrentBag<ScanResult> results = new ConcurrentBag<ScanResult>();

        // Well-known port presets
        private static readonly Dictionary<string, string> Presets = new Dictionary<string, string>
        {
            { "Custom", "" },
            { "Common (Top 20)", "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080" },
            { "Web Ports", "80,443,8080,8443,8000,8888,9090,3000,5000" },
            { "Database Ports", "1433,1521,3306,5432,6379,9042,27017,28015" },
            { "Mail Ports", "25,110,143,465,587,993,995" },
            { "Full Range (1-1024)", "1-1024" },
            { "Full Range (1-65535)", "1-65535" },
        };

        public MainForm()
        {
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            // ── Form ──
            Text = "Port Scanner";
            Size = new Size(880, 680);
            MinimumSize = new Size(780, 580);
            StartPosition = FormStartPosition.CenterScreen;
            Font = new Font("Segoe UI", 9F);
            Icon = SystemIcons.Shield;

            // ── Tab Control ──
            tabControl = new TabControl { Dock = DockStyle.Fill };
            tabScan = new TabPage("Scan");
            tabResults = new TabPage("Log");
            tabAbout = new TabPage("About");
            tabControl.TabPages.AddRange(new[] { tabScan, tabResults, tabAbout });

            // ═══════════════════════════════════════
            //  SCAN TAB
            // ═══════════════════════════════════════
            var panelTop = new Panel { Dock = DockStyle.Top, Height = 210, Padding = new Padding(12) };

            // Row 1: Target
            lblTarget = new Label { Text = "Target (IP / Hostname / CIDR):", Location = new Point(12, 14), AutoSize = true };
            txtTarget = new TextBox { Location = new Point(220, 11), Width = 280, PlaceholderText = "e.g. 192.168.1.1 or 192.168.1.0/24" };

            // Row 2: Preset
            lblPreset = new Label { Text = "Port Preset:", Location = new Point(12, 46), AutoSize = true };
            cmbPreset = new ComboBox { Location = new Point(220, 43), Width = 280, DropDownStyle = ComboBoxStyle.DropDownList };
            foreach (var k in Presets.Keys) cmbPreset.Items.Add(k);
            cmbPreset.SelectedIndex = 0;
            cmbPreset.SelectedIndexChanged += CmbPreset_Changed;

            // Row 3: Port range
            lblPortRange = new Label { Text = "Port Range:", Location = new Point(12, 78), AutoSize = true };
            txtPortStart = new TextBox { Location = new Point(220, 75), Width = 100, Text = "1" };
            var lblDash = new Label { Text = "–", Location = new Point(325, 78), AutoSize = true };
            txtPortEnd = new TextBox { Location = new Point(340, 75), Width = 100, Text = "1024" };

            // Row 4: Timeout & Threads
            lblTimeout = new Label { Text = "Timeout (ms):", Location = new Point(12, 110), AutoSize = true };
            txtTimeout = new TextBox { Location = new Point(220, 107), Width = 100, Text = "200" };
            lblThreads = new Label { Text = "Max Threads:", Location = new Point(340, 110), AutoSize = true };
            txtThreads = new TextBox { Location = new Point(440, 107), Width = 60, Text = "100" };

            // Row 5: Options
            chkResolveHostnames = new CheckBox { Text = "Resolve Hostnames", Location = new Point(220, 140), AutoSize = true, Checked = true };
            chkGrabBanners = new CheckBox { Text = "Grab Banners", Location = new Point(400, 140), AutoSize = true };

            // Row 6: Buttons
            btnScan = new Button { Text = "▶  Start Scan", Location = new Point(220, 170), Size = new Size(120, 30), BackColor = Color.FromArgb(34, 139, 34), ForeColor = Color.White, FlatStyle = FlatStyle.Flat };
            btnStop = new Button { Text = "■  Stop", Location = new Point(350, 170), Size = new Size(90, 30), Enabled = false, FlatStyle = FlatStyle.Flat };
            btnClear = new Button { Text = "Clear", Location = new Point(450, 170), Size = new Size(70, 30), FlatStyle = FlatStyle.Flat };
            btnExport = new Button { Text = "Export CSV", Location = new Point(530, 170), Size = new Size(90, 30), FlatStyle = FlatStyle.Flat };

            btnScan.Click += BtnScan_Click;
            btnStop.Click += BtnStop_Click;
            btnClear.Click += BtnClear_Click;
            btnExport.Click += BtnExport_Click;

            panelTop.Controls.AddRange(new Control[] {
                lblTarget, txtTarget, lblPreset, cmbPreset,
                lblPortRange, txtPortStart, lblDash, txtPortEnd,
                lblTimeout, txtTimeout, lblThreads, txtThreads,
                chkResolveHostnames, chkGrabBanners,
                btnScan, btnStop, btnClear, btnExport
            });

            // Progress area
            var panelProgress = new Panel { Dock = DockStyle.Top, Height = 40, Padding = new Padding(12, 4, 12, 4) };
            progressBar = new ProgressBar { Dock = DockStyle.Top, Height = 18, Style = ProgressBarStyle.Continuous };
            lblProgress = new Label { Dock = DockStyle.Top, Text = "Ready", Height = 18, TextAlign = ContentAlignment.MiddleLeft };
            panelProgress.Controls.Add(lblProgress);
            panelProgress.Controls.Add(progressBar);

            // Results ListView
            lvResults = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
                Font = new Font("Consolas", 9F)
            };
            lvResults.Columns.Add("Host", 160);
            lvResults.Columns.Add("Port", 70);
            lvResults.Columns.Add("State", 70);
            lvResults.Columns.Add("Service", 110);
            lvResults.Columns.Add("Banner", 300);
            lvResults.Columns.Add("Latency", 80);

            // Status bar
            lblStatus = new Label { Dock = DockStyle.Bottom, Height = 22, TextAlign = ContentAlignment.MiddleLeft, Text = " Ready", BackColor = Color.FromArgb(240, 240, 240) };

            tabScan.Controls.Add(lvResults);
            tabScan.Controls.Add(panelProgress);
            tabScan.Controls.Add(panelTop);
            tabScan.Controls.Add(lblStatus);

            // ═══════════════════════════════════════
            //  LOG TAB
            // ═══════════════════════════════════════
            txtLog = new RichTextBox { Dock = DockStyle.Fill, ReadOnly = true, Font = new Font("Consolas", 9F), BackColor = Color.FromArgb(30, 30, 30), ForeColor = Color.LightGreen };
            tabResults.Controls.Add(txtLog);

            // ═══════════════════════════════════════
            //  ABOUT TAB
            // ═══════════════════════════════════════
            var lblAbout = new Label
            {
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleCenter,
                Text = "Port Scanner v1.0\n\n"
                     + "A lightweight network port scanner.\n\n"
                     + "Features:\n"
                     + "• Single IP, hostname, or CIDR range scanning\n"
                     + "• Configurable port ranges & presets\n"
                     + "• Multi-threaded async scanning\n"
                     + "• Banner grabbing\n"
                     + "• CSV export\n\n"
                     + "Use responsibly — only scan networks you own or have permission to scan."
            };
            tabAbout.Controls.Add(lblAbout);

            Controls.Add(tabControl);
        }

        // ── Preset changed ──
        private void CmbPreset_Changed(object sender, EventArgs e)
        {
            string key = cmbPreset.SelectedItem?.ToString() ?? "";
            if (!Presets.ContainsKey(key) || key == "Custom") return;

            string val = Presets[key];
            if (val.Contains("-") && !val.Contains(","))
            {
                var parts = val.Split('-');
                txtPortStart.Text = parts[0];
                txtPortEnd.Text = parts[1];
            }
            else
            {
                // For comma-separated presets, store in start field and clear end
                txtPortStart.Text = val;
                txtPortEnd.Text = "";
            }
        }

        // ── Parse ports from input ──
        private List<int> ParsePorts()
        {
            var ports = new SortedSet<int>();
            string startText = txtPortStart.Text.Trim();
            string endText = txtPortEnd.Text.Trim();

            if (startText.Contains(","))
            {
                // Comma-separated list
                foreach (var token in startText.Split(','))
                {
                    string t = token.Trim();
                    if (t.Contains("-"))
                    {
                        var rng = t.Split('-');
                        if (int.TryParse(rng[0], out int a) && int.TryParse(rng[1], out int b))
                            for (int i = a; i <= b; i++) if (i >= 1 && i <= 65535) ports.Add(i);
                    }
                    else if (int.TryParse(t, out int p) && p >= 1 && p <= 65535)
                        ports.Add(p);
                }
            }
            else
            {
                int start = int.TryParse(startText, out int s) ? s : 1;
                int end = int.TryParse(endText, out int en) ? en : start;
                for (int i = Math.Max(1, start); i <= Math.Min(65535, end); i++)
                    ports.Add(i);
            }
            return ports.ToList();
        }

        // ── Parse target into IP list (supports CIDR) ──
        private List<IPAddress> ParseTargets(string target)
        {
            var list = new List<IPAddress>();

            if (target.Contains("/"))
            {
                // CIDR notation
                var parts = target.Split('/');
                if (IPAddress.TryParse(parts[0], out var networkAddr) && int.TryParse(parts[1], out int prefix))
                {
                    if (prefix < 0 || prefix > 32) throw new ArgumentException("Invalid CIDR prefix.");
                    uint ip = BitConverter.ToUInt32(networkAddr.GetAddressBytes().Reverse().ToArray(), 0);
                    uint mask = prefix == 0 ? 0 : 0xFFFFFFFF << (32 - prefix);
                    uint network = ip & mask;
                    uint broadcast = network | ~mask;

                    // Skip network and broadcast for subnets > /31
                    uint start = prefix <= 30 ? network + 1 : network;
                    uint end = prefix <= 30 ? broadcast - 1 : broadcast;

                    if (end - start > 1024)
                        throw new ArgumentException("CIDR range too large (max /22 = 1022 hosts). Narrow the range.");

                    for (uint i = start; i <= end; i++)
                        list.Add(new IPAddress(BitConverter.GetBytes(i).Reverse().ToArray()));
                }
            }
            else
            {
                // Single IP or hostname
                if (IPAddress.TryParse(target, out var addr))
                    list.Add(addr);
                else
                {
                    var entry = Dns.GetHostEntry(target);
                    if (entry.AddressList.Length > 0)
                        list.Add(entry.AddressList.First(a => a.AddressFamily == AddressFamily.InterNetwork));
                }
            }

            return list;
        }

        // ── Start Scan ──
        private async void BtnScan_Click(object sender, EventArgs e)
        {
            if (isScanning) return;

            string target = txtTarget.Text.Trim();
            if (string.IsNullOrEmpty(target))
            {
                MessageBox.Show("Please enter a target IP or hostname.", "Input Required", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            List<IPAddress> hosts;
            try { hosts = ParseTargets(target); }
            catch (Exception ex)
            {
                MessageBox.Show($"Invalid target: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            var ports = ParsePorts();
            if (ports.Count == 0)
            {
                MessageBox.Show("No valid ports specified.", "Input Required", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            if (!int.TryParse(txtTimeout.Text, out int timeout) || timeout < 50) timeout = 200;
            if (!int.TryParse(txtThreads.Text, out int maxThreads) || maxThreads < 1) maxThreads = 100;

            // Reset
            isScanning = true;
            cts = new CancellationTokenSource();
            while (results.TryTake(out _)) { }
            openPorts = 0;
            scannedPorts = 0;
            totalPorts = hosts.Count * ports.Count;

            lvResults.Items.Clear();
            progressBar.Value = 0;
            progressBar.Maximum = totalPorts;
            btnScan.Enabled = false;
            btnStop.Enabled = true;
            lblStatus.Text = $" Scanning {hosts.Count} host(s), {ports.Count} port(s)...";
            Log($"[*] Scan started: {hosts.Count} host(s), {ports.Count} port(s), timeout={timeout}ms, threads={maxThreads}");

            bool resolve = chkResolveHostnames.Checked;
            bool banners = chkGrabBanners.Checked;
            var token = cts.Token;

            var sw = System.Diagnostics.Stopwatch.StartNew();

            try
            {
                var semaphore = new SemaphoreSlim(maxThreads);
                var tasks = new List<Task>();

                foreach (var host in hosts)
                {
                    foreach (var port in ports)
                    {
                        if (token.IsCancellationRequested) break;

                        await semaphore.WaitAsync(token);
                        tasks.Add(Task.Run(async () =>
                        {
                            try
                            {
                                await ScanPort(host, port, timeout, resolve, banners, token);
                            }
                            finally
                            {
                                semaphore.Release();
                            }
                        }, token));
                    }
                    if (token.IsCancellationRequested) break;
                }

                await Task.WhenAll(tasks);
            }
            catch (OperationCanceledException)
            {
                Log("[!] Scan cancelled by user.");
            }
            catch (Exception ex)
            {
                Log($"[!] Error: {ex.Message}");
            }

            sw.Stop();
            isScanning = false;
            btnScan.Enabled = true;
            btnStop.Enabled = false;
            progressBar.Value = progressBar.Maximum;
            string summary = $" Done — {openPorts} open port(s) found in {sw.Elapsed.TotalSeconds:F1}s";
            lblStatus.Text = summary;
            lblProgress.Text = $"{scannedPorts}/{totalPorts} complete";
            Log($"[*] Scan finished: {openPorts} open, {sw.Elapsed.TotalSeconds:F1}s elapsed.");
        }

        // ── Scan a single port ──
        private async Task ScanPort(IPAddress host, int port, int timeout, bool resolve, bool banners, CancellationToken token)
        {
            string banner = "";
            string state = "Closed";
            double latencyMs = 0;

            var sw = System.Diagnostics.Stopwatch.StartNew();
            try
            {
                using (var client = new TcpClient())
                {
                    var connectTask = client.ConnectAsync(host, port);
                    if (await Task.WhenAny(connectTask, Task.Delay(timeout, token)) == connectTask && client.Connected)
                    {
                        sw.Stop();
                        latencyMs = sw.Elapsed.TotalMilliseconds;
                        state = "Open";

                        if (banners)
                        {
                            try
                            {
                                var stream = client.GetStream();
                                stream.ReadTimeout = Math.Min(timeout, 1000);
                                // Send a basic probe for HTTP
                                if (port == 80 || port == 8080 || port == 8443 || port == 443)
                                {
                                    byte[] probe = Encoding.ASCII.GetBytes($"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n");
                                    await stream.WriteAsync(probe, 0, probe.Length, token);
                                }
                                byte[] buf = new byte[512];
                                var readTask = stream.ReadAsync(buf, 0, buf.Length, token);
                                if (await Task.WhenAny(readTask, Task.Delay(800, token)) == readTask)
                                {
                                    int read = readTask.Result;
                                    if (read > 0)
                                        banner = Encoding.ASCII.GetString(buf, 0, read).Trim().Replace("\r", "").Replace("\n", " ");
                                }
                            }
                            catch { /* banner grab failed, that's okay */ }
                        }
                    }
                }
            }
            catch { /* connection failed = closed/filtered */ }

            Interlocked.Increment(ref scannedPorts);

            if (state == "Open")
            {
                Interlocked.Increment(ref openPorts);
                string service = GetServiceName(port);
                string hostStr = host.ToString();

                var result = new ScanResult { Host = hostStr, Port = port, State = state, Service = service, Banner = banner, Latency = latencyMs };
                results.Add(result);

                BeginInvoke((Action)(() =>
                {
                    var item = new ListViewItem(new[] { hostStr, port.ToString(), state, service, banner.Length > 80 ? banner.Substring(0, 80) + "..." : banner, $"{latencyMs:F0} ms" });
                    item.ForeColor = Color.DarkGreen;
                    lvResults.Items.Add(item);
                    lvResults.EnsureVisible(lvResults.Items.Count - 1);
                    Log($"  [+] {hostStr}:{port} OPEN ({service}) {(banner.Length > 0 ? "| " + banner.Substring(0, Math.Min(60, banner.Length)) : "")}");
                }));
            }

            BeginInvoke((Action)(() =>
            {
                if (scannedPorts <= progressBar.Maximum)
                    progressBar.Value = scannedPorts;
                lblProgress.Text = $"{scannedPorts}/{totalPorts} ({openPorts} open)";
            }));
        }

        // ── Stop ──
        private void BtnStop_Click(object sender, EventArgs e)
        {
            cts?.Cancel();
            btnStop.Enabled = false;
            lblStatus.Text = " Stopping...";
        }

        // ── Clear ──
        private void BtnClear_Click(object sender, EventArgs e)
        {
            lvResults.Items.Clear();
            txtLog.Clear();
            progressBar.Value = 0;
            lblProgress.Text = "";
            lblStatus.Text = " Ready";
            while (results.TryTake(out _)) { }
        }

        // ── Export CSV ──
        private void BtnExport_Click(object sender, EventArgs e)
        {
            if (lvResults.Items.Count == 0)
            {
                MessageBox.Show("No results to export.", "Export", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            using (var dlg = new SaveFileDialog { Filter = "CSV Files|*.csv", FileName = $"scan_{DateTime.Now:yyyyMMdd_HHmmss}.csv" })
            {
                if (dlg.ShowDialog() == DialogResult.OK)
                {
                    var sb = new StringBuilder();
                    sb.AppendLine("Host,Port,State,Service,Banner,Latency");
                    foreach (ListViewItem item in lvResults.Items)
                    {
                        sb.AppendLine(string.Join(",",
                            item.SubItems[0].Text,
                            item.SubItems[1].Text,
                            item.SubItems[2].Text,
                            $"\"{item.SubItems[3].Text}\"",
                            $"\"{item.SubItems[4].Text.Replace("\"", "\"\"")}\"",
                            item.SubItems[5].Text));
                    }
                    File.WriteAllText(dlg.FileName, sb.ToString());
                    MessageBox.Show($"Exported {lvResults.Items.Count} results.", "Export", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    Log($"[*] Exported {lvResults.Items.Count} results to {dlg.FileName}");
                }
            }
        }

        // ── Log helper ──
        private void Log(string msg)
        {
            if (InvokeRequired) { BeginInvoke((Action)(() => Log(msg))); return; }
            txtLog.AppendText($"[{DateTime.Now:HH:mm:ss}] {msg}\n");
        }

        // ── Well-known service names ──
        private static string GetServiceName(int port)
        {
            return port switch
            {
                20 => "FTP-DATA", 21 => "FTP", 22 => "SSH", 23 => "Telnet",
                25 => "SMTP", 53 => "DNS", 67 => "DHCP", 68 => "DHCP",
                69 => "TFTP", 80 => "HTTP", 110 => "POP3", 111 => "RPCBind",
                123 => "NTP", 135 => "MSRPC", 137 => "NetBIOS", 138 => "NetBIOS",
                139 => "NetBIOS", 143 => "IMAP", 161 => "SNMP", 162 => "SNMP-Trap",
                389 => "LDAP", 443 => "HTTPS", 445 => "SMB", 465 => "SMTPS",
                514 => "Syslog", 587 => "SMTP", 636 => "LDAPS", 993 => "IMAPS",
                995 => "POP3S", 1080 => "SOCKS", 1433 => "MSSQL", 1521 => "Oracle",
                1723 => "PPTP", 2049 => "NFS", 3306 => "MySQL", 3389 => "RDP",
                5432 => "PostgreSQL", 5900 => "VNC", 5901 => "VNC", 6379 => "Redis",
                8080 => "HTTP-Proxy", 8443 => "HTTPS-Alt", 8888 => "HTTP-Alt",
                9090 => "Web-Mgmt", 9042 => "Cassandra", 27017 => "MongoDB",
                _ => ""
            };
        }

        // ── Entry point ──
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }

    // ── Result model ──
    public class ScanResult
    {
        public string Host { get; set; }
        public int Port { get; set; }
        public string State { get; set; }
        public string Service { get; set; }
        public string Banner { get; set; }
        public double Latency { get; set; }
    }
}
