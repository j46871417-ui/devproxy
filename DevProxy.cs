using System;
using System.IO;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Diagnostics;

namespace DevProxy
{
    class Program
    {
        static readonly string Version = "v1.0.0";

        static void Main(string[] args)
        {
            if (args.Length > 0 && args[0] == "--daemon")
            {
                RunLocalProxy(args[1]);
                return;
            }

            Console.OutputEncoding = Encoding.UTF8;
            Console.Title = "DevProxy CLI " + Version;

            if (args.Length > 0)
            {
                string arg = args[0].Trim();
                if (arg == "--remove" || arg == "-r" || arg == "clean" || arg == "remove")
                {
                    RemoveAll();
                    return;
                }
                if (arg == "--status" || arg == "-s" || arg == "status")
                {
                    ShowStatus();
                    return;
                }
                if (arg == "--help" || arg == "-h" || arg == "help")
                {
                    ShowHelp();
                    return;
                }
                string norm = NormalizeProxy(arg);
                if (norm != null)
                {
                    ApplyProxy(norm);
                    return;
                }
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[-] Ошибка: Некорректный формат строки прокси.");
                Console.WriteLine("    Поддерживаются: http://user:pass@host:port, host:port:user:pass, socks5://...");
                Console.ResetColor();
                return;
            }

            while (true)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("\n============================================================");
                Console.WriteLine("  [+] DevProxy CLI " + Version + " (Native Windows)");
                Console.WriteLine("      Универсальная настройка Cursor, VS Code, Windsurf, Git");
                Console.WriteLine("============================================================");
                Console.ResetColor();

                Console.WriteLine("  [1] Встроить / обновить прокси (вставить строку или ссылку)");
                Console.WriteLine("  [2] Проверить текущий статус настроек");
                Console.WriteLine("  [3] Отключить / удалить прокси со всех IDE и системы");
                Console.WriteLine("  [0] Выход");
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("------------------------------------------------------------");
                Console.ResetColor();

                Console.Write("Выберите действие [0-3]: ");
                string choice = Console.ReadLine();
                if (choice == null) break;
                choice = choice.Trim();

                if (choice == "1")
                {
                    Console.WriteLine("\nВставьте строку прокси в любом формате:");
                    Console.WriteLine("  - http://username:password@1.2.3.4:8080");
                    Console.WriteLine("  - 1.2.3.4:8080:username:password");
                    Console.WriteLine("  - socks5://1.2.3.4:1080");
                    Console.WriteLine("  - 1.2.3.4:8080");
                    Console.Write("\nПрокси: ");
                    string input = Console.ReadLine();
                    if (!string.IsNullOrEmpty(input))
                    {
                        string norm = NormalizeProxy(input.Trim());
                        if (norm != null)
                        {
                            ApplyProxy(norm);
                        }
                        else
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine("[-] Не удалось распознать формат прокси.");
                            Console.ResetColor();
                        }
                    }
                }
                else if (choice == "2")
                {
                    ShowStatus();
                }
                else if (choice == "3")
                {
                    RemoveAll();
                }
                else if (choice == "0" || choice.ToLower() == "q" || choice.ToLower() == "exit")
                {
                    Console.WriteLine("Завершение работы.");
                    break;
                }
                else
                {
                    Console.WriteLine("Неизвестный пункт меню.");
                }
            }
        }

        static void ShowHelp()
        {
            Console.WriteLine("DevProxy CLI " + Version);
            Console.WriteLine("Универсальная утилита внедрения прокси в среды разработки.\n");
            Console.WriteLine("Использование:");
            Console.WriteLine("  devproxy.exe [ПРОКСИ]           - Применить прокси");
            Console.WriteLine("  devproxy.exe --status          - Показать текущий статус");
            Console.WriteLine("  devproxy.exe --remove          - Очистить настройки прокси");
            Console.WriteLine("  devproxy.exe --help            - Показать эту справку\n");
            Console.WriteLine("Поддерживаемые форматы:");
            Console.WriteLine("  http://user:pass@host:port");
            Console.WriteLine("  host:port:user:pass");
            Console.WriteLine("  socks5://host:port");
            Console.WriteLine("  host:port");
        }

        static string NormalizeProxy(string raw)
        {
            if (string.IsNullOrEmpty(raw)) return null;
            raw = raw.Trim().Trim('"', '\'');

            if (raw.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                raw.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ||
                raw.StartsWith("socks5://", StringComparison.OrdinalIgnoreCase) ||
                raw.StartsWith("socks5h://", StringComparison.OrdinalIgnoreCase))
            {
                return raw;
            }

            string[] parts = raw.Split(':');
            if (parts.Length == 4)
            {
                // host:port:user:pass
                return string.Format("http://{2}:{3}@{0}:{1}", parts[0], parts[1], parts[2], parts[3]);
            }
            if (parts.Length == 2)
            {
                // host:port
                return "http://" + raw;
            }

            return "http://" + raw;
        }

        struct Target
        {
            public string Name;
            public string ConfigPath;
            public Target(string n, string p) { Name = n; ConfigPath = p; }
        }

        static Target[] GetTargets()
        {
            string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            return new Target[]
            {
                new Target("Cursor", Path.Combine(appData, @"Cursor\User\settings.json")),
                new Target("VS Code", Path.Combine(appData, @"Code\User\settings.json")),
                new Target("Windsurf", Path.Combine(appData, @"Windsurf\User\settings.json")),
                new Target("VSCodium", Path.Combine(appData, @"VSCodium\User\settings.json")),
                new Target("Antigravity IDE", Path.Combine(appData, @"Antigravity\User\settings.json"))
            };
        }

        static string StripJsonComments(string json)
        {
            StringBuilder sb = new StringBuilder();
            bool inString = false;
            bool escape = false;

            for (int i = 0; i < json.Length; i++)
            {
                char c = json[i];
                if (inString)
                {
                    sb.Append(c);
                    if (escape) { escape = false; }
                    else if (c == '\\') { escape = true; }
                    else if (c == '"') { inString = false; }
                    continue;
                }

                if (c == '"')
                {
                    inString = true;
                    sb.Append(c);
                    continue;
                }

                if (c == '/' && i + 1 < json.Length)
                {
                    if (json[i + 1] == '/')
                    {
                        // Однострочный комментарий
                        while (i < json.Length && json[i] != '\n') i++;
                        if (i < json.Length) sb.Append(json[i]);
                        continue;
                    }
                    if (json[i + 1] == '*')
                    {
                        // Многострочный комментарий
                        i += 2;
                        while (i + 1 < json.Length && !(json[i] == '*' && json[i + 1] == '/')) i++;
                        i++;
                        continue;
                    }
                }

                sb.Append(c);
            }
            return sb.ToString();
        }

        static bool UpdateIdeSettings(string path, string proxyUrl)
        {
            try
            {
                string dir = Path.GetDirectoryName(path);
                if (!Directory.Exists(dir))
                {
                    Directory.CreateDirectory(dir);
                }

                string content = "{\n}";
                if (File.Exists(path))
                {
                    content = File.ReadAllText(path, Encoding.UTF8);
                    try
                    {
                        File.Copy(path, path + ".bak", true);
                    }
                    catch { }
                }

                content = StripJsonComments(content);

                content = UpsertJsonField(content, "http.proxy", "\"" + EscapeJson(proxyUrl) + "\"");
                content = UpsertJsonField(content, "http.proxyStrictSSL", "true");
                content = UpsertJsonField(content, "http.proxySupport", "\"on\"");

                File.WriteAllText(path, content, Encoding.UTF8);
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("    [!] Ошибка записи: " + ex.Message);
                return false;
            }
        }

        static bool CleanIdeSettings(string path)
        {
            try
            {
                if (!File.Exists(path)) return false;
                string content = File.ReadAllText(path, Encoding.UTF8);
                content = StripJsonComments(content);

                bool changed = false;
                string[] keys = new string[] { "http.proxy", "http.proxyStrictSSL", "http.proxySupport" };
                foreach (string key in keys)
                {
                    string pattern = @"\""" + Regex.Escape(key) + @"\""\s*:\s*(?:\""[^\""]*\""|true|false)\s*,?";
                    if (Regex.IsMatch(content, pattern))
                    {
                        content = Regex.Replace(content, pattern, "");
                        changed = true;
                    }
                }

                if (changed)
                {
                    content = Regex.Replace(content, @",\s*(\})", "$1");
                    File.WriteAllText(path, content, Encoding.UTF8);
                    return true;
                }
                return false;
            }
            catch
            {
                return false;
            }
        }

        static string EscapeJson(string str)
        {
            return str.Replace("\\", "\\\\").Replace("\"", "\\\"");
        }

        static string UpsertJsonField(string json, string key, string valJson)
        {
            string pattern = @"(\""" + Regex.Escape(key) + @"\""\s*:\s*)(?:\""[^\""]*\""|true|false)";
            if (Regex.IsMatch(json, pattern))
            {
                return Regex.Replace(json, pattern, "$1" + valJson);
            }

            int lastBrace = json.LastIndexOf('}');
            if (lastBrace >= 0)
            {
                string before = json.Substring(0, lastBrace).TrimEnd();
                bool needsComma = before.Length > 0 && !before.EndsWith("{") && !before.EndsWith(",");
                string insert = (needsComma ? ",\n" : "\n") + "  \"" + key + "\": " + valJson + "\n";
                return before + insert + json.Substring(lastBrace);
            }

            return "{\n  \"" + key + "\": " + valJson + "\n}";
        }

        static void SetEnvVar(string name, string val)
        {
            try
            {
                Environment.SetEnvironmentVariable(name, val, EnvironmentVariableTarget.User);
                Environment.SetEnvironmentVariable(name, val, EnvironmentVariableTarget.Process);
            }
            catch { }
        }

        static void RunGitCmd(string args)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("git", args)
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                Process p = Process.Start(psi);
                p.WaitForExit(3000);
            }
            catch { }
        }

        static void TestConnection(string proxyUrl)
        {
            Console.Write("  [?] Проверка соединения через прокси... ");
            try
            {
                ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072; // TLS 1.2

                Uri proxyUri = new Uri(proxyUrl);
                WebProxy proxy = new WebProxy(proxyUri.Host, proxyUri.Port);
                if (!string.IsNullOrEmpty(proxyUri.UserInfo))
                {
                    string[] userPass = proxyUri.UserInfo.Split(':');
                    string user = Uri.UnescapeDataString(userPass[0]);
                    string pass = userPass.Length > 1 ? Uri.UnescapeDataString(userPass[1]) : "";
                    proxy.Credentials = new NetworkCredential(user, pass);
                }

                string[] testEndpoints = new string[]
                {
                    "https://generativelanguage.googleapis.com",
                    "https://www.google.com"
                };

                bool ok = false;
                string lastError = "";

                foreach (string endpoint in testEndpoints)
                {
                    try
                    {
                        HttpWebRequest req = (HttpWebRequest)WebRequest.Create(endpoint);
                        req.Timeout = 7000;
                        req.Proxy = proxy;
                        req.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";

                        using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
                        {
                            ok = true;
                            break;
                        }
                    }
                    catch (WebException wex)
                    {
                        HttpWebResponse resp = wex.Response as HttpWebResponse;
                        if (resp != null)
                        {
                            int code = (int)resp.StatusCode;
                            if (code == 200 || code == 404 || code == 400)
                            {
                                ok = true;
                                break;
                            }
                        }
                        lastError = wex.Message;
                    }
                }

                if (ok)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("УСПЕХ! Прокси работает корректно.");
                    Console.ResetColor();
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("ПРЕДУПРЕЖДЕНИЕ: " + lastError);
                    Console.ResetColor();
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("ПРЕДУПРЕЖДЕНИЕ: " + ex.Message);
                Console.ResetColor();
            }
        }

        
        static readonly string[] AiDomains = {
            "googleapis.com", "google.com", "google.dev", "gstatic.com",
            "openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com",
            "anthropic.com", "claude.ai", "claudeusercontent.com",
            "x.ai", "grok.com", "sora.com", "cursor.sh", "cursor.com",
            "windsurf.ai", "codeium.com", "githubcopilot.com", "perplexity.ai",
            "huggingface.co", "midjourney.com"
        };

        static bool IsAiDomain(string host)
        {
            host = host.ToLower();
            if (host.Contains(":")) host = host.Split(':')[0];
            foreach (var d in AiDomains)
            {
                if (host == d || host.EndsWith("." + d)) return true;
            }
            return false;
        }

        static void RunLocalProxy(string upstreamUrl)
        {
            var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 11438);
            listener.Start();
            Console.WriteLine("Local AI Split Proxy listening on 127.0.0.1:11438");
            Console.WriteLine("Upstream: " + upstreamUrl);
            while (true)
            {
                var client = listener.AcceptTcpClient();
                System.Threading.ThreadPool.QueueUserWorkItem(state => HandleClient(client, upstreamUrl));
            }
        }

        static void HandleClient(System.Net.Sockets.TcpClient client, string upstreamUrl)
        {
            try
            {
                var stream = client.GetStream();
                byte[] buffer = new byte[8192];
                int bytesRead = stream.Read(buffer, 0, buffer.Length);
                if (bytesRead == 0) { client.Close(); return; }

                string request = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                string[] lines = request.Split(new[] { "\r\n" }, StringSplitOptions.None);
                string[] firstLine = lines[0].Split(' ');
                string method = firstLine[0];
                string url = firstLine[1];

                string host = "";
                int port = 80;

                if (method == "CONNECT")
                {
                    string[] hp = url.Split(':');
                    host = hp[0];
                    port = hp.Length > 1 ? int.Parse(hp[1]) : 443;
                }
                else
                {
                    foreach (var line in lines)
                    {
                        if (line.ToLower().StartsWith("host:"))
                        {
                            string h = line.Substring(5).Trim();
                            if (h.Contains(":"))
                            {
                                host = h.Split(':')[0];
                                port = int.Parse(h.Split(':')[1]);
                            }
                            else
                            {
                                host = h;
                            }
                            break;
                        }
                    }
                }

                bool useProxy = IsAiDomain(host);
                var remoteClient = new System.Net.Sockets.TcpClient();

                if (useProxy)
                {
                    Uri uri = new Uri(upstreamUrl);
                    remoteClient.Connect(uri.Host, uri.Port);
                    var remoteStream = remoteClient.GetStream();

                    if (method == "CONNECT")
                    {
                        string auth = "";
                        if (!string.IsNullOrEmpty(uri.UserInfo))
                        {
                            string b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(uri.UserInfo));
                            auth = "Proxy-Authorization: Basic " + b64 + "\r\n";
                        }
                        string connectReq = "CONNECT " + host + ":" + port + " HTTP/1.1\r\nHost: " + host + ":" + port + "\r\n" + auth + "\r\n";
                        byte[] reqBytes = Encoding.UTF8.GetBytes(connectReq);
                        remoteStream.Write(reqBytes, 0, reqBytes.Length);

                        byte[] respBuffer = new byte[8192];
                        int respRead = remoteStream.Read(respBuffer, 0, respBuffer.Length);
                        string respStr = Encoding.UTF8.GetString(respBuffer, 0, respRead);
                        if (!respStr.Contains("200 Connection"))
                        {
                            byte[] errBytes = Encoding.UTF8.GetBytes("HTTP/1.1 502 Bad Gateway\r\n\r\n");
                            stream.Write(errBytes, 0, errBytes.Length);
                            client.Close();
                            remoteClient.Close();
                            return;
                        }
                        byte[] okBytes = Encoding.UTF8.GetBytes("HTTP/1.1 200 Connection established\r\n\r\n");
                        stream.Write(okBytes, 0, okBytes.Length);
                    }
                    else
                    {
                        if (!string.IsNullOrEmpty(uri.UserInfo))
                        {
                            string b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(uri.UserInfo));
                            string authHeader = "Proxy-Authorization: Basic " + b64 + "\r\n";
                            int idx = request.IndexOf("\r\n");
                            request = request.Insert(idx + 2, authHeader);
                            byte[] reqBytes = Encoding.UTF8.GetBytes(request);
                            remoteStream.Write(reqBytes, 0, reqBytes.Length);
                        }
                        else
                        {
                            remoteStream.Write(buffer, 0, bytesRead);
                        }
                    }
                }
                else
                {
                    remoteClient.Connect(host, port);
                    var remoteStream = remoteClient.GetStream();
                    if (method == "CONNECT")
                    {
                        byte[] okBytes = Encoding.UTF8.GetBytes("HTTP/1.1 200 Connection established\r\n\r\n");
                        stream.Write(okBytes, 0, okBytes.Length);
                    }
                    else
                    {
                        remoteStream.Write(buffer, 0, bytesRead);
                    }
                }

                System.Threading.Tasks.Task.Run(() => {
                    try { stream.CopyTo(remoteClient.GetStream()); } catch { }
                });
                System.Threading.Tasks.Task.Run(() => {
                    try { remoteClient.GetStream().CopyTo(stream); } catch { }
                });
            }
            catch
            {
                client.Close();
            }
        }

        static void ApplyProxy(string proxyUrl)
        {
            Console.WriteLine("\n[+] Применяем прокси: " + proxyUrl);

            // 1. IDEs
            foreach (Target t in GetTargets())
            {
                string dir = Path.GetDirectoryName(t.ConfigPath);
                bool exists = Directory.Exists(dir) || File.Exists(t.ConfigPath);
                bool ok = UpdateIdeSettings(t.ConfigPath, proxyUrl);
                if (ok)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("  [✓] " + t.Name + (exists ? " (обновлен)" : " (создан конфиг)"));
                    Console.ResetColor();
                }
            }

            // 2. Windows Environment
            SetEnvVar("HTTP_PROXY", proxyUrl);
            SetEnvVar("HTTPS_PROXY", proxyUrl);
            SetEnvVar("ALL_PROXY", proxyUrl);
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  [✓] Системные переменные пользователя (HTTP_PROXY, HTTPS_PROXY, ALL_PROXY)");
            Console.ResetColor();

            // 3. Git
            RunGitCmd("config --global http.proxy \"" + proxyUrl + "\"");
            RunGitCmd("config --global https.proxy \"" + proxyUrl + "\"");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  [✓] Глобальная конфигурация Git (http.proxy, https.proxy)");
            Console.ResetColor();

            // 4. Test
            TestConnection(proxyUrl);

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("\n[✓] ГОТОВО! Прокси успешно внедрен во все редакторы и терминал.");
            Console.ResetColor();
            Console.WriteLine("    (Если редактор уже запущен, перезапустите его или нажмите Reload Window)");
        }

        static void ShowStatus()
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("\n=== ТЕКУЩИЙ СТАТУС НАСТРОЕК ПРОКСИ ===");
            Console.ResetColor();

            foreach (Target t in GetTargets())
            {
                string status = "не настроен";
                if (File.Exists(t.ConfigPath))
                {
                    string text = File.ReadAllText(t.ConfigPath);
                    Match m = Regex.Match(text, @"\""http\.proxy\""\s*:\s*\""([^\""]+)\""");
                    if (m.Success)
                    {
                        status = m.Groups[1].Value;
                    }
                }
                Console.WriteLine("  * {0,-16}: {1}", t.Name, status);
            }

            string envHttp = Environment.GetEnvironmentVariable("HTTP_PROXY", EnvironmentVariableTarget.User) ?? "не задана";
            Console.WriteLine("  * {0,-16}: {1}", "HTTP_PROXY", envHttp);

            string envHttps = Environment.GetEnvironmentVariable("HTTPS_PROXY", EnvironmentVariableTarget.User) ?? "не задана";
            Console.WriteLine("  * {0,-16}: {1}", "HTTPS_PROXY", envHttps);

            Console.WriteLine();
        }

        static void RemoveAll()
        {
            Console.WriteLine("\n[-] Сбрасываем и удаляем прокси со всех сред...");

            foreach (Target t in GetTargets())
            {
                if (CleanIdeSettings(t.ConfigPath))
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("  [x] Очищено: " + t.Name);
                    Console.ResetColor();
                }
            }

            SetEnvVar("HTTP_PROXY", null);
            SetEnvVar("HTTPS_PROXY", null);
            SetEnvVar("ALL_PROXY", null);
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  [x] Сброшены системные переменные Windows");
            Console.ResetColor();

            RunGitCmd("config --global --unset http.proxy");
            RunGitCmd("config --global --unset https.proxy");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  [x] Сброшен глобальный конфиг Git");
            Console.ResetColor();

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("\n[✓] Все настройки прокси успешно удалены.");
            Console.ResetColor();
        }
    }
}
