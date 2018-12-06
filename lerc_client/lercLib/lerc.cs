using System;
using System.Collections.Concurrent;
using System.Collections.Specialized;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

namespace lercLib
{
    public static class lerc
    {
        #region PROPERTIES
        static X509Certificate2 clientCertificate;
        static X509Chain caChain;
        static string host;
        public static string lastServerUsed;
        public volatile static bool quit;
        static StringDictionary config;
        static string defaultServerUrl;
        static string version;
        #endregion

        // initialize lerc
        static lerc()
        {
            // get uri encoded host name
            host = Uri.EscapeUriString(Environment.MachineName);

            defaultServerUrl = ConfigurationManager.AppSettings["defaultServerUrl"];

            version = Assembly.GetExecutingAssembly().GetName().Version.ToString();

            // load config
            LoadConfig();

            // load the client certificate
            string assemblyLocation = Assembly.GetExecutingAssembly().Location;
            string workDir = Path.GetDirectoryName(assemblyLocation);
            string certPath = Path.Combine(workDir, "lerc.client.pfx");
            clientCertificate = new X509Certificate2(certPath);

            // load the trusted ca certificate chian
            caChain = new X509Chain();
            caChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            caChain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            string trustedCertPath = Path.Combine(workDir, "lerc.ca.pem");
            string b64String = "";
            foreach (string line in File.ReadLines(trustedCertPath))
            {
                if (line == "-----BEGIN CERTIFICATE-----")
                {
                    b64String = "";
                } else if (line == "-----END CERTIFICATE-----")
                {
                    caChain.ChainPolicy.ExtraStore.Insert(0, new X509Certificate2(Convert.FromBase64String(b64String)));
                } else
                {
                    b64String += line;
                }
            }
        }

        // loads config dictionary from file
        static void LoadConfig()
        {
            // read config
            config = new StringDictionary();
            string exeDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            string configPath = Path.Combine(exeDir, "config.txt");

            if (File.Exists(configPath))
            {
                try
                {
                    using (StreamReader sr = new StreamReader(configPath))
                    {
                        string line;
                        while ((line = sr.ReadLine()) != null)
                        {
                            char[] delimeters = new char[1] { ':' };
                            string[] kv = line.Split(delimeters, 2);
                            config.Add(kv[0], kv[1].Trim());
                        }
                    }
                }
                catch (Exception e)
                {
                    Log.Error("Error: Failed to load config: " + e.Message);
                }
            }
        }

        static string ConfigGetString(string key, string defaultValue)
        {
            if (config.ContainsKey(key) && config[key] != "") {
                return config[key];
            }
            return defaultValue;
        }

        static int ConfigGetInt(string key, int defaultValue)
        {
            if (config.ContainsKey(key) && config[key] != "")
            {
                int value;
                int.TryParse(config[key], out value);
                return value;
            }
            return defaultValue;
        }

        // clears the cahced protocol version to prevent ProtocolViolationException from being raised
        public static void ClearServicePointCache(ServicePoint servicePoint)
        {
            int maxIdleTime = servicePoint.MaxIdleTime;
            servicePoint.MaxIdleTime = 0;
            Thread.Sleep(10);
            servicePoint.MaxIdleTime = maxIdleTime;
        }

        // return true if the server cert is signed with the CA, false otherwise
        public static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            // build the chain
            if (!caChain.Build(new X509Certificate2(certificate)))
                return false;

            // Make sure we have the same number of elements.
            if (caChain.ChainElements.Count != caChain.ChainPolicy.ExtraStore.Count + 1)
                return false;

            // Make sure all the thumbprints of the CAs match up.
            for (var i = 1; i < caChain.ChainElements.Count; i++)
            {
                if (caChain.ChainElements[i].Certificate.Thumbprint != caChain.ChainPolicy.ExtraStore[i - 1].Thumbprint)
                    return false;
            }

            return true;
        }

        // extension method for web request to get the request stream with a proper timeout
        public static Stream GetRequestStreamWithTimeout(this WebRequest request)
        {
            IAsyncResult worker = request.BeginGetRequestStream(null, null);
            if (!worker.AsyncWaitHandle.WaitOne(request.Timeout))
            {
                TimeoutException ex = new TimeoutException();
                throw new WebException(ex.Message, ex, WebExceptionStatus.Timeout, null);
            }
            return request.EndGetRequestStream(worker);
        }

        // extension method for web request to get the response with a proper timeout
        public static WebResponse GetResponseWithTimeout(this HttpWebRequest request)
        {
            IAsyncResult worker = request.BeginGetResponse(null, null);
            if (!worker.AsyncWaitHandle.WaitOne(request.Timeout))
            {
                TimeoutException ex = new TimeoutException();
                throw new WebException(ex.Message, ex, WebExceptionStatus.Timeout, null);
            }
            return request.EndGetResponse(worker);
        }

        // fetches the next instruction to execute from the server
        public static Instruction FetchInstruction()
        {
            // reload config in case it has changed
            LoadConfig();

            string[] serverUrls = ConfigGetString("serverurls", defaultServerUrl).Split(',');
            for (int i = 0; i < serverUrls.Length; i++)
            {
                try
                {
                    lastServerUsed = serverUrls[i];
                    string url = lastServerUsed + "fetch?host=" + host + "&company=" + ConfigGetString("company", "0") + "&version=" + version;
                    Log.Trace("GET " + url);
                    HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
                    request.ClientCertificates.Add(clientCertificate);
                    request.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(ValidateServerCertificate);
                    request.Method = "GET";
                    request.Proxy = new WebProxy();
                    ClearServicePointCache(request.ServicePoint);

                    HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                    if (response.StatusCode == HttpStatusCode.OK)
                    {
                        using (StreamReader responseStream = new StreamReader(response.GetResponseStream()))
                        {
                            Instruction instruction = Json.Load<Instruction>(responseStream.ReadToEnd());
                            if (instruction != null)
                            {
                                return instruction;
                            } else
                            {
                                Log.Error("Error: empty response");
                            }
                        }
                    } else
                    {
                        Log.Debug("Error: (" + response.StatusCode + ") " + response.StatusDescription);
                    }
                }
                catch (Exception e)
                {
                    Log.Debug("Error: " + e.Message);
                }
            }

            // return default instruction
            Instruction defaultInstruction = new Instruction();
            defaultInstruction.operation = "sleep";
            defaultInstruction.seconds = ConfigGetInt("reconnectdelay", 60);
            lastServerUsed = "None";
            return defaultInstruction;
        }

        // sends an error message to the server
        public static void SendErrorMessage(string id, string message)
        {
            try
            {
                string uri = lastServerUsed + "error?host=" + host + "&company=" + ConfigGetString("company", "0") + "&id=" + id + "&version=" + version;
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(uri);
                request.ClientCertificates.Add(clientCertificate);
                request.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(ValidateServerCertificate);
                request.Method = "POST";
                request.Proxy = new WebProxy();
                ClearServicePointCache(request.ServicePoint);

                using (StreamWriter requestStream = new StreamWriter(request.GetRequestStream()))
                {
                    requestStream.Write(message);
                }

                request.GetResponse(); // sends the request
            }
            catch { } // ignore further errors
        }
        
        // runs a shell command and optionally pipes the output back to the server
        public static void RunCommand(string id, string command, bool async)
        {
            string uri;
            HttpWebRequest request;

            // run the command
            Process cmd = new Process();
            cmd.StartInfo.FileName = "cmd.exe";
            cmd.StartInfo.Arguments = "/C " + command;
            cmd.StartInfo.CreateNoWindow = true;
            cmd.StartInfo.UseShellExecute = false;

            if (async)
            {
                cmd.Start();
            }
            else
            {
                ConcurrentQueue<string> output = new ConcurrentQueue<string>();
                DataReceivedEventHandler QueueOutput = new DataReceivedEventHandler((sender, e) => {
                    if (e.Data != null) { output.Enqueue(e.Data + "\n"); }
                });
                cmd.StartInfo.RedirectStandardInput = true;
                cmd.StartInfo.RedirectStandardOutput = true;
                cmd.StartInfo.RedirectStandardError = true;
                cmd.OutputDataReceived += QueueOutput;
                cmd.ErrorDataReceived += QueueOutput;
                cmd.Start();
                cmd.BeginErrorReadLine();
                cmd.BeginOutputReadLine();

                int lastSendTime = Environment.TickCount;
                while (!cmd.HasExited || !output.IsEmpty)
                {
                    using (MemoryStream buffer = new MemoryStream())
                    {
                        while (!output.IsEmpty)
                        {
                            string line;
                            if (output.TryDequeue(out line))
                            {
                                byte[] data = Encoding.UTF8.GetBytes(line);
                                buffer.Write(data, 0, data.Length);
                                buffer.Flush();
                            }
                        }

                        buffer.Seek(0, SeekOrigin.Begin);
                        if (buffer.Length > 0 || lastSendTime + 60000 < Environment.TickCount)
                        {
                            lastSendTime = Environment.TickCount;

                            string company = ConfigGetString("company", "0");
                            uri = lastServerUsed + "pipe?host=" + host + "&company=" + company + "&id=" + id + "&size=" + buffer.Length + "&done=false&version=" + version;
                            request = (HttpWebRequest)WebRequest.Create(uri);
                            request.ClientCertificates.Add(clientCertificate);
                            request.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(ValidateServerCertificate);
                            request.Method = "POST";
                            request.Proxy = new WebProxy();
                            request.AllowWriteStreamBuffering = false;
                            request.SendChunked = true;
                            ClearServicePointCache(request.ServicePoint);

                            using (Stream requestStream = request.GetRequestStreamWithTimeout())
                            {
                                int chunksize = ConfigGetInt("chunksize", 2048);
                                byte[] data = new byte[chunksize];
                                int bytesRead;
                                while ((bytesRead = buffer.Read(data, 0, chunksize)) > 0)
                                {
                                    requestStream.Write(data, 0, bytesRead);
                                    requestStream.Flush();
                                }
                            }

                            // wait for response
                            request.GetResponseWithTimeout();
                        }
                        Thread.Sleep(1000);
                    }
                }
            }

            // inform that the command is done
            uri = lastServerUsed + "pipe?host=" + host + "&company=" + ConfigGetString("company", "0") + "&id=" + id + "&size=0&done=true&version=" + version;
            request = (HttpWebRequest)WebRequest.Create(uri);
            request.ClientCertificates.Add(clientCertificate);
            request.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(ValidateServerCertificate);
            request.Method = "POST";
            request.Proxy = new WebProxy();
            request.AllowWriteStreamBuffering = false;
            request.SendChunked = true;
            ClearServicePointCache(request.ServicePoint);

            using (Stream requestStream = request.GetRequestStreamWithTimeout())
            {
            }

            // wait for response
            request.GetResponseWithTimeout();
        }

        // uploads the file at the specified path to the server starting from position
        public static void UploadFile(string id, string path, long position)
        {
            // open the target file
            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                // seek to the desired starting position
                fs.Seek(position, SeekOrigin.Begin);

                string uri = lastServerUsed + "upload?host=" + host + "&company=" + ConfigGetString("company", "0") + "&id=" + id + "&size=" + fs.Length + "&version=" + version;
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(uri);
                request.ClientCertificates.Add(clientCertificate);
                request.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(ValidateServerCertificate);
                request.Method = "POST";
                request.Proxy = new WebProxy();
                request.AllowWriteStreamBuffering = false;
                request.SendChunked = true;
                ClearServicePointCache(request.ServicePoint);

                // stream the file to the server in chunks
                using (Stream requestStream = request.GetRequestStreamWithTimeout())
                {
                    int chunksize = ConfigGetInt("chunksize", 2048);
                    byte[] data = new byte[chunksize];
                    int bytesRead;
                    while ((bytesRead = fs.Read(data, 0, chunksize)) > 0)
                    {
                        requestStream.Write(data, 0, bytesRead);
                        requestStream.Flush();
                    }
                }

                // wait for response
                request.GetResponseWithTimeout();
            }
        }

        // downloads a file from the server to the specified path
        public static void DownloadFile(string id, string path)
        {
            // open or create the target file
            using (FileStream fs = new FileStream(path, FileMode.Append, FileAccess.Write))
            {
                // get the current position in the file
                long position = fs.Position;

                // send the current position to the server as a query string variable
                string uri = lastServerUsed + "download?host=" + host + "&company=" + ConfigGetString("company", "0") + "&id=" + id + "&position=" + position + "&version=" + version;
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(uri);
                request.ClientCertificates.Add(clientCertificate);
                request.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(ValidateServerCertificate);
                request.Method = "GET";
                request.Proxy = new WebProxy();
                request.AllowReadStreamBuffering = false;
                ClearServicePointCache(request.ServicePoint);

                // write data stream from server to file
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                using (Stream responseStream = response.GetResponseStream())
                {
                    int chunksize = ConfigGetInt("chunksize", 2048);
                    byte[] data = new byte[chunksize];
                    int bytesRead;
                    while ((bytesRead = responseStream.Read(data, 0, chunksize)) > 0)
                    {
                        fs.Write(data, 0, bytesRead);
                        fs.Flush();
                    }
                }
            }
        }

        // terminates lerc and disables auto start
        public static void Quit()
        {
            // start a process to uninstall the service
            Process cmd = new Process();
            cmd.StartInfo.FileName = "msiexec.exe";
            cmd.StartInfo.Arguments = "/quiet /qn /x {01B30771-E563-4EE3-9689-AC6A56BA6343}";
            cmd.StartInfo.CreateNoWindow = true;
            cmd.StartInfo.UseShellExecute = false;
            cmd.Start();

            // stop service
            quit = true;
        }
    }
}