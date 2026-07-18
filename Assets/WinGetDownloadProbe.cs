// Copyright (c) Microsoft Corporation and Dumplings contributors.
// Licensed under the MIT License.
//
// The call sequence follows winget-cli's MIT-licensed Downloader.cpp and
// DODownloader.cpp. This file contains an independent C# interop implementation.

using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Dumplings.WinGetDownload
{
    public sealed class DownloadResult
    {
        public string Method { get; set; }
        public bool Success { get; set; }
        public bool ResponseAccepted { get; set; }
        public bool Completed { get; set; }
        public string Uri { get; set; }
        public string FinalUri { get; set; }
        public string DestinationPath { get; set; }
        public string UserAgent { get; set; }
        public int? HttpStatusCode { get; set; }
        public string ContentType { get; set; }
        public long? ContentLength { get; set; }
        public long BytesDownloaded { get; set; }
        public string Sha256 { get; set; }
        public string ResponseHeaders { get; set; }
        public string ServerIPAddress { get; set; }
        public int HResult { get; set; }
        public int NativeErrorCode { get; set; }
        public string FailureStage { get; set; }
        public string ErrorMessage { get; set; }
        public string DeliveryOptimizationState { get; set; }
        public int DeliveryOptimizationExtendedError { get; set; }
        public bool IsFatalDeliveryOptimizationError { get; set; }
        public int AttemptCount { get; set; }
        public bool Cancelled { get; set; }
        public bool TimedOut { get; set; }
        public bool FallbackOccurred { get; set; }
        public string PreviousFailure { get; set; }
    }

    public static class DownloadFailureFormatter
    {
        public static string Format(string method, DownloadResult result, Exception exception)
        {
            string prefix = string.IsNullOrWhiteSpace(method) ? "Download" : method;
            if (exception != null) return prefix + ": " + exception.Message;
            if (result == null) return prefix + ": the download did not complete successfully";

            List<string> details = new List<string>();
            if (result.HttpStatusCode.HasValue) details.Add("HTTP " + result.HttpStatusCode.Value);
            if (!string.IsNullOrWhiteSpace(result.ErrorMessage)) details.Add(result.ErrorMessage);
            if (!string.IsNullOrWhiteSpace(result.FailureStage)) details.Add("stage " + result.FailureStage);
            if (result.HResult != 0) details.Add("HRESULT 0x" + unchecked((uint)result.HResult).ToString("X8"));
            if (result.NativeErrorCode != 0) details.Add("native error " + result.NativeErrorCode);
            return details.Count == 0 ? prefix + ": the download did not complete successfully" : prefix + ": " + string.Join("; ", details);
        }
    }

    public sealed class DownloadProgressSnapshot
    {
        public long BytesDownloaded { get; internal set; }
        public long? ContentLength { get; internal set; }
        public string State { get; internal set; }
    }

    public sealed class DownloadOperation : IDisposable
    {
        private readonly CancellationTokenSource cancellation = new CancellationTokenSource();
        private readonly object sync = new object();
        private Task<DownloadResult> task;
        private Action cancellationAction;
        private long bytesDownloaded;
        private long? contentLength;
        private string state = "Starting";

        private DownloadOperation() { }

        internal static DownloadOperation Start(Func<DownloadOperation, DownloadResult> callback)
        {
            DownloadOperation operation = new DownloadOperation();
            operation.task = Task.Run(() => callback(operation));
            return operation;
        }

        public bool IsCompleted { get { return task.IsCompleted; } }
        public DownloadResult Result { get { return task.GetAwaiter().GetResult(); } }
        public bool Wait(int milliseconds) { return task.Wait(milliseconds); }

        public DownloadProgressSnapshot GetProgress()
        {
            lock (sync)
            {
                return new DownloadProgressSnapshot
                {
                    BytesDownloaded = bytesDownloaded,
                    ContentLength = contentLength,
                    State = state,
                };
            }
        }

        public void Cancel()
        {
            if (!cancellation.IsCancellationRequested) cancellation.Cancel();
            Action action;
            lock (sync) action = cancellationAction;
            if (action != null)
            {
                try { action(); }
                catch { }
            }
        }

        internal void ThrowIfCancellationRequested() { cancellation.Token.ThrowIfCancellationRequested(); }

        internal void UpdateProgress(long bytes, long? total, string currentState)
        {
            lock (sync)
            {
                bytesDownloaded = bytes;
                contentLength = total;
                state = currentState;
            }
        }

        internal void SetCancellationAction(Action action)
        {
            lock (sync) cancellationAction = action;
            if (cancellation.IsCancellationRequested && action != null) action();
        }

        internal void ClearCancellationAction()
        {
            lock (sync) cancellationAction = null;
        }

        public void Dispose() { if (!IsCompleted) Cancel(); }
    }

    internal static class Hashing
    {
        internal static void Populate(DownloadResult result, DownloadOperation operation)
        {
            using (FileStream stream = new FileStream(result.DestinationPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (IncrementalHash sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
            {
                operation.UpdateProgress(stream.Length, stream.Length, "Hashing");
                byte[] buffer = new byte[1024 * 1024];
                int count;
                while ((count = stream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    operation.ThrowIfCancellationRequested();
                    sha256.AppendData(buffer, 0, count);
                }
                byte[] hash = sha256.GetHashAndReset();
                result.BytesDownloaded = stream.Length;
                result.Sha256 = BitConverter.ToString(hash).Replace("-", string.Empty);
            }
        }
    }

    public static class WinInetDownloader
    {
        private const uint INTERNET_OPEN_TYPE_PRECONFIG = 0;
        private const uint INTERNET_OPEN_TYPE_PROXY = 3;
        private const uint INTERNET_SERVICE_HTTP = 3;
        private const uint INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS = 0x00004000;
        private const uint INTERNET_FLAG_SECURE = 0x00800000;
        private const uint INTERNET_FLAG_NO_CACHE_WRITE = 0x04000000;
        private const uint INTERNET_FLAG_RELOAD = 0x80000000;
        private const uint INTERNET_OPTION_CONNECT_TIMEOUT = 2;
        private const uint INTERNET_OPTION_SEND_TIMEOUT = 5;
        private const uint INTERNET_OPTION_RECEIVE_TIMEOUT = 6;
        private const uint HTTP_QUERY_CONTENT_TYPE = 1;
        private const uint HTTP_QUERY_CONTENT_LENGTH = 5;
        private const uint HTTP_QUERY_STATUS_CODE = 19;
        private const uint HTTP_QUERY_RAW_HEADERS_CRLF = 22;
        private const uint HTTP_QUERY_FLAG_NUMBER = 0x20000000;
        private const uint INTERNET_OPTION_URL = 34;
        private const int ERROR_INSUFFICIENT_BUFFER = 122;
        private const int ERROR_CANCELLED = 1223;
        private const int ERROR_INTERNET_OPERATION_CANCELLED = 12017;

        [DllImport("wininet.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr InternetOpenW(string agent, uint accessType, string proxy, string proxyBypass, uint flags);

        [DllImport("wininet.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr InternetOpenUrlW(IntPtr internet, string url, string headers, uint headersLength, uint flags, UIntPtr context);

        [DllImport("wininet.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr InternetConnectW(IntPtr internet, string serverName, ushort serverPort, string userName, string password, uint service, uint flags, UIntPtr context);

        [DllImport("wininet.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr HttpOpenRequestW(IntPtr connect, string verb, string objectName, string version, string referrer, IntPtr acceptTypes, uint flags, UIntPtr context);

        [DllImport("wininet.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool HttpSendRequestW(IntPtr request, string headers, uint headersLength, IntPtr optional, uint optionalLength);

        [DllImport("wininet.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool InternetReadFile(IntPtr file, byte[] buffer, uint bytesToRead, out uint bytesRead);

        [DllImport("wininet.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool HttpQueryInfoW(IntPtr request, uint infoLevel, IntPtr buffer, ref uint bufferLength, IntPtr index);

        [DllImport("wininet.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool InternetQueryOptionW(IntPtr internet, uint option, IntPtr buffer, ref uint bufferLength);

        [DllImport("wininet.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool InternetSetOptionW(IntPtr internet, uint option, IntPtr buffer, uint bufferLength);

        [DllImport("wininet.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool InternetCloseHandle(IntPtr internet);

        private static int HResultFromWin32(int error)
        {
            return error <= 0 ? error : unchecked((int)(0x80070000u | ((uint)error & 0xFFFFu)));
        }

        private static int HttpHResult(int status)
        {
            return unchecked((int)(0x80190000u | ((uint)status & 0xFFFFu)));
        }

        private static void SetTimeout(IntPtr handle, uint option, int seconds)
        {
            if (seconds < 0) return;
            int milliseconds = seconds == 0 || seconds >= int.MaxValue / 1000 ? int.MaxValue : seconds * 1000;
            IntPtr value = Marshal.AllocHGlobal(sizeof(int));
            try
            {
                Marshal.WriteInt32(value, milliseconds);
                if (!InternetSetOptionW(handle, option, value, sizeof(int)))
                {
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "InternetSetOptionW failed.");
                }
            }
            finally { Marshal.FreeHGlobal(value); }
        }

        private sealed class NativeHandleState
        {
            private readonly object sync = new object();
            private IntPtr session;
            private IntPtr connection;
            private IntPtr request;

            internal void SetSession(IntPtr value) { lock (sync) session = value; }
            internal void SetConnection(IntPtr value) { lock (sync) connection = value; }
            internal void SetRequest(IntPtr value) { lock (sync) request = value; }

            internal void Close()
            {
                IntPtr requestToClose;
                IntPtr connectionToClose;
                IntPtr sessionToClose;
                lock (sync)
                {
                    requestToClose = request;
                    connectionToClose = connection;
                    sessionToClose = session;
                    request = IntPtr.Zero;
                    connection = IntPtr.Zero;
                    session = IntPtr.Zero;
                }
                if (requestToClose != IntPtr.Zero) InternetCloseHandle(requestToClose);
                if (connectionToClose != IntPtr.Zero) InternetCloseHandle(connectionToClose);
                if (sessionToClose != IntPtr.Zero) InternetCloseHandle(sessionToClose);
            }
        }

        private static string BuildHeaders(IDictionary<string, string> requestHeaders)
        {
            StringBuilder headerBuilder = new StringBuilder();
            if (requestHeaders != null)
            {
                foreach (KeyValuePair<string, string> header in requestHeaders)
                {
                    headerBuilder.Append(header.Key).Append(": ").Append(header.Value).Append("\r\n");
                }
            }
            return headerBuilder.ToString();
        }

        private static string QueryString(IntPtr request, uint query)
        {
            uint bytes = 0;
            HttpQueryInfoW(request, query, IntPtr.Zero, ref bytes, IntPtr.Zero);
            if (bytes == 0 || Marshal.GetLastWin32Error() != ERROR_INSUFFICIENT_BUFFER) return null;
            IntPtr buffer = Marshal.AllocHGlobal(checked((int)bytes + 2));
            try
            {
                if (!HttpQueryInfoW(request, query, buffer, ref bytes, IntPtr.Zero)) return null;
                return Marshal.PtrToStringUni(buffer, checked((int)bytes / 2)).TrimEnd('\0');
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        private static string QueryOptionString(IntPtr request, uint option)
        {
            uint bytes = 0;
            InternetQueryOptionW(request, option, IntPtr.Zero, ref bytes);
            if (bytes == 0 || Marshal.GetLastWin32Error() != ERROR_INSUFFICIENT_BUFFER) return null;
            IntPtr buffer = Marshal.AllocHGlobal(checked((int)bytes));
            try
            {
                if (!InternetQueryOptionW(request, option, buffer, ref bytes)) return null;
                return Marshal.PtrToStringUni(buffer).TrimEnd('\0');
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        public static DownloadOperation StartDownload(string uri, string destinationPath, string userAgent, IDictionary<string, string> requestHeaders, string proxy, bool responseOnly, int connectionTimeoutSeconds, int operationTimeoutSeconds)
        {
            return DownloadOperation.Start(operation => DownloadCore(uri, destinationPath, userAgent, requestHeaders, proxy, responseOnly, connectionTimeoutSeconds, operationTimeoutSeconds, operation));
        }

        public static DownloadResult Download(string uri, string destinationPath, string userAgent, IDictionary<string, string> requestHeaders, string proxy, bool responseOnly)
        {
            using (DownloadOperation operation = StartDownload(uri, destinationPath, userAgent, requestHeaders, proxy, responseOnly, 0, 0)) return operation.Result;
        }

        public static DownloadOperation StartRedirectResolution(string uri, string method, string userAgent, IDictionary<string, string> requestHeaders, string proxy, int connectionTimeoutSeconds, int operationTimeoutSeconds)
        {
            return DownloadOperation.Start(operation => ResolveRedirectCore(uri, method, userAgent, requestHeaders, proxy, connectionTimeoutSeconds, operationTimeoutSeconds, operation));
        }

        private static DownloadResult ResolveRedirectCore(string uri, string method, string userAgent, IDictionary<string, string> requestHeaders, string proxy, int connectionTimeoutSeconds, int operationTimeoutSeconds, DownloadOperation operation)
        {
            DownloadResult result = new DownloadResult
            {
                Method = "WinINet",
                Uri = uri,
                UserAgent = userAgent,
            };

            NativeHandleState handles = new NativeHandleState();
            string stage = "ValidateRequest";
            try
            {
                string normalizedMethod = (method ?? string.Empty).ToUpperInvariant();
                if (normalizedMethod != "GET" && normalizedMethod != "HEAD") throw new ArgumentException("WinINet redirect resolution supports only GET and HEAD.", "method");
                Uri requestUri = new Uri(uri, UriKind.Absolute);
                if (requestUri.Scheme != Uri.UriSchemeHttp && requestUri.Scheme != Uri.UriSchemeHttps) throw new ArgumentException("WinINet redirect resolution requires an HTTP or HTTPS URI.", "uri");

                operation.UpdateProgress(0, null, "Connecting");
                operation.SetCancellationAction(handles.Close);
                operation.ThrowIfCancellationRequested();

                stage = "OpenSession";
                uint accessType = string.IsNullOrEmpty(proxy) ? INTERNET_OPEN_TYPE_PRECONFIG : INTERNET_OPEN_TYPE_PROXY;
                IntPtr session = InternetOpenW(userAgent, accessType, string.IsNullOrEmpty(proxy) ? null : proxy, null, 0);
                if (session == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "InternetOpenW failed.");
                handles.SetSession(session);
                SetTimeout(session, INTERNET_OPTION_CONNECT_TIMEOUT, connectionTimeoutSeconds);
                SetTimeout(session, INTERNET_OPTION_SEND_TIMEOUT, operationTimeoutSeconds);
                SetTimeout(session, INTERNET_OPTION_RECEIVE_TIMEOUT, operationTimeoutSeconds);

                stage = "Connect";
                operation.ThrowIfCancellationRequested();
                IntPtr connection = InternetConnectW(session, requestUri.DnsSafeHost, checked((ushort)requestUri.Port), null, null, INTERNET_SERVICE_HTTP, 0, UIntPtr.Zero);
                if (connection == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "InternetConnectW failed.");
                handles.SetConnection(connection);

                stage = "OpenRequest";
                uint flags = INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_RELOAD;
                if (requestUri.Scheme == Uri.UriSchemeHttps) flags |= INTERNET_FLAG_SECURE;
                IntPtr request = HttpOpenRequestW(connection, normalizedMethod, requestUri.PathAndQuery, null, null, IntPtr.Zero, flags, UIntPtr.Zero);
                if (request == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "HttpOpenRequestW failed.");
                handles.SetRequest(request);
                SetTimeout(request, INTERNET_OPTION_RECEIVE_TIMEOUT, operationTimeoutSeconds);

                stage = "SendRequest";
                operation.ThrowIfCancellationRequested();
                string headers = BuildHeaders(requestHeaders);
                if (!HttpSendRequestW(request, headers.Length == 0 ? null : headers, checked((uint)headers.Length), IntPtr.Zero, 0))
                {
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "HttpSendRequestW failed.");
                }

                stage = "ReadResponseHeaders";
                string statusText = QueryString(request, HTTP_QUERY_STATUS_CODE);
                int status;
                if (!int.TryParse(statusText, out status)) throw new InvalidOperationException("WinINet did not return an HTTP status code.");
                result.HttpStatusCode = status;
                result.FinalUri = QueryOptionString(request, INTERNET_OPTION_URL);
                result.ContentType = QueryString(request, HTTP_QUERY_CONTENT_TYPE);
                result.ResponseHeaders = QueryString(request, HTTP_QUERY_RAW_HEADERS_CRLF);
                long contentLength;
                if (long.TryParse(QueryString(request, HTTP_QUERY_CONTENT_LENGTH), out contentLength)) result.ContentLength = contentLength;
                result.ResponseAccepted = status >= 200 && status < 300;
                result.Success = true;
                result.Completed = true;
                operation.UpdateProgress(0, result.ContentLength, "ResponseReceived");
                return result;
            }
            catch (OperationCanceledException)
            {
                result.HResult = HResultFromWin32(ERROR_CANCELLED);
                result.NativeErrorCode = ERROR_CANCELLED;
                result.FailureStage = stage;
                result.ErrorMessage = "The WinINet redirect request was cancelled.";
                result.Cancelled = true;
                operation.UpdateProgress(0, result.ContentLength, "Cancelled");
                return result;
            }
            catch (Exception exception)
            {
                int nativeError = exception is System.ComponentModel.Win32Exception ? ((System.ComponentModel.Win32Exception)exception).NativeErrorCode : 0;
                result.HResult = exception.HResult;
                result.NativeErrorCode = nativeError;
                result.FailureStage = stage;
                result.ErrorMessage = exception.Message;
                result.Cancelled = nativeError == ERROR_CANCELLED || nativeError == ERROR_INTERNET_OPERATION_CANCELLED;
                result.TimedOut = exception is TimeoutException;
                return result;
            }
            finally
            {
                operation.ClearCancellationAction();
                handles.Close();
            }
        }

        private static DownloadResult DownloadCore(string uri, string destinationPath, string userAgent, IDictionary<string, string> requestHeaders, string proxy, bool responseOnly, int connectionTimeoutSeconds, int operationTimeoutSeconds, DownloadOperation operation)
        {
            DownloadResult result = new DownloadResult
            {
                Method = "WinINet",
                Uri = uri,
                DestinationPath = destinationPath,
                UserAgent = userAgent,
            };

            NativeHandleState handles = new NativeHandleState();
            string stage = "OpenSession";
            try
            {
                operation.UpdateProgress(0, null, "Connecting");
                operation.SetCancellationAction(handles.Close);
                operation.ThrowIfCancellationRequested();
                uint accessType = string.IsNullOrEmpty(proxy) ? INTERNET_OPEN_TYPE_PRECONFIG : INTERNET_OPEN_TYPE_PROXY;
                IntPtr session = InternetOpenW(userAgent, accessType, string.IsNullOrEmpty(proxy) ? null : proxy, null, 0);
                if (session == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "InternetOpenW failed.");
                handles.SetSession(session);
                operation.ThrowIfCancellationRequested();
                SetTimeout(session, INTERNET_OPTION_CONNECT_TIMEOUT, connectionTimeoutSeconds);
                SetTimeout(session, INTERNET_OPTION_SEND_TIMEOUT, operationTimeoutSeconds);
                SetTimeout(session, INTERNET_OPTION_RECEIVE_TIMEOUT, operationTimeoutSeconds);

                string headers = BuildHeaders(requestHeaders);
                stage = "OpenRequest";
                operation.ThrowIfCancellationRequested();
                IntPtr request = InternetOpenUrlW(session, uri, headers.Length == 0 ? null : headers, checked((uint)headers.Length), INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS, UIntPtr.Zero);
                if (request == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "InternetOpenUrlW failed.");
                handles.SetRequest(request);
                operation.ThrowIfCancellationRequested();
                SetTimeout(request, INTERNET_OPTION_RECEIVE_TIMEOUT, operationTimeoutSeconds);

                stage = "ReadResponseHeaders";
                string statusText = QueryString(request, HTTP_QUERY_STATUS_CODE);
                int status;
                if (!int.TryParse(statusText, out status)) throw new InvalidOperationException("WinINet did not return an HTTP status code.");
                result.HttpStatusCode = status;
                result.FinalUri = QueryOptionString(request, INTERNET_OPTION_URL);
                result.ContentType = QueryString(request, HTTP_QUERY_CONTENT_TYPE);
                result.ResponseHeaders = QueryString(request, HTTP_QUERY_RAW_HEADERS_CRLF);
                long contentLength;
                if (long.TryParse(QueryString(request, HTTP_QUERY_CONTENT_LENGTH), out contentLength)) result.ContentLength = contentLength;
                operation.UpdateProgress(0, result.ContentLength, "ResponseReceived");

                if (status != 200)
                {
                    result.HResult = HttpHResult(status);
                    result.ErrorMessage = "WinINet returned HTTP status " + status + ".";
                    return result;
                }
                result.ResponseAccepted = true;
                if (responseOnly) return result;

                stage = "Download";
                Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(destinationPath)));
                using (FileStream output = new FileStream(destinationPath, FileMode.Create, FileAccess.Write, FileShare.Read))
                {
                    byte[] buffer = new byte[1024 * 1024];
                    while (true)
                    {
                        operation.ThrowIfCancellationRequested();
                        uint bytesRead;
                        if (!InternetReadFile(request, buffer, checked((uint)buffer.Length), out bytesRead))
                        {
                            operation.ThrowIfCancellationRequested();
                            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "InternetReadFile failed.");
                        }
                        if (bytesRead == 0) break;
                        output.Write(buffer, 0, checked((int)bytesRead));
                        operation.UpdateProgress(output.Length, result.ContentLength, "Downloading");
                    }
                }

                stage = "HashDownload";
                Hashing.Populate(result, operation);
                if (result.ContentLength.HasValue && result.ContentLength.Value > 0 && result.BytesDownloaded != result.ContentLength.Value)
                {
                    result.HResult = unchecked((int)0x8A150044);
                    result.ErrorMessage = "The downloaded size does not match Content-Length.";
                    return result;
                }
                result.Success = true;
                result.Completed = true;
                return result;
            }
            catch (OperationCanceledException)
            {
                result.HResult = HResultFromWin32(ERROR_CANCELLED);
                result.NativeErrorCode = ERROR_CANCELLED;
                result.FailureStage = stage;
                result.ErrorMessage = "The WinINet download was cancelled.";
                result.Cancelled = true;
                operation.UpdateProgress(result.BytesDownloaded, result.ContentLength, "Cancelled");
                return result;
            }
            catch (Exception exception)
            {
                int nativeError = exception is System.ComponentModel.Win32Exception ? ((System.ComponentModel.Win32Exception)exception).NativeErrorCode : 0;
                if (nativeError == ERROR_CANCELLED || nativeError == ERROR_INTERNET_OPERATION_CANCELLED)
                {
                    result.Cancelled = true;
                    result.ErrorMessage = "The WinINet download was cancelled.";
                    operation.UpdateProgress(result.BytesDownloaded, result.ContentLength, "Cancelled");
                }
                result.HResult = exception.HResult;
                result.NativeErrorCode = nativeError;
                result.FailureStage = stage;
                if (!result.Cancelled) result.ErrorMessage = exception.Message;
                result.TimedOut = exception is TimeoutException;
                return result;
            }
            finally
            {
                operation.ClearCancellationAction();
                handles.Close();
            }
        }
    }

    public enum DODownloadProperty
    {
        Id = 0,
        Uri = 1,
        ContentId = 2,
        DisplayName = 3,
        LocalPath = 4,
        HttpCustomHeaders = 5,
        CostPolicy = 6,
        SecurityFlags = 7,
        CallbackFreqPercent = 8,
        CallbackFreqSeconds = 9,
        NoProgressTimeoutSeconds = 10,
        ForegroundPriority = 11,
        BlockingMode = 12,
        CallbackInterface = 13,
        StreamInterface = 14,
        SecurityContext = 15,
        NetworkToken = 16,
        CorrelationVector = 17,
        DecryptionInfo = 18,
        IntegrityCheckInfo = 19,
        IntegrityCheckMandatory = 20,
        TotalSizeBytes = 21,
        DisallowOnCellular = 22,
        HttpCustomAuthHeaders = 23,
        HttpAllowSecureToNonSecureRedirect = 24,
        NonVolatile = 25,
        HttpRedirectionTarget = 26,
        HttpResponseHeaders = 27,
        HttpServerIPAddress = 28,
        HttpStatusCode = 29,
    }

    public enum DODownloadState
    {
        Created = 0,
        Transferring = 1,
        Transferred = 2,
        Finalized = 3,
        Aborted = 4,
        Paused = 5,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DO_DOWNLOAD_STATUS
    {
        public ulong BytesTotal;
        public ulong BytesTransferred;
        public DODownloadState State;
        public int Error;
        public int ExtendedError;
    }

    [ComImport, Guid("FBBD7FC0-C147-4727-A38D-827EF071EE77"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IDODownload
    {
        [PreserveSig] int Start(IntPtr ranges);
        [PreserveSig] int Pause();
        [PreserveSig] int Abort();
        [PreserveSig] int FinalizeDownload();
        [PreserveSig] int GetStatus(out DO_DOWNLOAD_STATUS status);
        [PreserveSig] int GetProperty(DODownloadProperty property, IntPtr value);
        [PreserveSig] int SetProperty(DODownloadProperty property, IntPtr value);
    }

    [ComImport, Guid("400E2D4A-1431-4C1A-A748-39CA472CFDB1"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IDOManager
    {
        [PreserveSig] int CreateDownload([MarshalAs(UnmanagedType.Interface)] out IDODownload download);
        [PreserveSig] int EnumDownloads(IntPtr category, out IntPtr downloads);
    }

    [ComVisible(true), Guid("D166E8E3-A90E-4392-8E87-05E996D3747D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IDODownloadStatusCallback
    {
        [PreserveSig] int OnStatusChange([MarshalAs(UnmanagedType.Interface)] IDODownload download, ref DO_DOWNLOAD_STATUS status);
    }

    [ComVisible(true), ClassInterface(ClassInterfaceType.None)]
    public sealed class DOStatusCallback : IDODownloadStatusCallback, IDisposable
    {
        private readonly AutoResetEvent changed = new AutoResetEvent(false);
        private readonly object statusLock = new object();
        private DO_DOWNLOAD_STATUS status;

        public int OnStatusChange(IDODownload download, ref DO_DOWNLOAD_STATUS currentStatus)
        {
            lock (statusLock) status = currentStatus;
            changed.Set();
            return 0;
        }

        internal bool Wait(int milliseconds) { return changed.WaitOne(milliseconds); }
        internal DO_DOWNLOAD_STATUS Status { get { lock (statusLock) return status; } }
        public void Dispose() { changed.Dispose(); }
    }

    public static class DeliveryOptimizationDownloader
    {
        private static readonly Guid DeliveryOptimizationClass = new Guid("5B99FA76-721C-423C-ADAC-56D03C8A8007");
        private const int RPC_C_AUTHN_DEFAULT = -1;
        private const int RPC_C_AUTHZ_DEFAULT = -1;
        private const int RPC_C_AUTHN_LEVEL_DEFAULT = 0;
        private const int RPC_C_IMP_LEVEL_IMPERSONATE = 3;
        private const int EOAC_DEFAULT = 0;
        private const int DO_E_DOWNLOAD_NO_PROGRESS = unchecked((int)0x80D02002);
        private const int DO_E_BLOCKED_BY_COST_TRANSFER_POLICY = unchecked((int)0x80D03801);
        private const int DO_E_BLOCKED_BY_CELLULAR_POLICY = unchecked((int)0x80D03803);
        private const int DO_E_BLOCKED_BY_POWER_STATE = unchecked((int)0x80D03804);
        private const int DO_E_BLOCKED_BY_NO_NETWORK = unchecked((int)0x80D03805);

        [DllImport("ole32.dll")]
        private static extern int CoSetProxyBlanket(IntPtr proxy, int authnSvc, int authzSvc, IntPtr serverPrincipalName, int authnLevel, int impLevel, IntPtr authInfo, int capabilities);

        [DllImport("oleaut32.dll")]
        private static extern int VariantClear(IntPtr variant);

        private static bool Failed(int value) { return value < 0; }

        private static void ThrowForHR(int value)
        {
            if (Failed(value)) Marshal.ThrowExceptionForHR(value);
        }

        private static bool IsFatal(int error)
        {
            return error == DO_E_BLOCKED_BY_COST_TRANSFER_POLICY ||
                error == DO_E_BLOCKED_BY_CELLULAR_POLICY ||
                error == DO_E_BLOCKED_BY_POWER_STATE ||
                error == DO_E_BLOCKED_BY_NO_NETWORK;
        }

        private static void SetProperty(IDODownload download, DODownloadProperty property, object value)
        {
            IntPtr variant = Marshal.AllocCoTaskMem(IntPtr.Size == 8 ? 24 : 16);
            for (int index = 0; index < (IntPtr.Size == 8 ? 24 : 16); ++index) Marshal.WriteByte(variant, index, 0);
            try
            {
                Marshal.GetNativeVariantForObject(value, variant);
                ThrowForHR(download.SetProperty(property, variant));
            }
            finally
            {
                VariantClear(variant);
                Marshal.FreeCoTaskMem(variant);
            }
        }

        private static void SetUnknownProperty(IDODownload download, DODownloadProperty property, object value, Type interfaceType)
        {
            const short VT_UNKNOWN = 13;
            IntPtr variant = Marshal.AllocCoTaskMem(IntPtr.Size == 8 ? 24 : 16);
            for (int index = 0; index < (IntPtr.Size == 8 ? 24 : 16); ++index) Marshal.WriteByte(variant, index, 0);
            try
            {
                IntPtr unknown = Marshal.GetComInterfaceForObject(value, interfaceType);
                Marshal.WriteInt16(variant, 0, VT_UNKNOWN);
                Marshal.WriteIntPtr(variant, 8, unknown);
                ThrowForHR(download.SetProperty(property, variant));
            }
            finally
            {
                VariantClear(variant);
                Marshal.FreeCoTaskMem(variant);
            }
        }

        private static object GetProperty(IDODownload download, DODownloadProperty property)
        {
            IntPtr variant = Marshal.AllocCoTaskMem(IntPtr.Size == 8 ? 24 : 16);
            for (int index = 0; index < (IntPtr.Size == 8 ? 24 : 16); ++index) Marshal.WriteByte(variant, index, 0);
            try
            {
                int hr = download.GetProperty(property, variant);
                if (Failed(hr)) return null;
                return Marshal.GetObjectForNativeVariant(variant);
            }
            finally
            {
                VariantClear(variant);
                Marshal.FreeCoTaskMem(variant);
            }
        }

        private static int? ConvertStatusCode(object value)
        {
            if (value == null) return null;
            try { return Convert.ToInt32(value); }
            catch { return null; }
        }

        private static void PopulateResponseInfo(IDODownload download, DownloadResult result)
        {
            if (download == null) return;
            result.ResponseHeaders = GetProperty(download, DODownloadProperty.HttpResponseHeaders) as string;
            result.FinalUri = GetProperty(download, DODownloadProperty.HttpRedirectionTarget) as string;
            result.ServerIPAddress = GetProperty(download, DODownloadProperty.HttpServerIPAddress) as string;
            result.HttpStatusCode = ConvertStatusCode(GetProperty(download, DODownloadProperty.HttpStatusCode));
            if (!string.IsNullOrEmpty(result.ResponseHeaders))
            {
                foreach (string line in result.ResponseHeaders.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries))
                {
                    if (line.StartsWith("content-type:", StringComparison.OrdinalIgnoreCase)) result.ContentType = line.Substring(13).Trim();
                }
            }
        }

        public static DownloadOperation StartDownload(string uri, string destinationPath, string displayName, string contentId, IDictionary<string, string> requestHeaders, int noProgressTimeoutSeconds, int maximumDurationSeconds, bool responseOnly, int connectionTimeoutSeconds, int operationTimeoutSeconds)
        {
            return DownloadOperation.Start(operation => DownloadCore(uri, destinationPath, displayName, contentId, requestHeaders, noProgressTimeoutSeconds, maximumDurationSeconds, responseOnly, connectionTimeoutSeconds, operationTimeoutSeconds, operation));
        }

        public static DownloadResult Download(string uri, string destinationPath, string displayName, string contentId, IDictionary<string, string> requestHeaders, int noProgressTimeoutSeconds, int maximumDurationSeconds, bool responseOnly)
        {
            using (DownloadOperation operation = StartDownload(uri, destinationPath, displayName, contentId, requestHeaders, noProgressTimeoutSeconds, maximumDurationSeconds, responseOnly, 0, 0)) return operation.Result;
        }

        private static DownloadResult DownloadCore(string uri, string destinationPath, string displayName, string contentId, IDictionary<string, string> requestHeaders, int noProgressTimeoutSeconds, int maximumDurationSeconds, bool responseOnly, int connectionTimeoutSeconds, int operationTimeoutSeconds, DownloadOperation operation)
        {
            DownloadResult result = new DownloadResult
            {
                Method = "DeliveryOptimization",
                Uri = uri,
                DestinationPath = destinationPath,
                UserAgent = "Microsoft-Delivery-Optimization/10.0",
            };
            IDOManager manager = null;
            IDODownload download = null;
            DOStatusCallback callback = null;
            bool completed = false;
            string stage = "CreateManager";
            try
            {
                operation.UpdateProgress(0, null, "Connecting");
                operation.ThrowIfCancellationRequested();
                if (File.Exists(destinationPath)) File.Delete(destinationPath);
                Type managerType = Type.GetTypeFromCLSID(DeliveryOptimizationClass, true);
                manager = (IDOManager)Activator.CreateInstance(managerType);
                stage = "CreateDownload";
                ThrowForHR(manager.CreateDownload(out download));

                stage = "SetProxyBlanket";
                IntPtr unknown = Marshal.GetIUnknownForObject(download);
                IntPtr downloadProxy = IntPtr.Zero;
                try
                {
                    Guid downloadInterface = new Guid("FBBD7FC0-C147-4727-A38D-827EF071EE77");
                    ThrowForHR(Marshal.QueryInterface(unknown, in downloadInterface, out downloadProxy));
                    ThrowForHR(CoSetProxyBlanket(downloadProxy, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, IntPtr.Zero, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, IntPtr.Zero, EOAC_DEFAULT));
                }
                finally
                {
                    if (downloadProxy != IntPtr.Zero) Marshal.Release(downloadProxy);
                    Marshal.Release(unknown);
                }

                stage = "SetProperties";
                callback = new DOStatusCallback();
                stage = "SetUri";
                SetProperty(download, DODownloadProperty.Uri, uri);
                stage = "SetForegroundPriority";
                SetProperty(download, DODownloadProperty.ForegroundPriority, true);
                stage = "SetLocalPath";
                SetProperty(download, DODownloadProperty.LocalPath, Path.GetFullPath(destinationPath));
                stage = "SetCallbackInterface";
                SetUnknownProperty(download, DODownloadProperty.CallbackInterface, callback, typeof(IDODownloadStatusCallback));
                if (!string.IsNullOrWhiteSpace(displayName)) { stage = "SetDisplayName"; SetProperty(download, DODownloadProperty.DisplayName, displayName); }
                if (!string.IsNullOrWhiteSpace(contentId)) { stage = "SetContentId"; SetProperty(download, DODownloadProperty.ContentId, contentId); }
                if (requestHeaders != null && requestHeaders.Count > 0)
                {
                    stage = "SetCustomHeaders";
                    StringBuilder customHeaders = new StringBuilder();
                    foreach (KeyValuePair<string, string> header in requestHeaders) customHeaders.Append(header.Key).Append(": ").Append(header.Value).Append("\r\n");
                    SetProperty(download, DODownloadProperty.HttpCustomHeaders, customHeaders.ToString());
                }

                stage = "Start";
                IntPtr ranges = Marshal.AllocCoTaskMem(24);
                for (int index = 0; index < 24; ++index) Marshal.WriteByte(ranges, index, 0);
                try { ThrowForHR(download.Start(ranges)); }
                finally { Marshal.FreeCoTaskMem(ranges); }

                DateTime started = DateTime.UtcNow;
                DateTime lastProgress = started;
                ulong lastTransferred = 0;
                bool responseStarted = false;
                while (true)
                {
                    stage = "WaitForStatus";
                    operation.ThrowIfCancellationRequested();
                    callback.Wait(250);
                    operation.ThrowIfCancellationRequested();
                    DO_DOWNLOAD_STATUS status;
                    ThrowForHR(download.GetStatus(out status));
                    result.DeliveryOptimizationState = status.State.ToString();
                    result.DeliveryOptimizationExtendedError = status.ExtendedError;
                    if (Failed(status.Error)) Marshal.ThrowExceptionForHR(status.Error);
                    long transferred = status.BytesTransferred > long.MaxValue ? long.MaxValue : (long)status.BytesTransferred;
                    long? total = status.BytesTotal > 0 && status.BytesTotal <= long.MaxValue ? (long?)status.BytesTotal : null;
                    operation.UpdateProgress(transferred, total, status.State.ToString());
                    result.BytesDownloaded = transferred;
                    result.ContentLength = total;
                    if (status.BytesTransferred != lastTransferred)
                    {
                        lastTransferred = status.BytesTransferred;
                        lastProgress = DateTime.UtcNow;
                    }

                    if (status.State == DODownloadState.Transferring)
                    {
                        responseStarted = true;
                        if (responseOnly)
                        {
                            PopulateResponseInfo(download, result);
                            if ((result.HttpStatusCode >= 200 && result.HttpStatusCode < 300) || status.BytesTransferred > 0)
                            {
                                result.ResponseAccepted = true;
                                download.Abort();
                                completed = true;
                                return result;
                            }
                        }
                    }
                    else if (status.State == DODownloadState.Transferred || status.State == DODownloadState.Finalized)
                    {
                        responseStarted = true;
                        stage = "ReadResponseProperties";
                        PopulateResponseInfo(download, result);
                        result.ResponseAccepted = !result.HttpStatusCode.HasValue || (result.HttpStatusCode.Value >= 200 && result.HttpStatusCode.Value < 300);
                        if (status.State == DODownloadState.Transferred) ThrowForHR(download.FinalizeDownload());
                        completed = true;
                        stage = "HashDownload";
                        Hashing.Populate(result, operation);
                        result.ContentLength = total;
                        result.Success = true;
                        result.Completed = true;
                        return result;
                    }
                    else if (status.State == DODownloadState.Aborted)
                    {
                        throw new COMException("Delivery Optimization aborted the download.", status.Error);
                    }

                    if (connectionTimeoutSeconds > 0 && !responseStarted && DateTime.UtcNow >= started.AddSeconds(connectionTimeoutSeconds))
                    {
                        throw new TimeoutException("Delivery Optimization exceeded the connection timeout before receiving a response.");
                    }
                    if (operationTimeoutSeconds > 0 && responseStarted && DateTime.UtcNow >= lastProgress.AddSeconds(operationTimeoutSeconds))
                    {
                        throw new TimeoutException("Delivery Optimization exceeded the per-operation timeout without receiving more data.");
                    }
                    if (noProgressTimeoutSeconds > 0 && DateTime.UtcNow >= lastProgress.AddSeconds(noProgressTimeoutSeconds))
                    {
                        throw new COMException("Delivery Optimization made no progress before the WinGet timeout.", DO_E_DOWNLOAD_NO_PROGRESS);
                    }
                    if (maximumDurationSeconds > 0 && DateTime.UtcNow >= started.AddSeconds(maximumDurationSeconds)) throw new TimeoutException("Delivery Optimization exceeded the probe duration limit.");
                }
            }
            catch (OperationCanceledException exception)
            {
                result.HResult = exception.HResult;
                result.FailureStage = stage;
                result.ErrorMessage = "The Delivery Optimization download was cancelled.";
                result.Cancelled = true;
                operation.UpdateProgress(result.BytesDownloaded, result.ContentLength, "Cancelled");
                return result;
            }
            catch (Exception exception)
            {
                try { PopulateResponseInfo(download, result); }
                catch { }
                result.HResult = exception.HResult;
                result.FailureStage = stage;
                result.ErrorMessage = exception.Message;
                result.IsFatalDeliveryOptimizationError = IsFatal(exception.HResult);
                result.TimedOut = exception is TimeoutException || exception.HResult == DO_E_DOWNLOAD_NO_PROGRESS;
                return result;
            }
            finally
            {
                if (download != null)
                {
                    try
                    {
                        if (!completed) download.Abort();
                    }
                    catch { }
                }
                if (callback != null) callback.Dispose();
                if (download != null && Marshal.IsComObject(download)) Marshal.FinalReleaseComObject(download);
                if (manager != null && Marshal.IsComObject(manager)) Marshal.FinalReleaseComObject(manager);
            }
        }
    }
}
