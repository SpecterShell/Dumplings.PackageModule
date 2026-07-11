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
    }

    internal static class Hashing
    {
        internal static void Populate(DownloadResult result)
        {
            using (FileStream stream = new FileStream(result.DestinationPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(stream);
                result.BytesDownloaded = stream.Length;
                result.Sha256 = BitConverter.ToString(hash).Replace("-", string.Empty);
            }
        }
    }

    public static class WinInetDownloader
    {
        private const uint INTERNET_OPEN_TYPE_PRECONFIG = 0;
        private const uint INTERNET_OPEN_TYPE_PROXY = 3;
        private const uint INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS = 0x00004000;
        private const uint HTTP_QUERY_CONTENT_TYPE = 1;
        private const uint HTTP_QUERY_CONTENT_LENGTH = 5;
        private const uint HTTP_QUERY_STATUS_CODE = 19;
        private const uint HTTP_QUERY_RAW_HEADERS_CRLF = 22;
        private const uint HTTP_QUERY_FLAG_NUMBER = 0x20000000;
        private const uint INTERNET_OPTION_URL = 34;
        private const int ERROR_INSUFFICIENT_BUFFER = 122;

        [DllImport("wininet.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr InternetOpenW(string agent, uint accessType, string proxy, string proxyBypass, uint flags);

        [DllImport("wininet.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr InternetOpenUrlW(IntPtr internet, string url, string headers, uint headersLength, uint flags, UIntPtr context);

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
        private static extern bool InternetCloseHandle(IntPtr internet);

        private static int HResultFromWin32(int error)
        {
            return error <= 0 ? error : unchecked((int)(0x80070000u | ((uint)error & 0xFFFFu)));
        }

        private static int HttpHResult(int status)
        {
            return unchecked((int)(0x80190000u | ((uint)status & 0xFFFFu)));
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

        public static DownloadResult Download(string uri, string destinationPath, string userAgent, IDictionary<string, string> requestHeaders, string proxy, bool responseOnly)
        {
            DownloadResult result = new DownloadResult
            {
                Method = "WinINet",
                Uri = uri,
                DestinationPath = destinationPath,
                UserAgent = userAgent,
            };

            IntPtr session = IntPtr.Zero;
            IntPtr request = IntPtr.Zero;
            try
            {
                uint accessType = string.IsNullOrEmpty(proxy) ? INTERNET_OPEN_TYPE_PRECONFIG : INTERNET_OPEN_TYPE_PROXY;
                session = InternetOpenW(userAgent, accessType, string.IsNullOrEmpty(proxy) ? null : proxy, null, 0);
                if (session == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "InternetOpenW failed.");

                StringBuilder headerBuilder = new StringBuilder();
                if (requestHeaders != null)
                {
                    foreach (KeyValuePair<string, string> header in requestHeaders)
                    {
                        headerBuilder.Append(header.Key).Append(": ").Append(header.Value).Append("\r\n");
                    }
                }
                string headers = headerBuilder.ToString();
                request = InternetOpenUrlW(session, uri, headers.Length == 0 ? null : headers, checked((uint)headers.Length), INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS, UIntPtr.Zero);
                if (request == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "InternetOpenUrlW failed.");

                string statusText = QueryString(request, HTTP_QUERY_STATUS_CODE);
                int status;
                if (!int.TryParse(statusText, out status)) throw new InvalidOperationException("WinINet did not return an HTTP status code.");
                result.HttpStatusCode = status;
                result.FinalUri = QueryOptionString(request, INTERNET_OPTION_URL);
                result.ContentType = QueryString(request, HTTP_QUERY_CONTENT_TYPE);
                result.ResponseHeaders = QueryString(request, HTTP_QUERY_RAW_HEADERS_CRLF);
                long contentLength;
                if (long.TryParse(QueryString(request, HTTP_QUERY_CONTENT_LENGTH), out contentLength)) result.ContentLength = contentLength;

                if (status != 200)
                {
                    result.HResult = HttpHResult(status);
                    result.ErrorMessage = "WinINet returned HTTP status " + status + ".";
                    return result;
                }
                result.ResponseAccepted = true;
                if (responseOnly) return result;

                Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(destinationPath)));
                using (FileStream output = new FileStream(destinationPath, FileMode.Create, FileAccess.Write, FileShare.Read))
                {
                    byte[] buffer = new byte[1024 * 1024];
                    while (true)
                    {
                        uint bytesRead;
                        if (!InternetReadFile(request, buffer, checked((uint)buffer.Length), out bytesRead))
                        {
                            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "InternetReadFile failed.");
                        }
                        if (bytesRead == 0) break;
                        output.Write(buffer, 0, checked((int)bytesRead));
                    }
                }

                Hashing.Populate(result);
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
            catch (Exception exception)
            {
                result.HResult = exception.HResult;
                result.NativeErrorCode = exception is System.ComponentModel.Win32Exception ? ((System.ComponentModel.Win32Exception)exception).NativeErrorCode : 0;
                result.ErrorMessage = exception.Message;
                return result;
            }
            finally
            {
                if (request != IntPtr.Zero) InternetCloseHandle(request);
                if (session != IntPtr.Zero) InternetCloseHandle(session);
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

        public static DownloadResult Download(string uri, string destinationPath, string displayName, string contentId, IDictionary<string, string> requestHeaders, int noProgressTimeoutSeconds, int maximumDurationSeconds, bool responseOnly)
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
                DateTime progressDeadline = started.AddSeconds(noProgressTimeoutSeconds);
                ulong initialTransferred = ulong.MaxValue;
                bool madeProgress = false;
                while (true)
                {
                    stage = "WaitForStatus";
                    callback.Wait(1000);
                    DO_DOWNLOAD_STATUS status;
                    ThrowForHR(download.GetStatus(out status));
                    result.DeliveryOptimizationState = status.State.ToString();
                    result.DeliveryOptimizationExtendedError = status.ExtendedError;
                    if (Failed(status.Error)) Marshal.ThrowExceptionForHR(status.Error);

                    if (status.State == DODownloadState.Transferring)
                    {
                        if (responseOnly)
                        {
                            result.ResponseHeaders = GetProperty(download, DODownloadProperty.HttpResponseHeaders) as string;
                            result.FinalUri = GetProperty(download, DODownloadProperty.HttpRedirectionTarget) as string;
                            result.ServerIPAddress = GetProperty(download, DODownloadProperty.HttpServerIPAddress) as string;
                            result.HttpStatusCode = ConvertStatusCode(GetProperty(download, DODownloadProperty.HttpStatusCode));
                            if ((result.HttpStatusCode >= 200 && result.HttpStatusCode < 300) || status.BytesTransferred > 0)
                            {
                                result.ResponseAccepted = true;
                                download.Abort();
                                completed = true;
                                return result;
                            }
                        }
                        if (initialTransferred == ulong.MaxValue) initialTransferred = status.BytesTransferred;
                        else if (status.BytesTransferred != initialTransferred) madeProgress = true;
                    }
                    else if (status.State == DODownloadState.Transferred || status.State == DODownloadState.Finalized)
                    {
                        stage = "ReadResponseProperties";
                        result.ResponseHeaders = GetProperty(download, DODownloadProperty.HttpResponseHeaders) as string;
                        result.FinalUri = GetProperty(download, DODownloadProperty.HttpRedirectionTarget) as string;
                        result.ServerIPAddress = GetProperty(download, DODownloadProperty.HttpServerIPAddress) as string;
                        result.HttpStatusCode = ConvertStatusCode(GetProperty(download, DODownloadProperty.HttpStatusCode));
                        result.ResponseAccepted = !result.HttpStatusCode.HasValue || (result.HttpStatusCode.Value >= 200 && result.HttpStatusCode.Value < 300);
                        if (status.State == DODownloadState.Transferred) ThrowForHR(download.FinalizeDownload());
                        completed = true;
                        stage = "HashDownload";
                        Hashing.Populate(result);
                        result.ContentLength = status.BytesTotal > 0 ? (long?)checked((long)status.BytesTotal) : null;
                        if (!string.IsNullOrEmpty(result.ResponseHeaders))
                        {
                            foreach (string line in result.ResponseHeaders.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries))
                            {
                                if (line.StartsWith("content-type:", StringComparison.OrdinalIgnoreCase)) result.ContentType = line.Substring(13).Trim();
                            }
                        }
                        result.Success = true;
                        result.Completed = true;
                        return result;
                    }
                    else if (status.State == DODownloadState.Aborted)
                    {
                        throw new COMException("Delivery Optimization aborted the download.", status.Error);
                    }

                    if (!madeProgress && DateTime.UtcNow >= progressDeadline) throw new COMException("Delivery Optimization made no progress before the WinGet timeout.", DO_E_DOWNLOAD_NO_PROGRESS);
                    if (maximumDurationSeconds > 0 && DateTime.UtcNow >= started.AddSeconds(maximumDurationSeconds)) throw new TimeoutException("Delivery Optimization exceeded the probe duration limit.");
                }
            }
            catch (Exception exception)
            {
                result.HResult = exception.HResult;
                result.FailureStage = stage;
                result.ErrorMessage = exception.Message;
                result.IsFatalDeliveryOptimizationError = IsFatal(exception.HResult);
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
