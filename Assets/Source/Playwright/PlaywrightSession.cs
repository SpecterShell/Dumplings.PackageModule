// SPDX-License-Identifier: Apache-2.0

// Runtime/API references:
// https://github.com/Kaliiiiiiiiii-Vinyzu/patchright
// https://github.com/DevEnterpriseSoftware/patchright-dotnet
// https://github.com/D4Vinci/Scrapling

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Dumplings.Playwright
{
    /// <summary>Detached evidence for one captured XHR or fetch response.</summary>
    public sealed class PlaywrightCapturedResponse
    {
        public string Url { get; set; } = string.Empty;
        public int StatusCode { get; set; }
        public string StatusDescription { get; set; } = string.Empty;
        public Dictionary<string, string> Headers { get; set; } = new Dictionary<string, string>();
        public string Content { get; set; } = string.Empty;
    }

    /// <summary>
    /// Compiled response listener used instead of a PowerShell event callback.
    /// It stores matching response handles synchronously, then materializes their
    /// bodies before the page lease is released.
    /// </summary>
    public sealed class PlaywrightResponseCapture : IDisposable
    {
        private readonly object _sync = new object();
        private readonly IPage _page;
        private readonly Regex _urlPattern;
        private readonly List<IResponse> _responses = new List<IResponse>();
        private readonly EventHandler<IResponse> _handler;
        private bool _disposed;

        internal PlaywrightResponseCapture(IPage page, string urlPattern)
        {
            _page = page ?? throw new ArgumentNullException("page");
            _urlPattern = new Regex(urlPattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
            _handler = OnResponse;
            _page.Response += _handler;
        }

        public async Task<PlaywrightCapturedResponse[]> CompleteAsync()
        {
            IResponse[] responses;
            lock (_sync)
            {
                if (!_disposed)
                {
                    _page.Response -= _handler;
                    _disposed = true;
                }
                responses = _responses.ToArray();
            }

            List<PlaywrightCapturedResponse> results = new List<PlaywrightCapturedResponse>();
            foreach (IResponse response in responses)
            {
                PlaywrightCapturedResponse result = new PlaywrightCapturedResponse
                {
                    Url = response.Url ?? string.Empty,
                    StatusCode = response.Status,
                    StatusDescription = response.StatusText ?? string.Empty
                };
                try { result.Headers = await response.AllHeadersAsync().ConfigureAwait(false); } catch { }
                try { result.Content = await response.TextAsync().ConfigureAwait(false); } catch { }
                results.Add(result);
            }
            return results.ToArray();
        }

        public void Dispose()
        {
            lock (_sync)
            {
                if (_disposed) return;
                _page.Response -= _handler;
                _disposed = true;
            }
        }

        private void OnResponse(object sender, IResponse response)
        {
            string resourceType = response.Request.ResourceType ?? string.Empty;
            if (!resourceType.Equals("xhr", StringComparison.OrdinalIgnoreCase) &&
                !resourceType.Equals("fetch", StringComparison.OrdinalIgnoreCase)) return;
            if (!_urlPattern.IsMatch(response.Url ?? string.Empty)) return;
            lock (_sync)
            {
                if (!_disposed) _responses.Add(response);
            }
        }
    }

    /// <summary>
    /// Immutable input used to create one pooled browser session. PowerShell
    /// builds this object before entering Playwright so no asynchronous browser
    /// callback ever has to call back into a PowerShell runspace.
    /// </summary>
    public sealed class PlaywrightSessionConfiguration
    {
        public string BrowserName { get; set; } = "Chromium";
        public string Channel { get; set; } = string.Empty;
        public bool Headless { get; set; }
        public int OperationTimeoutMilliseconds { get; set; } = 30000;
        public bool Stealth { get; set; }
        public bool IgnoreHttpsErrors { get; set; }
        public bool BlockWebRtc { get; set; }
        public bool DisableWebGl { get; set; }
        public bool DnsOverHttps { get; set; }
        public string UserAgent { get; set; } = string.Empty;
        public string Locale { get; set; } = string.Empty;
        public string TimezoneId { get; set; } = string.Empty;
        public string ProxyServer { get; set; } = string.Empty;
        public string ProxyUsername { get; set; } = string.Empty;
        public string ProxyPassword { get; set; } = string.Empty;
        public string ProxyBypass { get; set; } = string.Empty;
        public string InitScriptPath { get; set; } = string.Empty;
        public string[] ExtraBrowserArguments { get; set; } = Array.Empty<string>();
        public string[] BlockedUrlPatterns { get; set; } = Array.Empty<string>();
        public string[] BlockedResourceTypes { get; set; } = Array.Empty<string>();
        public string[] BlockedDomains { get; set; } = Array.Empty<string>();
        public Dictionary<string, string> ExtraHttpHeaders { get; set; } =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Owns one Playwright driver, browser, isolated context, and page. All
    /// Playwright callbacks are compiled C# delegates so the driver never calls
    /// PowerShell asynchronously from a thread without the originating runspace.
    /// </summary>
    public sealed class PlaywrightSession : IDisposable
    {
        private static readonly string[] PatchrightIgnoredChromiumArguments =
        {
            "--enable-automation",
            "--disable-popup-blocking",
            "--disable-component-update",
            "--disable-default-apps",
            "--disable-extensions"
        };

        private readonly object _sync = new object();
        private readonly PlaywrightSessionConfiguration _configuration;
        private readonly Regex[] _blockedUrlPatterns;
        private readonly HashSet<string> _blockedResourceTypes;
        private readonly HashSet<string> _blockedDomains;
        private IPlaywright _playwright;
        private IBrowser _browser;
        private IBrowserContext _context;
        private IPage _page;
        private string _effectiveUserAgent = string.Empty;
        private int _disposed;

        private PlaywrightSession(
            IPlaywright playwright,
            IBrowser browser,
            PlaywrightSessionConfiguration configuration)
        {
            _playwright = playwright;
            _browser = browser;
            _configuration = configuration;
            _blockedUrlPatterns = (configuration.BlockedUrlPatterns ?? Array.Empty<string>())
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Select(CompileWildcard)
                .ToArray();
            _blockedResourceTypes = new HashSet<string>(
                configuration.BlockedResourceTypes ?? Array.Empty<string>(),
                StringComparer.OrdinalIgnoreCase);
            _blockedDomains = new HashSet<string>(
                (configuration.BlockedDomains ?? Array.Empty<string>())
                    .Select(NormalizeDomain)
                    .Where(value => value.Length > 0),
                StringComparer.OrdinalIgnoreCase);
            CreateContextAndPage();
        }

        public IPlaywright Playwright { get { return _playwright; } }
        public IBrowser Browser { get { return _browser; } }
        public IBrowserContext Context { get { return _context; } }
        public IPage Page { get { return _page; } }
        public string EffectiveUserAgent { get { return _effectiveUserAgent; } }
        public bool IsDisposed { get { lock (_sync) return _disposed != 0; } }

        public static PlaywrightSession Create(PlaywrightSessionConfiguration configuration)
        {
            if (configuration == null) throw new ArgumentNullException("configuration");
            if (configuration.OperationTimeoutMilliseconds <= 0)
                throw new ArgumentOutOfRangeException("configuration.OperationTimeoutMilliseconds");

            IPlaywright playwright = null;
            IBrowser browser = null;
            try
            {
                playwright = Microsoft.Playwright.Playwright.CreateAsync().ConfigureAwait(false).GetAwaiter().GetResult();
                IBrowserType browserType;
                switch ((configuration.BrowserName ?? string.Empty).ToLowerInvariant())
                {
                    case "chromium": browserType = playwright.Chromium; break;
                    case "firefox": browserType = playwright.Firefox; break;
                    case "webkit": browserType = playwright.Webkit; break;
                    default: throw new ArgumentException("Unsupported Playwright browser: " + configuration.BrowserName);
                }

                if (configuration.Stealth && browserType != playwright.Chromium)
                    throw new ArgumentException("The stealth profile requires the Chromium browser engine.");
                if ((configuration.BlockWebRtc || configuration.DisableWebGl || configuration.DnsOverHttps) &&
                    browserType != playwright.Chromium)
                    throw new ArgumentException("WebRTC, WebGL, and DNS-over-HTTPS launch controls require Chromium.");

                BrowserTypeLaunchOptions options = new BrowserTypeLaunchOptions
                {
                    Headless = configuration.Headless,
                    Timeout = configuration.OperationTimeoutMilliseconds
                };
                if (browserType == playwright.Chromium && !string.IsNullOrWhiteSpace(configuration.Channel))
                    options.Channel = configuration.Channel;

                if (browserType == playwright.Chromium)
                {
                    List<string> arguments = new List<string>();
                    if (configuration.Stealth)
                        arguments.Add("--disable-blink-features=AutomationControlled");
                    if (configuration.BlockWebRtc)
                    {
                        arguments.Add("--webrtc-ip-handling-policy=disable_non_proxied_udp");
                        arguments.Add("--force-webrtc-ip-handling-policy");
                    }
                    if (configuration.DisableWebGl)
                    {
                        arguments.Add("--disable-webgl");
                        arguments.Add("--disable-webgl2");
                    }
                    if (configuration.DnsOverHttps)
                        arguments.Add("--dns-over-https-templates=https://cloudflare-dns.com/dns-query");
                    arguments.AddRange(configuration.ExtraBrowserArguments ?? Array.Empty<string>());
                    options.Args = arguments.Where(value => !string.IsNullOrWhiteSpace(value))
                        .Distinct(StringComparer.Ordinal).ToArray();

                    // These are the command-line leak controls documented by
                    // Patchright and used by Scrapling's Patchright profile.
                    if (configuration.Stealth)
                        options.IgnoreDefaultArgs = PatchrightIgnoredChromiumArguments;

                }

                browser = browserType.LaunchAsync(options).ConfigureAwait(false).GetAwaiter().GetResult();
                return new PlaywrightSession(playwright, browser, configuration);
            }
            catch
            {
                if (browser != null)
                {
                    try { browser.CloseAsync().ConfigureAwait(false).GetAwaiter().GetResult(); } catch { }
                }
                if (playwright != null) playwright.Dispose();
                throw;
            }
        }

        public PlaywrightResponseCapture BeginResponseCapture(string urlPattern)
        {
            if (string.IsNullOrWhiteSpace(urlPattern)) throw new ArgumentException("A response URL pattern is required.", "urlPattern");
            return new PlaywrightResponseCapture(_page, urlPattern);
        }

        public bool Reset()
        {
            lock (_sync)
            {
                if (_disposed != 0 || _browser == null || !_browser.IsConnected) return false;
                try
                {
                    CloseContext();
                    CreateContextAndPage();
                    return true;
                }
                catch
                {
                    return false;
                }
            }
        }

        public void Dispose()
        {
            lock (_sync)
            {
                if (_disposed != 0) return;
                _disposed = 1;
                CloseContext();
                if (_browser != null)
                {
                    try { _browser.CloseAsync().ConfigureAwait(false).GetAwaiter().GetResult(); } catch { }
                    _browser = null;
                }
                if (_playwright != null)
                {
                    try { _playwright.Dispose(); } catch { }
                    _playwright = null;
                }
            }
        }

        private void CreateContextAndPage()
        {
            _effectiveUserAgent = ResolveUserAgent();
            BrowserNewContextOptions options = new BrowserNewContextOptions
            {
                AcceptDownloads = true,
                ViewportSize = new ViewportSize { Width = 1920, Height = 1080 }
            };

            if (_configuration.Stealth)
            {
                options.ColorScheme = ColorScheme.Dark;
                options.DeviceScaleFactor = 2;
                options.HasTouch = false;
                options.IsMobile = false;
                options.IgnoreHTTPSErrors = true;
                options.Permissions = new[] { "geolocation", "notifications" };
                options.ScreenSize = new ScreenSize { Width = 1920, Height = 1080 };
                options.ServiceWorkers = ServiceWorkerPolicy.Allow;
            }
            if (_configuration.IgnoreHttpsErrors) options.IgnoreHTTPSErrors = true;
            if (!string.IsNullOrWhiteSpace(_effectiveUserAgent)) options.UserAgent = _effectiveUserAgent;
            if (!string.IsNullOrWhiteSpace(_configuration.Locale)) options.Locale = _configuration.Locale;
            if (!string.IsNullOrWhiteSpace(_configuration.TimezoneId)) options.TimezoneId = _configuration.TimezoneId;
            if (_configuration.ExtraHttpHeaders != null && _configuration.ExtraHttpHeaders.Count > 0)
                options.ExtraHTTPHeaders = _configuration.ExtraHttpHeaders;
            if (!string.IsNullOrWhiteSpace(_configuration.ProxyServer))
            {
                options.Proxy = new Proxy
                {
                    Server = _configuration.ProxyServer,
                    Username = EmptyToNull(_configuration.ProxyUsername),
                    Password = EmptyToNull(_configuration.ProxyPassword),
                    Bypass = EmptyToNull(_configuration.ProxyBypass)
                };
            }

            _context = _browser.NewContextAsync(options).ConfigureAwait(false).GetAwaiter().GetResult();
            _context.SetDefaultTimeout(_configuration.OperationTimeoutMilliseconds);
            _context.SetDefaultNavigationTimeout(_configuration.OperationTimeoutMilliseconds);
            if (!string.IsNullOrWhiteSpace(_configuration.InitScriptPath))
            {
                _context.AddInitScriptAsync(scriptPath: _configuration.InitScriptPath)
                    .ConfigureAwait(false).GetAwaiter().GetResult();
            }
            if (_blockedUrlPatterns.Length > 0 || _blockedResourceTypes.Count > 0 || _blockedDomains.Count > 0)
            {
                // This Func<IRoute,Task> is a compiled C# delegate. Do not replace it
                // with a PowerShell scriptblock: Playwright invokes it asynchronously.
                _context.RouteAsync("**/*", HandleRouteAsync).ConfigureAwait(false).GetAwaiter().GetResult();
            }
            _page = _context.NewPageAsync().ConfigureAwait(false).GetAwaiter().GetResult();
        }

        private string ResolveUserAgent()
        {
            if (!string.IsNullOrWhiteSpace(_configuration.UserAgent)) return _configuration.UserAgent;
            if (!_configuration.Stealth || !_configuration.Headless) return string.Empty;

            // Scrapling removes only Chromium's headless product token. Query the
            // selected browser first so version and platform remain source-backed.
            IBrowserContext probeContext = null;
            try
            {
                probeContext = _browser.NewContextAsync().ConfigureAwait(false).GetAwaiter().GetResult();
                IPage probePage = probeContext.NewPageAsync().ConfigureAwait(false).GetAwaiter().GetResult();
                string userAgent = probePage.EvaluateAsync<string>("() => navigator.userAgent", null)
                    .ConfigureAwait(false).GetAwaiter().GetResult();
                return (userAgent ?? string.Empty).Replace("HeadlessChrome/", "Chrome/");
            }
            finally
            {
                if (probeContext != null)
                {
                    try { probeContext.CloseAsync().ConfigureAwait(false).GetAwaiter().GetResult(); } catch { }
                }
            }
        }

        private async Task HandleRouteAsync(IRoute route)
        {
            IRequest request = route.Request;
            string url = request.Url ?? string.Empty;
            bool blocked = _blockedUrlPatterns.Any(pattern => pattern.IsMatch(url)) ||
                _blockedResourceTypes.Contains(request.ResourceType ?? string.Empty) ||
                IsBlockedDomain(url);
            if (blocked)
                await route.AbortAsync("blockedbyclient").ConfigureAwait(false);
            else
                await route.ContinueAsync().ConfigureAwait(false);
        }

        private bool IsBlockedDomain(string url)
        {
            if (_blockedDomains.Count == 0) return false;
            Uri uri;
            if (!Uri.TryCreate(url, UriKind.Absolute, out uri)) return false;
            string host = NormalizeDomain(uri.IdnHost);
            while (host.Length > 0)
            {
                if (_blockedDomains.Contains(host)) return true;
                int separator = host.IndexOf('.');
                if (separator < 0) break;
                host = host.Substring(separator + 1);
            }
            return false;
        }

        private void CloseContext()
        {
            if (_context != null)
            {
                try { _context.CloseAsync().ConfigureAwait(false).GetAwaiter().GetResult(); } catch { }
            }
            _page = null;
            _context = null;
        }

        private static string NormalizeDomain(string domain)
        {
            return (domain ?? string.Empty).Trim().Trim('.').ToLowerInvariant();
        }

        private static string EmptyToNull(string value)
        {
            return string.IsNullOrWhiteSpace(value) ? null : value;
        }

        private static Regex CompileWildcard(string wildcard)
        {
            StringBuilder expression = new StringBuilder("^");
            foreach (char value in wildcard)
            {
                switch (value)
                {
                    case '*': expression.Append(".*"); break;
                    case '?': expression.Append('.'); break;
                    default: expression.Append(Regex.Escape(value.ToString())); break;
                }
            }
            expression.Append('$');
            return new Regex(expression.ToString(), RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
        }
    }
}
