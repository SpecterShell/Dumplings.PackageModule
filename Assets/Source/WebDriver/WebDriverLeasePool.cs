// SPDX-License-Identifier: MIT

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace Dumplings.WebDriver
{
    public enum WebDriverLeaseOutcome
    {
        None,
        Released,
        Stopped,
        Failed,
        TimedOut,
        Disposed
    }

    public sealed class WebDriverLeaseEvent
    {
        public WebDriverLeaseEvent(string ownerId, string eventType, string configuration, long generation, string message)
        {
            OwnerId = ownerId;
            EventType = eventType;
            Configuration = configuration;
            Generation = generation;
            Message = message;
            TimestampUtc = DateTime.UtcNow;
        }

        public string OwnerId { get; private set; }
        public string EventType { get; private set; }
        public string Configuration { get; private set; }
        public long Generation { get; private set; }
        public string Message { get; private set; }
        public DateTime TimestampUtc { get; private set; }
    }

    public sealed class WebDriverLeaseOutcomeRecord
    {
        public WebDriverLeaseOutcomeRecord(string ownerId, WebDriverLeaseOutcome outcome, string message)
        {
            OwnerId = ownerId;
            Outcome = outcome;
            Message = message;
            TimestampUtc = DateTime.UtcNow;
        }

        public string OwnerId { get; private set; }
        public WebDriverLeaseOutcome Outcome { get; private set; }
        public string Message { get; private set; }
        public DateTime TimestampUtc { get; private set; }
    }

    public sealed class WebDriverResource : IDisposable
    {
        private sealed class ProcessIdentity
        {
            public ProcessIdentity(int processId, string processName, DateTime startTimeUtc, int depth)
            {
                ProcessId = processId;
                ProcessName = processName;
                StartTimeUtc = startTimeUtc;
                Depth = depth;
            }

            public int ProcessId;
            public string ProcessName;
            public DateTime StartTimeUtc;
            public int Depth;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct ProcessEntry32
        {
            public uint Size;
            public uint Usage;
            public uint ProcessId;
            public IntPtr DefaultHeapId;
            public uint ModuleId;
            public uint ThreadCount;
            public uint ParentProcessId;
            public int BasePriority;
            public uint Flags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string ExecutableFile;
        }

        private const uint SnapshotProcesses = 0x00000002;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool Process32First(IntPtr snapshot, ref ProcessEntry32 entry);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool Process32Next(IntPtr snapshot, ref ProcessEntry32 entry);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);

        private readonly IDisposable _driver;
        private readonly IDisposable _service;
        private readonly int _serviceProcessId;
        private readonly string _serviceProcessName;
        private readonly DateTime? _serviceProcessStartTimeUtc;
        private readonly List<ProcessIdentity> _ownedProcesses;
        private readonly string[] _cleanupPaths;
        private int _disposed;

        public WebDriverResource(object driver, IDisposable service, int serviceProcessId, string configuration, string[] cleanupPaths)
        {
            if (driver == null) throw new ArgumentNullException("driver");
            if (string.IsNullOrWhiteSpace(configuration)) throw new ArgumentException("A configuration is required.", "configuration");

            Driver = driver;
            _driver = driver as IDisposable;
            _service = service;
            _serviceProcessId = serviceProcessId;
            Configuration = configuration;
            _cleanupPaths = cleanupPaths ?? new string[0];
            if (serviceProcessId > 0)
            {
                try
                {
                    using (Process process = Process.GetProcessById(serviceProcessId))
                    {
                        _serviceProcessName = process.ProcessName;
                        _serviceProcessStartTimeUtc = process.StartTime.ToUniversalTime();
                    }
                }
                catch
                {
                }
            }
            _ownedProcesses = CaptureDescendantProcesses(serviceProcessId);
        }

        public object Driver { get; private set; }
        public string Configuration { get; private set; }
        public int ServiceProcessId { get { return _serviceProcessId; } }
        public bool IsDisposed { get { return Volatile.Read(ref _disposed) != 0; } }

        public void Abort()
        {
            Cleanup(true);
        }

        public void Dispose()
        {
            Cleanup(false);
        }

        private void Cleanup(bool abort)
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;

            List<ProcessIdentity> ownedProcesses = new List<ProcessIdentity>(_ownedProcesses);
            if (abort) MergeProcessIdentities(ownedProcesses, CaptureDescendantProcesses(_serviceProcessId));

            if (_driver != null)
            {
                if (abort)
                {
                    // Let Selenium close detached browser processes first, but never let cleanup block queue progress.
                    try { Task.Run((Action)_driver.Dispose).Wait(2000); }
                    catch { }
                }
                else
                {
                    try { _driver.Dispose(); }
                    catch { }
                }
            }

            if (abort)
            {
                ownedProcesses.Sort((left, right) => right.Depth.CompareTo(left.Depth));
                foreach (ProcessIdentity identity in ownedProcesses) KillVerifiedProcess(identity);
                if (_serviceProcessStartTimeUtc.HasValue)
                {
                    KillVerifiedProcess(new ProcessIdentity(_serviceProcessId, _serviceProcessName, _serviceProcessStartTimeUtc.Value, 0));
                }
                WaitForProcessesToExit(ownedProcesses, TimeSpan.FromSeconds(5));
            }

            try
            {
                if (_service != null) _service.Dispose();
            }
            catch
            {
            }

            foreach (string cleanupPath in _cleanupPaths)
            {
                if (string.IsNullOrWhiteSpace(cleanupPath)) continue;
                for (int attempt = 0; attempt < 20; attempt++)
                {
                    try
                    {
                        if (Directory.Exists(cleanupPath))
                        {
                            foreach (string file in Directory.EnumerateFiles(cleanupPath, "*", SearchOption.AllDirectories))
                            {
                                try { File.SetAttributes(file, FileAttributes.Normal); }
                                catch { }
                            }
                            Directory.Delete(cleanupPath, true);
                        }
                        break;
                    }
                    catch
                    {
                        if (attempt < 19) Thread.Sleep(250);
                    }
                }
            }
        }

        private static List<ProcessIdentity> CaptureDescendantProcesses(int rootProcessId)
        {
            List<ProcessIdentity> result = new List<ProcessIdentity>();
            if (rootProcessId <= 0) return result;

            Dictionary<int, List<int>> children = new Dictionary<int, List<int>>();
            IntPtr snapshot = CreateToolhelp32Snapshot(SnapshotProcesses, 0);
            if (snapshot == new IntPtr(-1)) return result;
            try
            {
                ProcessEntry32 entry = new ProcessEntry32();
                entry.Size = (uint)Marshal.SizeOf(typeof(ProcessEntry32));
                if (Process32First(snapshot, ref entry))
                {
                    do
                    {
                        int parentId = unchecked((int)entry.ParentProcessId);
                        int processId = unchecked((int)entry.ProcessId);
                        List<int> childIds;
                        if (!children.TryGetValue(parentId, out childIds))
                        {
                            childIds = new List<int>();
                            children[parentId] = childIds;
                        }
                        childIds.Add(processId);
                    }
                    while (Process32Next(snapshot, ref entry));
                }
            }
            finally
            {
                CloseHandle(snapshot);
            }

            Queue<KeyValuePair<int, int>> pending = new Queue<KeyValuePair<int, int>>();
            pending.Enqueue(new KeyValuePair<int, int>(rootProcessId, 0));
            HashSet<int> visited = new HashSet<int>();
            visited.Add(rootProcessId);
            while (pending.Count > 0)
            {
                KeyValuePair<int, int> current = pending.Dequeue();
                List<int> childIds;
                if (!children.TryGetValue(current.Key, out childIds)) continue;
                foreach (int childId in childIds)
                {
                    if (!visited.Add(childId)) continue;
                    int depth = current.Value + 1;
                    ProcessIdentity identity = TryGetProcessIdentity(childId, depth);
                    if (identity != null) result.Add(identity);
                    pending.Enqueue(new KeyValuePair<int, int>(childId, depth));
                }
            }
            return result;
        }

        private static ProcessIdentity TryGetProcessIdentity(int processId, int depth)
        {
            try
            {
                using (Process process = Process.GetProcessById(processId))
                {
                    return new ProcessIdentity(processId, process.ProcessName, process.StartTime.ToUniversalTime(), depth);
                }
            }
            catch
            {
                return null;
            }
        }

        private static void MergeProcessIdentities(List<ProcessIdentity> target, List<ProcessIdentity> source)
        {
            Dictionary<int, ProcessIdentity> identities = new Dictionary<int, ProcessIdentity>();
            foreach (ProcessIdentity identity in target) identities[identity.ProcessId] = identity;
            foreach (ProcessIdentity identity in source)
            {
                ProcessIdentity existing;
                if (!identities.TryGetValue(identity.ProcessId, out existing) || existing.StartTimeUtc != identity.StartTimeUtc)
                {
                    target.Add(identity);
                    identities[identity.ProcessId] = identity;
                }
                else if (identity.Depth > existing.Depth)
                {
                    existing.Depth = identity.Depth;
                }
            }
        }

        private static void KillVerifiedProcess(ProcessIdentity identity)
        {
            try
            {
                using (Process process = Process.GetProcessById(identity.ProcessId))
                {
                    if (string.Equals(process.ProcessName, identity.ProcessName, StringComparison.OrdinalIgnoreCase) &&
                        process.StartTime.ToUniversalTime() == identity.StartTimeUtc)
                    {
                        process.Kill(true);
                    }
                }
            }
            catch
            {
            }
        }

        private static void WaitForProcessesToExit(List<ProcessIdentity> identities, TimeSpan timeout)
        {
            DateTime deadline = DateTime.UtcNow.Add(timeout);
            while (DateTime.UtcNow < deadline)
            {
                bool anyAlive = false;
                foreach (ProcessIdentity identity in identities)
                {
                    ProcessIdentity current = TryGetProcessIdentity(identity.ProcessId, identity.Depth);
                    if (current != null && string.Equals(current.ProcessName, identity.ProcessName, StringComparison.OrdinalIgnoreCase) &&
                        current.StartTimeUtc == identity.StartTimeUtc)
                    {
                        anyAlive = true;
                        break;
                    }
                }
                if (!anyAlive) return;
                Thread.Sleep(100);
            }
        }
    }

    public sealed class WebDriverLease
    {
        internal WebDriverLease(string ownerId, string configuration, long generation, object driver, DateTime expiresAtUtc)
        {
            OwnerId = ownerId;
            Configuration = configuration;
            Generation = generation;
            Driver = driver;
            ExpiresAtUtc = expiresAtUtc;
        }

        public string OwnerId { get; private set; }
        public string Configuration { get; private set; }
        public long Generation { get; private set; }
        public object Driver { get; private set; }
        public DateTime ExpiresAtUtc { get; internal set; }
    }

    public sealed class WebDriverLeasePool : IDisposable
    {
        private sealed class Waiter
        {
            public Waiter(string ownerId, string configuration)
            {
                OwnerId = ownerId;
                Configuration = configuration;
            }

            public string OwnerId;
            public string Configuration;
            public LinkedListNode<Waiter> Node;
        }

        private readonly object _sync = new object();
        private readonly LinkedList<Waiter> _waiters = new LinkedList<Waiter>();
        private readonly Dictionary<string, WebDriverLeaseOutcomeRecord> _outcomes =
            new Dictionary<string, WebDriverLeaseOutcomeRecord>(StringComparer.Ordinal);
        private readonly ConcurrentQueue<WebDriverLeaseEvent> _events = new ConcurrentQueue<WebDriverLeaseEvent>();
        private readonly Timer _timer;
        private WebDriverResource _resource;
        private WebDriverLease _activeLease;
        private TimeSpan _activeDuration;
        private bool _transitioning;
        private bool _disposed;
        private long _nextGeneration;

        public WebDriverLeasePool()
        {
            _timer = new Timer(OnLeaseTimer, null, Timeout.Infinite, Timeout.Infinite);
        }

        public int PendingCount
        {
            get { lock (_sync) return _waiters.Count; }
        }

        public string ActiveOwnerId
        {
            get { lock (_sync) return _activeLease == null ? null : _activeLease.OwnerId; }
        }

        public string ResourceConfiguration
        {
            get { lock (_sync) return _resource == null ? null : _resource.Configuration; }
        }

        public int ResourceServiceProcessId
        {
            get { lock (_sync) return _resource == null ? 0 : _resource.ServiceProcessId; }
        }

        public WebDriverLease Acquire(
            string ownerId,
            string configuration,
            Func<WebDriverResource> factory,
            TimeSpan leaseDuration,
            TimeSpan waitTimeout)
        {
            if (string.IsNullOrWhiteSpace(ownerId)) throw new ArgumentException("An owner ID is required.", "ownerId");
            if (string.IsNullOrWhiteSpace(configuration)) throw new ArgumentException("A configuration is required.", "configuration");
            if (factory == null) throw new ArgumentNullException("factory");
            if (leaseDuration <= TimeSpan.Zero) throw new ArgumentOutOfRangeException("leaseDuration");
            if (waitTimeout != Timeout.InfiniteTimeSpan && waitTimeout <= TimeSpan.Zero) throw new ArgumentOutOfRangeException("waitTimeout");

            Waiter waiter;
            long generation;
            DateTime waitStarted = DateTime.UtcNow;
            DateTime waitDeadline = waitTimeout == Timeout.InfiniteTimeSpan ? DateTime.MaxValue : waitStarted.Add(waitTimeout);

            lock (_sync)
            {
                ThrowIfDisposed();
                if (_activeLease != null && string.Equals(_activeLease.OwnerId, ownerId, StringComparison.Ordinal))
                {
                    if (!string.Equals(_activeLease.Configuration, configuration, StringComparison.Ordinal))
                    {
                        throw new InvalidOperationException("The active owner cannot change WebDriver configuration within one lease.");
                    }
                    return _activeLease;
                }

                WebDriverLeaseOutcomeRecord priorOutcome;
                if (_outcomes.TryGetValue(ownerId, out priorOutcome) && priorOutcome.Outcome == WebDriverLeaseOutcome.TimedOut)
                {
                    throw new TimeoutException(priorOutcome.Message);
                }
                if (priorOutcome != null && priorOutcome.Outcome == WebDriverLeaseOutcome.Released) _outcomes.Remove(ownerId);

                waiter = new Waiter(ownerId, configuration);
                waiter.Node = _waiters.AddLast(waiter);
                AddEvent(ownerId, "Queued", configuration, 0, "The WebDriver request entered the FIFO queue.");

                while (true)
                {
                    ThrowIfDisposed();
                    if (!_transitioning && _activeLease == null && ReferenceEquals(_waiters.First, waiter.Node))
                    {
                        _waiters.Remove(waiter.Node);
                        waiter.Node = null;
                        _transitioning = true;
                        generation = ++_nextGeneration;
                        break;
                    }

                    if (waitTimeout == Timeout.InfiniteTimeSpan)
                    {
                        Monitor.Wait(_sync);
                    }
                    else
                    {
                        TimeSpan remaining = waitDeadline - DateTime.UtcNow;
                        if (remaining <= TimeSpan.Zero || !Monitor.Wait(_sync, remaining))
                        {
                            if (waiter.Node != null && waiter.Node.List != null) _waiters.Remove(waiter.Node);
                            RecordOutcome(ownerId, WebDriverLeaseOutcome.TimedOut, "Timed out while waiting for the shared WebDriver lease.");
                            AddEvent(ownerId, "QueueTimeout", configuration, 0, "The WebDriver queue wait timed out.");
                            throw new TimeoutException("Timed out while waiting for the shared WebDriver lease.");
                        }
                    }
                }
            }

            WebDriverResource selectedResource = null;
            WebDriverResource replacedResource = null;
            try
            {
                lock (_sync)
                {
                    if (_resource != null && !_resource.IsDisposed && string.Equals(_resource.Configuration, configuration, StringComparison.Ordinal))
                    {
                        selectedResource = _resource;
                    }
                    else
                    {
                        replacedResource = _resource;
                        _resource = null;
                    }
                }

                if (replacedResource != null)
                {
                    replacedResource.Abort();
                    AddEvent(ownerId, "Recycled", configuration, generation, "The previous WebDriver configuration was recycled.");
                }
                if (selectedResource == null) selectedResource = factory();
                if (selectedResource == null) throw new InvalidOperationException("The WebDriver resource factory returned null.");
                if (!string.Equals(selectedResource.Configuration, configuration, StringComparison.Ordinal))
                {
                    selectedResource.Abort();
                    throw new InvalidOperationException("The WebDriver resource factory returned a different configuration.");
                }

                lock (_sync)
                {
                    if (_disposed)
                    {
                        selectedResource.Abort();
                        throw new ObjectDisposedException("WebDriverLeasePool");
                    }

                    _resource = selectedResource;
                    _activeDuration = leaseDuration;
                    _activeLease = new WebDriverLease(ownerId, configuration, generation, selectedResource.Driver, DateTime.UtcNow.Add(leaseDuration));
                    _transitioning = false;
                    _timer.Change(ToTimerMilliseconds(leaseDuration), Timeout.Infinite);
                    AddEvent(ownerId, "Acquired", configuration, generation,
                        "The WebDriver lease was acquired after waiting " + (DateTime.UtcNow - waitStarted).TotalMilliseconds.ToString("F0") + " ms.");
                    Monitor.PulseAll(_sync);
                    return _activeLease;
                }
            }
            catch (Exception exception)
            {
                if (selectedResource != null && !ReferenceEquals(selectedResource, _resource)) selectedResource.Abort();
                lock (_sync)
                {
                    _transitioning = false;
                    RecordOutcome(ownerId, WebDriverLeaseOutcome.Failed, "WebDriver creation failed: " + exception.Message);
                    AddEvent(ownerId, "Failed", configuration, generation, exception.Message);
                    Monitor.PulseAll(_sync);
                }
                throw;
            }
        }

        public bool Release(string ownerId, long generation, WebDriverLeaseOutcome outcome, bool recycle, string message)
        {
            WebDriverResource resourceToRecycle = null;
            string configuration;
            lock (_sync)
            {
                if (_activeLease == null || _activeLease.Generation != generation ||
                    !string.Equals(_activeLease.OwnerId, ownerId, StringComparison.Ordinal)) return false;

                configuration = _activeLease.Configuration;
                _timer.Change(Timeout.Infinite, Timeout.Infinite);
                _activeLease = null;
                if (recycle)
                {
                    _transitioning = true;
                    resourceToRecycle = _resource;
                    _resource = null;
                }
                RecordOutcome(ownerId, outcome, message);
                AddEvent(ownerId, outcome.ToString(), configuration, generation, message);
                if (!recycle) Monitor.PulseAll(_sync);
            }

            if (resourceToRecycle != null) resourceToRecycle.Abort();
            if (recycle)
            {
                lock (_sync)
                {
                    _transitioning = false;
                    Monitor.PulseAll(_sync);
                }
            }
            return true;
        }

        public WebDriverLease GetActiveLease(string ownerId)
        {
            lock (_sync)
            {
                return _activeLease != null && string.Equals(_activeLease.OwnerId, ownerId, StringComparison.Ordinal) ? _activeLease : null;
            }
        }

        public WebDriverLeaseOutcomeRecord TakeOutcome(string ownerId)
        {
            lock (_sync)
            {
                WebDriverLeaseOutcomeRecord outcome;
                if (!_outcomes.TryGetValue(ownerId, out outcome)) return null;
                _outcomes.Remove(ownerId);
                return outcome;
            }
        }

        public WebDriverLeaseOutcomeRecord GetOutcome(string ownerId)
        {
            lock (_sync)
            {
                WebDriverLeaseOutcomeRecord outcome;
                return _outcomes.TryGetValue(ownerId, out outcome) ? outcome : null;
            }
        }

        public WebDriverLeaseEvent[] DrainEvents()
        {
            List<WebDriverLeaseEvent> result = new List<WebDriverLeaseEvent>();
            WebDriverLeaseEvent leaseEvent;
            while (_events.TryDequeue(out leaseEvent)) result.Add(leaseEvent);
            return result.ToArray();
        }

        public void Dispose()
        {
            WebDriverResource resourceToRecycle;
            lock (_sync)
            {
                if (_disposed) return;
                _disposed = true;
                _timer.Change(Timeout.Infinite, Timeout.Infinite);
                _timer.Dispose();
                resourceToRecycle = _resource;
                _resource = null;
                if (_activeLease != null)
                {
                    RecordOutcome(_activeLease.OwnerId, WebDriverLeaseOutcome.Disposed, "The shared WebDriver pool was disposed.");
                    AddEvent(_activeLease.OwnerId, "Disposed", _activeLease.Configuration, _activeLease.Generation, "The shared WebDriver pool was disposed.");
                }
                foreach (Waiter waiter in _waiters)
                {
                    RecordOutcome(waiter.OwnerId, WebDriverLeaseOutcome.Disposed, "The shared WebDriver pool was disposed while the task was waiting.");
                    AddEvent(waiter.OwnerId, "Disposed", waiter.Configuration, 0, "The shared WebDriver pool was disposed while the task was waiting.");
                }
                _waiters.Clear();
                _activeLease = null;
                _transitioning = false;
                Monitor.PulseAll(_sync);
            }
            if (resourceToRecycle != null) resourceToRecycle.Abort();
        }

        private void OnLeaseTimer(object state)
        {
            WebDriverResource resourceToRecycle = null;
            WebDriverLease expiredLease = null;
            lock (_sync)
            {
                if (_disposed || _activeLease == null) return;
                if (_waiters.Count == 0)
                {
                    _activeLease.ExpiresAtUtc = DateTime.UtcNow.Add(_activeDuration);
                    _timer.Change(ToTimerMilliseconds(_activeDuration), Timeout.Infinite);
                    AddEvent(_activeLease.OwnerId, "Renewed", _activeLease.Configuration, _activeLease.Generation,
                        "The WebDriver quantum was renewed because no task was waiting.");
                    return;
                }

                expiredLease = _activeLease;
                _activeLease = null;
                _transitioning = true;
                resourceToRecycle = _resource;
                _resource = null;
                RecordOutcome(expiredLease.OwnerId, WebDriverLeaseOutcome.TimedOut,
                    "The " + _activeDuration.TotalSeconds.ToString("F0") + "-second WebDriver lease expired while another task was waiting.");
                AddEvent(expiredLease.OwnerId, "TimedOut", expiredLease.Configuration, expiredLease.Generation,
                    "The WebDriver lease expired while another task was waiting.");
            }

            if (resourceToRecycle != null) resourceToRecycle.Abort();
            lock (_sync)
            {
                _transitioning = false;
                Monitor.PulseAll(_sync);
            }
        }

        private void RecordOutcome(string ownerId, WebDriverLeaseOutcome outcome, string message)
        {
            WebDriverLeaseOutcomeRecord existing;
            if (_outcomes.TryGetValue(ownerId, out existing) && OutcomeSeverity(existing.Outcome) > OutcomeSeverity(outcome)) return;
            _outcomes[ownerId] = new WebDriverLeaseOutcomeRecord(ownerId, outcome, message);
        }

        private void AddEvent(string ownerId, string eventType, string configuration, long generation, string message)
        {
            _events.Enqueue(new WebDriverLeaseEvent(ownerId, eventType, configuration, generation, message));
        }

        private void ThrowIfDisposed()
        {
            if (_disposed) throw new ObjectDisposedException("WebDriverLeasePool");
        }

        private static int OutcomeSeverity(WebDriverLeaseOutcome outcome)
        {
            switch (outcome)
            {
                case WebDriverLeaseOutcome.Released: return 1;
                case WebDriverLeaseOutcome.Stopped: return 2;
                case WebDriverLeaseOutcome.Failed: return 3;
                case WebDriverLeaseOutcome.TimedOut: return 4;
                case WebDriverLeaseOutcome.Disposed: return 5;
                default: return 0;
            }
        }

        private static int ToTimerMilliseconds(TimeSpan duration)
        {
            double milliseconds = Math.Ceiling(duration.TotalMilliseconds);
            return milliseconds >= int.MaxValue ? int.MaxValue : Math.Max(1, (int)milliseconds);
        }
    }
}
