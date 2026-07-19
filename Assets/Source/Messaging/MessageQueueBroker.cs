// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace Dumplings.Messaging
{
    public enum MessageQueueRequestState
    {
        Pending,
        Active,
        Succeeded,
        Failed,
        Superseded,
        Cancelled
    }

    public sealed class MessageQueueTicket : IDisposable
    {
        private readonly ManualResetEventSlim _completion = new ManualResetEventSlim(false);
        private int _state = (int)MessageQueueRequestState.Pending;
        private int _disposed;

        internal MessageQueueTicket(string transport, string targetId, string queueKey, string sessionKey)
        {
            RequestId = Guid.NewGuid();
            Transport = transport;
            TargetId = targetId;
            QueueKey = queueKey;
            SessionKey = sessionKey;
            CreatedAtUtc = DateTime.UtcNow;
        }

        public Guid RequestId { get; private set; }
        public string Transport { get; private set; }
        public string TargetId { get; private set; }
        public string QueueKey { get; private set; }
        public string SessionKey { get; private set; }
        public DateTime CreatedAtUtc { get; private set; }
        public DateTime? StartedAtUtc { get; private set; }
        public DateTime? CompletedAtUtc { get; private set; }
        public string ErrorMessage { get; private set; }
        public Guid? SupersededByRequestId { get; private set; }
        public MessageQueueRequestState State { get { return (MessageQueueRequestState)Volatile.Read(ref _state); } }
        public bool IsCompleted { get { return _completion.IsSet; } }

        public bool Wait(TimeSpan timeout)
        {
            if (timeout != Timeout.InfiniteTimeSpan && timeout < TimeSpan.Zero) throw new ArgumentOutOfRangeException("timeout");
            return _completion.Wait(timeout);
        }

        internal bool TryActivate()
        {
            if (Interlocked.CompareExchange(ref _state, (int)MessageQueueRequestState.Active, (int)MessageQueueRequestState.Pending) != (int)MessageQueueRequestState.Pending)
            {
                return false;
            }
            StartedAtUtc = DateTime.UtcNow;
            return true;
        }

        internal void Complete(MessageQueueRequestState state, string errorMessage)
        {
            if (state != MessageQueueRequestState.Succeeded && state != MessageQueueRequestState.Failed && state != MessageQueueRequestState.Cancelled)
            {
                throw new ArgumentOutOfRangeException("state");
            }

            int prior;
            do
            {
                prior = Volatile.Read(ref _state);
                if (prior != (int)MessageQueueRequestState.Active && prior != (int)MessageQueueRequestState.Pending) return;
            }
            while (Interlocked.CompareExchange(ref _state, (int)state, prior) != prior);
            ErrorMessage = errorMessage;
            CompletedAtUtc = DateTime.UtcNow;
            _completion.Set();
        }

        internal void Supersede(Guid replacementRequestId)
        {
            if (Interlocked.CompareExchange(ref _state, (int)MessageQueueRequestState.Superseded, (int)MessageQueueRequestState.Pending) != (int)MessageQueueRequestState.Pending)
            {
                return;
            }
            SupersededByRequestId = replacementRequestId;
            CompletedAtUtc = DateTime.UtcNow;
            _completion.Set();
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0) _completion.Dispose();
        }
    }

    public sealed class MessageQueueWorkItem
    {
        internal MessageQueueWorkItem(MessageQueueTicket ticket, object payload)
        {
            Ticket = ticket;
            Payload = payload;
        }

        public MessageQueueTicket Ticket { get; private set; }
        public object Payload { get; private set; }
    }

    internal sealed class MessageTargetQueue
    {
        private readonly object _sync = new object();
        private readonly LinkedList<MessageQueueWorkItem> _pending = new LinkedList<MessageQueueWorkItem>();
        private readonly Dictionary<string, LinkedListNode<MessageQueueWorkItem>> _coalesced =
            new Dictionary<string, LinkedListNode<MessageQueueWorkItem>>(StringComparer.OrdinalIgnoreCase);
        private bool _accepting = true;
        private int _activeCount;

        public int PendingCount { get { lock (_sync) return _pending.Count; } }
        public int ActiveCount { get { lock (_sync) return _activeCount; } }
        public bool IsAccepting { get { lock (_sync) return _accepting; } }
        public bool IsCompleted { get { lock (_sync) return !_accepting && _pending.Count == 0 && _activeCount == 0; } }

        public void Enqueue(MessageQueueWorkItem workItem)
        {
            lock (_sync)
            {
                if (!_accepting) throw new InvalidOperationException("The message queue is no longer accepting requests.");

                string queueKey = workItem.Ticket.QueueKey;
                LinkedListNode<MessageQueueWorkItem> existingNode;
                if (!string.IsNullOrWhiteSpace(queueKey) && _coalesced.TryGetValue(queueKey, out existingNode))
                {
                    _pending.Remove(existingNode);
                    _coalesced.Remove(queueKey);
                    existingNode.Value.Ticket.Supersede(workItem.Ticket.RequestId);
                }

                LinkedListNode<MessageQueueWorkItem> node = _pending.AddLast(workItem);
                if (!string.IsNullOrWhiteSpace(queueKey)) _coalesced[queueKey] = node;
                Monitor.PulseAll(_sync);
            }
        }

        public MessageQueueWorkItem Take(CancellationToken cancellationToken)
        {
            lock (_sync)
            {
                while (true)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (_pending.Count > 0)
                    {
                        LinkedListNode<MessageQueueWorkItem> node = _pending.First;
                        _pending.RemoveFirst();
                        string queueKey = node.Value.Ticket.QueueKey;
                        if (!string.IsNullOrWhiteSpace(queueKey)) _coalesced.Remove(queueKey);
                        if (!node.Value.Ticket.TryActivate()) continue;
                        _activeCount++;
                        return node.Value;
                    }
                    if (!_accepting) return null;
                    Monitor.Wait(_sync, 250);
                }
            }
        }

        public void Complete(MessageQueueWorkItem workItem, MessageQueueRequestState state, string errorMessage)
        {
            lock (_sync)
            {
                workItem.Ticket.Complete(state, errorMessage);
                if (_activeCount > 0) _activeCount--;
                Monitor.PulseAll(_sync);
            }
        }

        public void CompleteAdding()
        {
            lock (_sync)
            {
                _accepting = false;
                Monitor.PulseAll(_sync);
            }
        }

        public void CancelPending(string reason)
        {
            lock (_sync)
            {
                foreach (MessageQueueWorkItem workItem in _pending)
                {
                    workItem.Ticket.Complete(MessageQueueRequestState.Cancelled, reason);
                }
                _pending.Clear();
                _coalesced.Clear();
                _accepting = false;
                Monitor.PulseAll(_sync);
            }
        }
    }

    public sealed class MessageQueueBroker : IDisposable
    {
        private readonly object _sync = new object();
        private readonly Dictionary<string, MessageTargetQueue> _targets =
            new Dictionary<string, MessageTargetQueue>(StringComparer.Ordinal);
        private readonly ConcurrentDictionary<Guid, MessageQueueTicket> _tickets =
            new ConcurrentDictionary<Guid, MessageQueueTicket>();
        private bool _accepting = true;
        private int _disposed;

        public bool IsAccepting { get { lock (_sync) return _accepting; } }
        public int TargetCount { get { lock (_sync) return _targets.Count; } }

        public MessageQueueTicket Enqueue(string transport, string targetId, string queueKey, string sessionKey, object payload)
        {
            if (string.IsNullOrWhiteSpace(transport)) throw new ArgumentException("A transport is required.", "transport");
            if (string.IsNullOrWhiteSpace(targetId)) throw new ArgumentException("A target ID is required.", "targetId");
            if (payload == null) throw new ArgumentNullException("payload");

            MessageQueueTicket ticket = new MessageQueueTicket(transport, targetId, queueKey, sessionKey);
            MessageTargetQueue target;
            lock (_sync)
            {
                ThrowIfDisposed();
                if (!_accepting) throw new InvalidOperationException("The message queue is no longer accepting requests.");
                if (!_targets.TryGetValue(targetId, out target))
                {
                    target = new MessageTargetQueue();
                    _targets[targetId] = target;
                }
                target.Enqueue(new MessageQueueWorkItem(ticket, payload));
                // Register only accepted work. A target cancelled after worker startup failure rejects
                // later requests, which must not leave unreachable Pending tickets in the broker.
                _tickets[ticket.RequestId] = ticket;
            }
            return ticket;
        }

        public MessageQueueWorkItem Take(string targetId, CancellationToken cancellationToken)
        {
            MessageTargetQueue target;
            lock (_sync)
            {
                ThrowIfDisposed();
                if (!_targets.TryGetValue(targetId, out target)) throw new KeyNotFoundException("The message target does not exist.");
            }
            return target.Take(cancellationToken);
        }

        public void Complete(MessageQueueWorkItem workItem, bool succeeded, string errorMessage)
        {
            if (workItem == null) throw new ArgumentNullException("workItem");
            MessageTargetQueue target;
            lock (_sync)
            {
                if (!_targets.TryGetValue(workItem.Ticket.TargetId, out target)) return;
            }
            target.Complete(workItem, succeeded ? MessageQueueRequestState.Succeeded : MessageQueueRequestState.Failed, errorMessage);
        }

        public MessageQueueTicket GetTicket(Guid requestId)
        {
            MessageQueueTicket ticket;
            return _tickets.TryGetValue(requestId, out ticket) ? ticket : null;
        }

        public MessageQueueTicket[] GetTickets()
        {
            return _tickets.Values.OrderBy(ticket => ticket.CreatedAtUtc).ToArray();
        }

        public string[] GetTargetIds()
        {
            lock (_sync) return _targets.Keys.ToArray();
        }

        public bool IsTargetCompleted(string targetId)
        {
            lock (_sync)
            {
                MessageTargetQueue target;
                return !_targets.TryGetValue(targetId, out target) || target.IsCompleted;
            }
        }

        public void CompleteAdding()
        {
            MessageTargetQueue[] targets;
            lock (_sync)
            {
                if (!_accepting) return;
                _accepting = false;
                targets = _targets.Values.ToArray();
            }
            foreach (MessageTargetQueue target in targets) target.CompleteAdding();
        }

        public bool WaitForIdle(TimeSpan timeout)
        {
            if (timeout != Timeout.InfiniteTimeSpan && timeout < TimeSpan.Zero) throw new ArgumentOutOfRangeException("timeout");
            DateTime deadline = timeout == Timeout.InfiniteTimeSpan ? DateTime.MaxValue : DateTime.UtcNow.Add(timeout);
            while (true)
            {
                MessageTargetQueue[] targets;
                lock (_sync) targets = _targets.Values.ToArray();
                if (targets.All(target => target.PendingCount == 0 && target.ActiveCount == 0)) return true;
                if (DateTime.UtcNow >= deadline) return false;
                Thread.Sleep(25);
            }
        }

        public void CancelPending(string reason)
        {
            MessageTargetQueue[] targets;
            lock (_sync)
            {
                _accepting = false;
                targets = _targets.Values.ToArray();
            }
            foreach (MessageTargetQueue target in targets) target.CancelPending(reason);
        }

        public void CancelTarget(string targetId, string reason)
        {
            MessageTargetQueue target;
            lock (_sync)
            {
                if (!_targets.TryGetValue(targetId, out target)) return;
            }
            target.CancelPending(reason);
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
            CompleteAdding();
            CancelPending("The message queue was disposed before the request could be sent.");
        }

        private void ThrowIfDisposed()
        {
            if (Volatile.Read(ref _disposed) != 0) throw new ObjectDisposedException("MessageQueueBroker");
        }
    }

    public interface IMessageQueueClock
    {
        DateTime UtcNow { get; }
        void Wait(TimeSpan delay, CancellationToken cancellationToken);
    }

    internal sealed class SystemMessageQueueClock : IMessageQueueClock
    {
        public DateTime UtcNow { get { return DateTime.UtcNow; } }

        public void Wait(TimeSpan delay, CancellationToken cancellationToken)
        {
            if (delay <= TimeSpan.Zero) return;
            if (cancellationToken.WaitHandle.WaitOne(delay)) cancellationToken.ThrowIfCancellationRequested();
        }
    }

    internal sealed class DelegateMessageQueueClock : IMessageQueueClock
    {
        private readonly Func<DateTime> _utcNow;
        private readonly Action<TimeSpan, CancellationToken> _wait;

        public DelegateMessageQueueClock(Func<DateTime> utcNow, Action<TimeSpan, CancellationToken> wait)
        {
            _utcNow = utcNow ?? throw new ArgumentNullException("utcNow");
            _wait = wait ?? throw new ArgumentNullException("wait");
        }

        public DateTime UtcNow { get { return _utcNow(); } }
        public void Wait(TimeSpan delay, CancellationToken cancellationToken) { _wait(delay, cancellationToken); }
    }

    public sealed class MessageRateLimitContext
    {
        private readonly object _sync = new object();
        private readonly TimeSpan _minimumInterval;
        private readonly CancellationToken _cancellationToken;
        private readonly IMessageQueueClock _clock;
        private DateTime _nextAllowedUtc = DateTime.MinValue;

        public MessageRateLimitContext(
            TimeSpan minimumInterval,
            int maximumRetryDelaySeconds,
            int maximumTotalRetryDelaySeconds,
            CancellationToken cancellationToken)
            : this(minimumInterval, maximumRetryDelaySeconds, maximumTotalRetryDelaySeconds, cancellationToken, new SystemMessageQueueClock())
        {
        }

        public MessageRateLimitContext(
            TimeSpan minimumInterval,
            int maximumRetryDelaySeconds,
            int maximumTotalRetryDelaySeconds,
            CancellationToken cancellationToken,
            IMessageQueueClock clock)
        {
            if (minimumInterval < TimeSpan.Zero) throw new ArgumentOutOfRangeException("minimumInterval");
            if (maximumRetryDelaySeconds < 0) throw new ArgumentOutOfRangeException("maximumRetryDelaySeconds");
            if (maximumTotalRetryDelaySeconds < 0) throw new ArgumentOutOfRangeException("maximumTotalRetryDelaySeconds");
            _minimumInterval = minimumInterval;
            MaximumRetryDelaySeconds = maximumRetryDelaySeconds;
            MaximumTotalRetryDelaySeconds = maximumTotalRetryDelaySeconds;
            _cancellationToken = cancellationToken;
            _clock = clock ?? throw new ArgumentNullException("clock");
        }

        public MessageRateLimitContext(
            TimeSpan minimumInterval,
            int maximumRetryDelaySeconds,
            int maximumTotalRetryDelaySeconds,
            CancellationToken cancellationToken,
            Func<DateTime> utcNow,
            Action<TimeSpan, CancellationToken> wait)
            : this(
                minimumInterval,
                maximumRetryDelaySeconds,
                maximumTotalRetryDelaySeconds,
                cancellationToken,
                new DelegateMessageQueueClock(utcNow, wait))
        {
        }

        public DateTime NextAllowedUtc { get { lock (_sync) return _nextAllowedUtc; } }
        public int MaximumRetryDelaySeconds { get; private set; }
        public int MaximumTotalRetryDelaySeconds { get; private set; }

        public void Wait()
        {
            while (true)
            {
                _cancellationToken.ThrowIfCancellationRequested();
                TimeSpan delay;
                lock (_sync) delay = _nextAllowedUtc - _clock.UtcNow;
                if (delay <= TimeSpan.Zero) return;
                _clock.Wait(delay, _cancellationToken);
            }
        }

        public void MarkAttemptCompleted()
        {
            lock (_sync)
            {
                DateTime candidate = _clock.UtcNow.Add(_minimumInterval);
                if (candidate > _nextAllowedUtc) _nextAllowedUtc = candidate;
            }
        }

        public void SetRetryAfter(TimeSpan retryAfter)
        {
            if (retryAfter < TimeSpan.Zero) throw new ArgumentOutOfRangeException("retryAfter");
            lock (_sync)
            {
                DateTime candidate = _clock.UtcNow.Add(retryAfter);
                if (candidate > _nextAllowedUtc) _nextAllowedUtc = candidate;
            }
        }
    }
}
