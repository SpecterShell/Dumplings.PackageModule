// SPDX-License-Identifier: Apache-2.0

using System;
using System.Reflection;
using System.Threading.Tasks;

namespace Dumplings.Playwright
{
    /// <summary>
    /// Completes Playwright tasks without installing PowerShell callbacks or
    /// depending on PowerShell's pipeline synchronization context.
    /// </summary>
    public static class PlaywrightTaskBridge
    {
        public static object Wait(Task task, TimeSpan timeout)
        {
            if (task == null) throw new ArgumentNullException("task");
            if (timeout != System.Threading.Timeout.InfiniteTimeSpan && timeout <= TimeSpan.Zero)
                throw new ArgumentOutOfRangeException("timeout");

            if (timeout != System.Threading.Timeout.InfiniteTimeSpan)
            {
                Task completed = Task.WhenAny(task, Task.Delay(timeout)).GetAwaiter().GetResult();
                if (!ReferenceEquals(completed, task))
                    throw new TimeoutException("The Playwright operation did not complete within " + timeout + ".");
            }

            // GetAwaiter().GetResult() preserves the original exception rather than
            // wrapping it in AggregateException as Task.Wait() would.
            task.GetAwaiter().GetResult();

            Type current = task.GetType();
            while (current != null)
            {
                if (current.IsGenericType && current.GetGenericTypeDefinition() == typeof(Task<>))
                {
                    PropertyInfo result = current.GetProperty("Result", BindingFlags.Public | BindingFlags.Instance);
                    object value = result == null ? null : result.GetValue(task, null);
                    // Task.CompletedTask can be implemented internally as
                    // Task<VoidTaskResult>; that implementation detail is not output.
                    return value != null && value.GetType().FullName == "System.Threading.Tasks.VoidTaskResult" ? null : value;
                }
                current = current.BaseType;
            }
            return null;
        }
    }
}
