# SPDX-License-Identifier: Apache-2.0
# Simple tasks use the shared invocation and configuration lifecycle without package state.
class SimpleTask : DumplingsTaskBase {
  SimpleTask([Collections.IDictionary]$Properties) : base($Properties) {}
}
