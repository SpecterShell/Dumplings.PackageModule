# SPDX-License-Identifier: Apache-2.0

# Collect per-task outcome details from lifecycle hooks and write a static
# status dashboard (status.json plus a JavaScript-rendered index.html) for the
# whole runner invocation.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Force stop on error
$ErrorActionPreference = 'Stop'

$Script:TaskStatusStoreKey = '__DumplingsTaskStatusRecords'
# Keep the most recent log entries per task; the tail explains the final outcome
$Script:TaskStatusLogLimit = 20
$Script:TaskStatusTextLimit = 500
$Script:TaskStatusErrorLimit = 1000

function Get-DumplingsTaskStatusStore {
  <#
  .SYNOPSIS
    Get the process-wide per-task status record store, creating it on first use.
  .PARAMETER Storage
    The process-wide storage shared across worker runspaces. A synchronized
    hashtable is locked while the store is created; plain dictionaries are
    accepted for standalone and test use.
  .OUTPUTS
    A ConcurrentDictionary keyed by task name holding ordered-dictionary records.
  #>
  [CmdletBinding()]
  [OutputType([System.Collections.Concurrent.ConcurrentDictionary[string, System.Collections.IDictionary]])]
  param (
    [Parameter(Mandatory)]
    [System.Collections.IDictionary]$Storage
  )

  if ($Storage -is [hashtable] -and $Storage.IsSynchronized) {
    [System.Threading.Monitor]::Enter($Storage.SyncRoot)
    try {
      if (-not $Storage.ContainsKey($Script:TaskStatusStoreKey)) {
        $Storage[$Script:TaskStatusStoreKey] = [System.Collections.Concurrent.ConcurrentDictionary[string, System.Collections.IDictionary]]::new([System.StringComparer]::OrdinalIgnoreCase)
      }
      return $Storage[$Script:TaskStatusStoreKey]
    } finally {
      [System.Threading.Monitor]::Exit($Storage.SyncRoot)
    }
  }

  if (-not $Storage.Contains($Script:TaskStatusStoreKey)) {
    $Storage[$Script:TaskStatusStoreKey] = [System.Collections.Concurrent.ConcurrentDictionary[string, System.Collections.IDictionary]]::new([System.StringComparer]::OrdinalIgnoreCase)
  }
  return $Storage[$Script:TaskStatusStoreKey]
}

function Get-TaskPropertyValue {
  <#
  .SYNOPSIS
    Read a property from a task object without tripping strict mode.
  .DESCRIPTION
    Task models are extensible, so status collection probes properties by name
    instead of assuming a concrete model type.
  #>
  [CmdletBinding()]
  [OutputType([object])]
  param (
    [object]$Task,

    [Parameter(Mandatory)]
    [ValidateNotNullOrWhiteSpace()]
    [string]$Name
  )

  if ($null -eq $Task) { return $null }
  $Property = $Task.PSObject.Properties[$Name]
  return $null -ne $Property ? $Property.Value : $null
}

function Register-DumplingsTaskStatus {
  <#
  .SYNOPSIS
    Record the outcome details of one finished task for the status report.
  .DESCRIPTION
    Called from the AfterTask lifecycle hook. Core owns the authoritative
    coarse state of every task; this record only carries the details Core does
    not track: package identifier, version, status flags, recent logs, and the
    invocation error. The record is keyed by task name in process-wide storage
    so concurrent workers can register independently.
  .PARAMETER Storage
    The process-wide storage shared across worker runspaces.
  .PARAMETER TaskName
    The name of the finished task.
  .PARAMETER Task
    The task object after invocation. Model-specific properties are read
    defensively and may be absent.
  .PARAMETER InvocationError
    The error record captured by Core when the task lifecycle failed.
  #>
  [CmdletBinding()]
  param (
    [Parameter(Mandatory)]
    [System.Collections.IDictionary]$Storage,

    [Parameter(Mandatory)]
    [ValidateNotNullOrWhiteSpace()]
    [string]$TaskName,

    [object]$Task,

    [object]$InvocationError
  )

  $Record = [ordered]@{
    Identifier = $null
    Version    = $null
    Statuses   = [string[]]@()
    Logs       = [string[]]@()
    Error      = $null
  }

  if ($null -ne $Task) {
    # Effective package identifier, mirroring the WinGet submission claim precedence
    $Config = Get-TaskPropertyValue -Task $Task -Name 'Config'
    if ($Config -is [System.Collections.IDictionary]) {
      foreach ($Key in 'WinGetNewPackageIdentifier', 'WinGetNewIdentifier', 'WinGetPackageIdentifier', 'WinGetIdentifier') {
        if ($Config.Contains($Key) -and -not [string]::IsNullOrWhiteSpace([string]$Config[$Key])) {
          $Record.Identifier = [string]$Config[$Key]
          break
        }
      }
    }

    # Prefer the version discovered in this run over the persisted last state
    foreach ($StateName in 'CurrentState', 'LastState') {
      $State = Get-TaskPropertyValue -Task $Task -Name $StateName
      if ($State -is [System.Collections.IDictionary] -and $State.Contains('Version') -and -not [string]::IsNullOrWhiteSpace([string]$State['Version'])) {
        $Record.Version = [string]$State['Version']
        break
      }
    }

    $Statuses = Get-TaskPropertyValue -Task $Task -Name 'Status'
    if ($null -ne $Statuses) {
      $Record.Statuses = [string[]]@($Statuses | ForEach-Object -Process { [string]$_ })
    }

    $Logs = Get-TaskPropertyValue -Task $Task -Name 'Logs'
    if ($null -ne $Logs) {
      $Record.Logs = [string[]]@(
        $Logs | Select-Object -Last $Script:TaskStatusLogLimit | ForEach-Object -Process {
          $Entry = [string]$_
          $Entry.Length -gt $Script:TaskStatusTextLimit ? $Entry.Substring(0, $Script:TaskStatusTextLimit) + '...[truncated]' : $Entry
        }
      )
    }
  }

  if ($null -ne $InvocationError) {
    $ErrorText = [string]$InvocationError
    $Record.Error = $ErrorText.Length -gt $Script:TaskStatusErrorLimit ? $ErrorText.Substring(0, $Script:TaskStatusErrorLimit) + '...[truncated]' : $ErrorText
  }

  (Get-DumplingsTaskStatusStore -Storage $Storage)[$TaskName] = $Record
}

function Get-DumplingsTaskStatusPage {
  <#
  .SYNOPSIS
    Return the static task status dashboard page.
  .DESCRIPTION
    The page is a static shell that fetches status.json from the same
    directory at view time and renders it in the browser. Task data is never
    embedded into the HTML, so the page stays small no matter how many tasks a
    run covers. All rendering goes through textContent, so report content
    cannot inject markup into the page.
  .OUTPUTS
    The dashboard HTML document.
  #>
  [CmdletBinding()]
  [OutputType([string])]
  param ()

  return @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Dumplings task status</title>
<style>
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 1.5rem 2rem 3rem; line-height: 1.45; }
h1 { font-size: 1.4rem; margin: 0 0 .25rem; }
a { color: inherit; }
.meta { opacity: .75; font-size: .9rem; margin: 0 0 1rem; }
.summary { display: flex; flex-wrap: wrap; gap: .5rem; margin: 0 0 1rem; padding: 0; list-style: none; }
.controls { display: flex; flex-wrap: wrap; align-items: center; gap: .5rem; margin-bottom: .8rem; }
.controls input, .controls select, .controls button { padding: .35rem .6rem; font-size: .95rem; border: 1px solid light-dark(#c8c8c8, #555); border-radius: .4rem; background: light-dark(#fff, #1e1e1e); color: inherit; }
.controls button { cursor: pointer; }
.controls input { flex: 1 1 16rem; }
.controls .count { opacity: .7; font-size: .85rem; }
table { border-collapse: collapse; width: 100%; font-size: .92rem; }
th, td { text-align: left; padding: .4rem .6rem; border-bottom: 1px solid light-dark(#e3e3e3, #3a3a3a); vertical-align: top; }
th { position: sticky; top: 0; background: light-dark(#fff, #121212); }
tbody tr:hover td { background: light-dark(#f6f6f6, #242424); }
td.name { font-weight: 600; }
td.name .identifier { display: block; font-weight: 400; opacity: .7; font-size: .82rem; overflow-wrap: anywhere; }
td.version { overflow-wrap: anywhere; }
.badge { display: inline-block; padding: .1rem .55rem; border-radius: 1rem; font-size: .8rem; font-weight: 700; white-space: nowrap; }
.state-Succeeded { background: #dafbe1; color: #116329; }
.state-Failed { background: #ffebe9; color: #a40e26; }
.state-Skipped { background: #f0e7ff; color: #6240b8; }
.state-Blocked { background: #fff1e0; color: #8a4600; }
.state-Running { background: #ddf4ff; color: #0550ae; }
.state-Pending { background: #eaeef2; color: #57606a; }
.flag { display: inline-block; padding: .05rem .45rem; margin: .05rem .15rem .05rem 0; border-radius: .3rem; font-size: .78rem; background: light-dark(#eef1f4, #2c333b); }
details { font-size: .85rem; }
details summary { cursor: pointer; opacity: .8; }
details pre { margin: .35rem 0 .6rem; padding: .5rem .7rem; border-radius: .4rem; background: light-dark(#f3f4f6, #1c2128); white-space: pre-wrap; overflow-wrap: anywhere; max-height: 18rem; overflow-y: auto; }
details.error summary { color: #cf222e; opacity: 1; }
.footer { margin-top: 1.5rem; font-size: .82rem; opacity: .65; }
</style>
</head>
<body>
<h1>Dumplings task status</h1>
<p class="meta" id="meta">Loading status...</p>
<ul class="summary" id="summary"></ul>
<div class="controls">
<input id="filter" type="search" placeholder="Filter by task, identifier, or version" aria-label="Filter tasks">
<select id="state" aria-label="Filter by state"><option value="">All states</option></select>
<button id="expand-all" type="button" title="Expand the logs of every shown task">Expand all logs</button>
<button id="collapse-all" type="button">Collapse all logs</button>
<span class="count">Showing <span id="shown">0</span> / <span id="total">0</span></span>
</div>
<table id="tasks">
<thead><tr><th>Task</th><th>State</th><th>Version</th><th>Flags</th><th>Details</th></tr></thead>
<tbody></tbody>
</table>
<p class="footer">Machine-readable data: <a href="status.json">status.json</a></p>
<script>
(function () {
  var STATE_ORDER = ['Failed', 'Blocked', 'Running', 'Pending', 'Skipped', 'Succeeded'];

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) { node.className = className; }
    if (text !== undefined && text !== null) { node.textContent = text; }
    return node;
  }

  function renderMeta(data) {
    var meta = document.getElementById('meta');
    meta.textContent = 'Generated ' + data.generatedAt + ' | Stop reason: ' + data.stopReason;
    if (!data.run) { return; }
    meta.appendChild(document.createTextNode(' | '));
    var runLabel = (data.run.workflow || 'Workflow') + ' run #' + data.run.runNumber;
    if (data.run.url) {
      var runLink = el('a', null, runLabel);
      runLink.href = data.run.url;
      meta.appendChild(runLink);
    } else {
      meta.appendChild(document.createTextNode(runLabel));
    }
    if (data.run.commit) {
      meta.appendChild(document.createTextNode(' (' + data.run.commit.substring(0, 7) + ')'));
    }
  }

  function renderSummary(data) {
    var summary = document.getElementById('summary');
    summary.appendChild(el('li', 'badge', data.summary.total + ' tasks'));
    var stateSelect = document.getElementById('state');
    STATE_ORDER.forEach(function (state) {
      var count = data.summary[state.toLowerCase()] || 0;
      if (count <= 0) { return; }
      summary.appendChild(el('li', 'badge state-' + state, count + ' ' + state.toLowerCase()));
      var option = el('option', null, state + ' (' + count + ')');
      option.value = state;
      stateSelect.appendChild(option);
    });
  }

  function renderRows(data) {
    var tbody = document.querySelector('#tasks tbody');
    var linkBase = data.run && data.run.repositoryUrl && data.run.commit ? data.run.repositoryUrl + '/tree/' + data.run.commit + '/Tasks/' : null;
    data.tasks.forEach(function (task) {
      var row = document.createElement('tr');
      row.setAttribute('data-state', task.state);
      row.setAttribute('data-search', ((task.name || '') + ' ' + (task.identifier || '') + ' ' + (task.version || '')).toLowerCase());

      var nameCell = el('td', 'name');
      if (linkBase) {
        var nameLink = el('a', null, task.name);
        nameLink.href = linkBase + encodeURIComponent(task.name);
        nameCell.appendChild(nameLink);
      } else {
        nameCell.appendChild(document.createTextNode(task.name));
      }
      if (task.identifier && task.identifier !== task.name) {
        nameCell.appendChild(el('span', 'identifier', task.identifier));
      }
      row.appendChild(nameCell);

      var stateCell = document.createElement('td');
      stateCell.appendChild(el('span', 'badge state-' + task.state, task.state));
      row.appendChild(stateCell);

      row.appendChild(el('td', 'version', task.version || ''));

      var flagsCell = el('td', 'flags');
      (task.statuses || []).forEach(function (flag) {
        flagsCell.appendChild(el('span', 'flag', flag));
        flagsCell.appendChild(document.createTextNode(' '));
      });
      row.appendChild(flagsCell);

      var detailsCell = el('td', 'details');
      var logs = task.logs || [];
      if (logs.length > 0) {
        var logDetails = document.createElement('details');
        logDetails.appendChild(el('summary', null, 'Logs (' + logs.length + ')'));
        logDetails.appendChild(el('pre', null, logs.join('\n')));
        detailsCell.appendChild(logDetails);
      }
      if (task.error) {
        var errorDetails = document.createElement('details');
        errorDetails.className = 'error';
        errorDetails.appendChild(el('summary', null, 'Error'));
        errorDetails.appendChild(el('pre', null, task.error));
        detailsCell.appendChild(errorDetails);
      }
      row.appendChild(detailsCell);

      tbody.appendChild(row);
    });
    document.getElementById('total').textContent = data.summary.total;
  }

  function bindControls() {
    var q = document.getElementById('filter');
    var s = document.getElementById('state');
    var rows = Array.prototype.slice.call(document.querySelectorAll('#tasks tbody tr'));
    var shown = document.getElementById('shown');
    shown.textContent = rows.length;
    function apply() {
      var text = q.value.toLowerCase();
      var state = s.value;
      var visible = 0;
      for (var i = 0; i < rows.length; i++) {
        var match = (!state || rows[i].getAttribute('data-state') === state) && (!text || rows[i].getAttribute('data-search').indexOf(text) !== -1);
        rows[i].style.display = match ? '' : 'none';
        if (match) { visible++; }
      }
      shown.textContent = visible;
    }
    q.addEventListener('input', apply);
    s.addEventListener('change', apply);
    function setOpen(details, open) {
      for (var i = 0; i < details.length; i++) { details[i].open = open; }
    }
    document.getElementById('expand-all').addEventListener('click', function () {
      // Only shown rows are expanded; opening many log sections at once can slow
      // down the page, so ask first
      var details = [];
      for (var i = 0; i < rows.length; i++) {
        if (rows[i].style.display === 'none') { continue; }
        var rowDetails = rows[i].querySelectorAll('details');
        for (var j = 0; j < rowDetails.length; j++) { details.push(rowDetails[j]); }
      }
      if (details.length >= 100 && !window.confirm('This will expand ' + details.length + ' log sections and may slow down the page. Continue?')) { return; }
      setOpen(details, true);
    });
    document.getElementById('collapse-all').addEventListener('click', function () {
      setOpen(document.querySelectorAll('#tasks details'), false);
    });
  }

  fetch('status.json')
    .then(function (response) {
      if (!response.ok) { throw new Error('HTTP ' + response.status); }
      return response.json();
    })
    .then(function (data) {
      renderMeta(data);
      renderSummary(data);
      renderRows(data);
      bindControls();
    })
    .catch(function (error) {
      document.getElementById('meta').textContent = 'Failed to load status.json: ' + error.message +
        '. If you opened this file from disk, view the published GitHub Pages site instead.';
    });
})();
</script>
</body>
</html>
'@
}

function Export-DumplingsTaskStatusReport {
  <#
  .SYNOPSIS
    Merge Core task states with recorded task details and write the status dashboard.
  .DESCRIPTION
    Called from the RunnerStopping lifecycle hook. Every planned task appears in
    the report, including blocked or never-started tasks that have no recorded
    details. The report consists of a machine-readable status.json and a static
    index.html that fetches status.json at view time, written to a Status
    folder beneath the output directory, ready to be published as a GitHub
    Pages site.
  .PARAMETER TaskStates
    The authoritative task-state map owned by Core, keyed by task name with
    values such as Succeeded, Failed, Skipped, Blocked, Running, or Pending.
  .PARAMETER Storage
    The process-wide storage holding the records collected by
    Register-DumplingsTaskStatus.
  .PARAMETER OutputPath
    The runner output directory. The report is written to its Status subfolder.
  .PARAMETER StopReason
    Why the runner stopped, as reported by Core.
  .OUTPUTS
    The path of the written report folder.
  #>
  [CmdletBinding()]
  [OutputType([string])]
  param (
    [Parameter(Mandatory)]
    [System.Collections.IDictionary]$TaskStates,

    [Parameter(Mandatory)]
    [System.Collections.IDictionary]$Storage,

    [Parameter(Mandatory)]
    [ValidateNotNullOrWhiteSpace()]
    [string]$OutputPath,

    [ValidateNotNullOrEmpty()]
    [string]$StopReason = 'Completed'
  )

  $Records = Get-DumplingsTaskStatusStore -Storage $Storage

  $Summary = [ordered]@{
    total     = 0
    succeeded = 0
    failed    = 0
    skipped   = 0
    blocked   = 0
    running   = 0
    pending   = 0
  }

  $Tasks = [System.Collections.Generic.List[System.Collections.IDictionary]]::new()
  foreach ($TaskState in $TaskStates.GetEnumerator()) {
    [System.Collections.IDictionary]$Record = $null
    if (-not $Records.TryGetValue([string]$TaskState.Key, [ref]$Record)) { $Record = $null }

    $State = [string]$TaskState.Value
    $Tasks.Add([ordered]@{
        name       = [string]$TaskState.Key
        state      = $State
        identifier = $null -ne $Record ? $Record['Identifier'] : $null
        version    = $null -ne $Record ? $Record['Version'] : $null
        statuses   = $null -ne $Record ? [string[]]$Record['Statuses'] : [string[]]@()
        logs       = $null -ne $Record ? [string[]]$Record['Logs'] : [string[]]@()
        error      = $null -ne $Record ? $Record['Error'] : $null
      })

    $Summary.total++
    $SummaryKey = $State.ToLower()
    if ($Summary.Contains($SummaryKey)) { $Summary[$SummaryKey]++ }
  }

  # Surface failures first, then order by task name
  $StateOrder = @{ Failed = 0; Blocked = 1; Running = 2; Pending = 3; Skipped = 4; Succeeded = 5 }
  $SortedTasks = @(
    $Tasks | Sort-Object -Property @{ Expression = { $StateOrder.Contains([string]$_.state) ? $StateOrder[[string]$_.state] : 9 } }, @{ Expression = { [string]$_.name } }
  )

  $Run = $null
  if (-not [string]::IsNullOrWhiteSpace($Env:GITHUB_RUN_ID)) {
    $Run = [ordered]@{
      workflow      = [string]$Env:GITHUB_WORKFLOW
      runNumber     = [string]$Env:GITHUB_RUN_NUMBER
      runId         = [string]$Env:GITHUB_RUN_ID
      repository    = [string]$Env:GITHUB_REPOSITORY
      commit        = [string]$Env:GITHUB_SHA
      url           = "${Env:GITHUB_SERVER_URL}/${Env:GITHUB_REPOSITORY}/actions/runs/${Env:GITHUB_RUN_ID}"
      repositoryUrl = "${Env:GITHUB_SERVER_URL}/${Env:GITHUB_REPOSITORY}"
    }
  }

  $Payload = [ordered]@{
    generatedAt = (Get-Date -AsUTC).ToString('yyyy-MM-ddTHH:mm:ssZ')
    stopReason  = $StopReason
    run         = $Run
    summary     = $Summary
    tasks       = $SortedTasks
  }

  $ReportPath = (New-Item -Path (Join-Path $OutputPath 'Status') -ItemType Directory -Force).FullName
  ConvertTo-Json -InputObject $Payload -Depth 8 -Compress | Set-Content -LiteralPath (Join-Path $ReportPath 'status.json') -Encoding utf8NoBOM
  Get-DumplingsTaskStatusPage | Set-Content -LiteralPath (Join-Path $ReportPath 'index.html') -Encoding utf8NoBOM

  return $ReportPath
}

Export-ModuleMember -Function Register-DumplingsTaskStatus, Export-DumplingsTaskStatusReport
