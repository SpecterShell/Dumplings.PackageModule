# Dumplings.PackageModule

Dumplings.PackageModule provides package automation and WinGet tooling for [Dumplings](https://github.com/SpecterShell/Dumplings). It runs on Windows with PowerShell 7.4 or later and is licensed under Apache-2.0, with the file-level exceptions listed below.

## Loading

Core loads PackageModule through `Index.ps1` in every task worker. Standalone callers should import the module manifest:

```powershell
Import-Module .\Modules\PackageModule\PackageModule.psd1 -Force
```

`PackageModule.psd1` is the supported entry point. `PackageModule.psm1` imports focused implementation modules in explicit dependency order. Each command retains its implementation-module owner so PowerShell exposes one command with its native help and completion metadata. `Index.ps1` imports that manifest globally, then loads the task model classes for Core.

Libraries are grouped by responsibility.

- `Infrastructure` contains bounded binary, archive, PE, cabinet, filesystem, parser-bridge, installed-state, and provider-neutral installer-analysis mechanics.
- `Installers` contains installer-family parsing and extraction. Thin executable wrappers use separate `DotNetInstaller`, `IExpress`, `SevenZipSfx`, and `WinRarSfx` modules backed by the shared `Bootstrapper` command resolver.
- `WinGet` contains manifest policy, matching, repositories, downloads, and submission.
- `Data`, `Networking`, `Browser`, and `Messaging` contain their corresponding integrations.

Functions that perform task execution, messaging, or submission expect the globals initialized by Core. Static parser and manifest functions can be used independently when their documented parameters are supplied.

## Responsibilities

### Task Models

`PackageTask` persists a release state and exposes the task-script lifecycle:

- `$this.Check()` validates and compares the current version and installer URLs with the previous state.
- `$this.Print()` prints the current state.
- `$this.Write()` writes a timestamped log and updates `State.yaml` when enabled.
- `$this.Message()` queues a state notification when enabled.
- `$this.Submit()` generates and submits manifests when enabled.

`SimpleTask` provides the same Core construction and skip behavior for scripts that do not need package state or WinGet submission.

Use the [`author-dumplings-task` skill](../../.agents/skills/author-dumplings-task/SKILL.md) for task layout, state handling, source patterns, providers, and dry runs.

Use the [`use-dumplings-functions` skill](../../.agents/skills/use-dumplings-functions/SKILL.md) for the curated networking, temporary-file, archive, content, feed, browser, HTML, and YAML helper contracts used by tasks and standalone analysis.

Package submissions are claimed by effective WinGet identifier in process-wide shared storage. The first task owns the claim for the run. Duplicate tasks skip submission, so they do not race the same package.

`DumplingsTaskBase` handles construction, invocation status, and logging for `SimpleTask` and `PackageTask`. `PackageTask` handles state comparison and submission. Markdown and Telegram notifications share one state traversal with format-specific escaping and spacing. An identical state notification is suppressed while its ticket remains usable. Failed, cancelled, or superseded tickets can be retried. Custom messages remain distinct.

Normal imports reuse modules within a runspace. During development, reload them with `Index.ps1 -Reload` or `Import-Module ./PackageModule.psd1 -Force -ArgumentList $true`. Commands retain their implementation-module ownership.

### Versionless Installer Tracking

`PackageTask.CheckInstallerUpdates(options)` checks per-installer ETag, Last-Modified, Content-Length, custom checksum headers, or SHA256. It downloads candidates, verifies hashes, and calls the required `ReadVersion(Path, Installer)` callback. It prepares `CurrentState` without writing files, messaging, or submitting. `CompleteInstallerUpdates(result)` applies the decision once, respecting the task's enablement settings. `Check()` retains its existing behavior.

```powershell
$this.CurrentState.Installer += [ordered]@{ InstallerUrl = 'https://example.com/setup.msi' }
$Result = $this.CheckInstallerUpdates(@{
  Validator = 'ETag'
  ReadVersion = { param($Path, $Installer) Read-ProductVersionFromMsi -Path $Path }
})
if ($Result.NeedsMetadata) {
  # Retrieve optional release notes here.
}
$this.CompleteInstallerUpdates($Result)
```

Unchanged validators avoid downloads. Changed validators with identical SHA256 refresh tracking only, preserving package metadata. New releases and same-version rebuilds use the normal submission safeguards. Rollbacks require explicit permission. All architectures must resolve to consistent versions. `Hash` always downloads, and `Force` also reruns version readers. Date and length checks can miss byte changes when the endpoint returns unchanged headers.

State stores bounded, versioned `InstallerTracking` records. It excludes HTTP responses, credentials, and temporary paths. Manifest updating reuses retained downloads and verified file identities without hashing again. Task disposal removes only owned files. `Installers` overrides provide stable keys and architecture-specific readers. Synchronous `Probe`/`Download` callbacks support custom endpoints.

See the [versionless task reference](../../.agents/skills/author-dumplings-task/references/sources/versionless.md) for complete options, callback contracts, outcomes, legacy mappings, and migration examples.

### Shared data and operation ownership

Use `Copy-Object` and `Test-ObjectValueEqual` from `Libraries/Data/Conversion.psm1`. They replace `Copy-WinGetManifestValue` and `Test-WinGetManifestValueEqual`. Copying preserves explicit nulls, nested empty arrays, ordered dictionaries, dates, and scriptblocks without a JSON round trip. It supports bounded data structures only and cannot clone arbitrary mutable .NET resources. Equality is case-sensitive, ignores dictionary key order, and preserves array order.

Each manifest-update operation owns its downloads, hashes, extracted ZIP entries, and parser results. Cache keys include file identity and every supplied parser option, including architecture, scope, and command line. Each entry applies cached parser facts to its own authored fields and diagnostic policy. Entries never share authored ARP values solely by URL. Cleanup in `finally` removes only operation-created files. Files supplied through `InstallerFiles` remain caller-owned. The internal metadata updater does not accept an `Installers` argument.

Submission reads remote reference manifests at one captured commit and carries that revision into branch creation. Confirmed identical PRs and empty changes stop redundant submission. If a comparison fails after retries, submission logs a warning and continues without those checks.

### Installer Analysis

Large families use locally imported implementation modules. CreateInstall separates Gentee decoding, operation evidence, and GEA archives. DeployMaster separates classic and modern media. InstallBuilder separates project semantics from Metakit/CookFS payloads. Family modules own public commands and compose results. Explicit parameters carry parsed programs, layouts, and catalogs between modules.

`Get-AKInstallerInfo` and `Expand-AKInstaller` cover classic GZip, legacy protected-ZIP/XOR, and modern protected-ZIP/RC4 AKInstaller media, current and historical encrypted AKInstallerMSI prerequisite wrappers, and direct embedded-MSI output. Native ARP identity comes from explicit compiled registry rows. MSI-wrapper identity comes from the selected nested MSI. Exact WinGet analysis maps the vendor's actionable outer bootstrapper outcomes to `ExpectedReturnCodes` while retaining generic failure code 1603 only as parser evidence.

`Get-DellUpdatePackageInfo`, `Test-DellUpdatePackage`, and `Expand-DellUpdatePackage` support Dell DUPFramework ZIP/7z wrappers, including catalog-derived framework 3.0/MUP 2.1 media. Mup.xml selects the vendor executable. The nested parser supplies ARP and scope. Selection preserves actual archive filename spelling for case-sensitive staging directories. Direct MSI metadata analysis stages only that database. EXE routes retain support files. Configuration, package metadata, vendor return mappings, supported architectures and localized revision history remain separate evidence. Extraction is bounded and never executes the wrapper's `/e` command. WinGet analysis uses the selected nested family's defaults through `/passthrough` without merging embedded MUP arguments. The original switches and vendor command remain available as an `EmbeddedMup` entry in `SuggestedManifestVariants` for focused fallback after a failed VM test. Incomplete or unsupported nested routes retain `/s`. Both routes use DUP return codes. `-CommandLine` accepts an explicit `/passthrough` command, preserving the vendor tail. Validate unattended support with that exact command. Authoring overrides and manifest updates forward authored switches into this analysis without automatically replacing existing commands. Unsupported hardware, opaque vendor launchers and distinct legacy SVMSEZ/BIOS containers remain explicit gaps.

TigerSetup formats 1-3 are handled by `Get-TigerSetupInfo`, `Test-TigerSetupInstaller` and `Expand-TigerSetupInstaller`. A physical-format catalog selects ZIP versus solid Zstd, raw versus compressed Protobuf, and generation-specific footer/schema validation. Resource validation precedes scope-specific ARP and system-effect projection. Authored `--install-root` overrides describe fresh-install evidence. Extraction preserves empty directories/files, avoids unrelated decoding for narrow selectors, verifies payloads and stages output before atomic per-file publication. Format-3 reconstructed uninstallers and rich ARP/association/PATH evidence have VM validation in both scopes, including limited-token user installation. Historical 0.5.2-0.11.0 source profiles have synthetic coverage, while 0.12.0-0.14.0 published artifacts are cached real regressions. [The focused workflow](../../.agents/skills/analyze-winget-installer/references/families/tiger-setup/workflow.md) covers commands and remaining artifact-specific VM checks.

Shared mechanics stay in the existing infrastructure and data modules: `Import-InstallerManagedAssembly` also accepts a literal provider path, `Read-BinaryInteger` accepts either a stream or byte buffer, and the data modules provide bounded text/XML readers and first-present dictionary lookup. Family-specific encoding choices, record bounds, and failure recovery remain at the call site.

`Get-InstallerAnalysis` detects file and installer families from structured content and magic bytes without applying package-provider policy or returning manifest suggestions. `Get-WinGetInstallerAnalysis` projects the same evidence into schema-valid `SuggestedManifestFields`, complete `SuggestedManifestVariants`, and separate `SuggestedNextSteps`. Generic EXE families keep their identity in `Family` and use `InstallerType: exe`. YAML family comments are not runtime values. `DetectedFamilies` contains only structurally confirmed or successfully parsed families, while `RoutingHints` and `RejectedCandidates` retain heuristic diagnostics without promoting them to detections. `FamilyCandidates` remains a confirmed-only compatibility projection.

Some implementations are maintained in the separately licensed InstallerParsers submodule. [`InstallerBridge.psm1`](Libraries/Infrastructure/InstallerBridge.psm1) invokes its JSON CLI in a child PowerShell process and returns deserialized evidence. It does not import GPL parser code into PackageModule's process module scope.

Each aggregate parser constructs the canonical identity/ARP envelope directly and returns context-neutral `Diagnostics` plus `UnresolvedFields`. Parsers do not write log messages directly. A diagnostic records its stable `Id`, `Source`, `Message`, `Kind`, affected areas and fields, and optional evidence. `FullAnalysis`, `Detection`, `ManifestAuthoring`, `ManifestUpdate`, and `Extraction` resolve that evidence to a log level and blocking decision only when it enters a workflow. This keeps family-specific ARP decisions in the parser that understands the format and prevents a partial manifest update from promoting unrelated parser limitations.

Public installer expansion functions resolve source and destination paths against PowerShell's filesystem location before passing them to .NET or a parser child process. Their optional `Name` selector defaults to `*`, so omitting it expands every catalogued payload within the parser's entry and byte limits. Extractors that can produce multiple files accept `CollisionAction Prompt|Error|Skip|Overwrite|Rename`. `Prompt` is the interactive default and offers `Rename` as its preselected choice. Functions and unattended automation that compose extractors pass `Rename` explicitly, allocating deterministic names such as `payload (1).dll` without opening a prompt.

Manifest updates run a known manifest-declared parser before generic detection. If metadata parsing fails, structural evidence classifies the result as matched, mismatched, or indeterminate. Only a definitive incompatible format produces a blocking diagnostic and throws. Matched or indeterminate failures preserve existing fields, and diagnostics unrelated to fields being refreshed stay verbose. Diagnostics are deduplicated within each installer entry and logged with an `[Installer #n/total]` prefix. Cached parser evidence remains attributed to every affected entry.

Bypass the parser stage globally with `-SkipInstallerAnalysis` or per task with `SkipInstallerAnalysis: true` in `Config.yaml`. This preserves existing installer metadata and skips nested extraction, family detection, and static parsing. SHA-256 downloads, release-date handling, formatting, validation, and submission still run.

Use the [`analyze-winget-installer` skill](../../.agents/skills/analyze-winget-installer/SKILL.md) for the supported workflow, parser routing, manifest interpretation, and VM-only validation rules.

### WinGet Manifests

Manifest processing uses these modules.

| Module | Responsibility |
| --- | --- |
| `YamlSchema.psm1` | Offline structured JSON-schema validation for YAML objects. |
| `WinGetManifestSchema.psm1` | WinGet schema selection, field ordering, and vendored schema access. |
| `WinGetManifestModel.psm1` | Logical manifest model, installer inheritance, post-processing, compaction, and merged projections. |
| `WinGetManifestSerialization.psm1` | Multi-file parsing, formatting, document sets, headers, and YAML output. |
| `WinGetManifestValidation.psm1` | Structural, schema, and semantic validation compatible with WinGet's local validation path. |
| `WinGetManifestUpdate.psm1` | Installer download, matching, parser metadata, and safe updates to existing authored fields. |
| `WinGetManifestAuthoring.psm1` | Immutable manifest creation/editing, conservative installer suggestions, and atomic local persistence. |
| `WinGetSubmission.psm1` | Repository acquisition, manifest generation, validation, duplicate-PR policy, and submission. |
| `SourceIdentity.psm1` | Forge- and storage-aware installer source identity normalization used by task state comparison to detect domain changes. |

Primary entry points include:

```powershell
# Read a singleton or multi-file manifest set into one logical model.
$Manifest = Read-WinGetManifest -Path C:\Manifests\Vendor.Package\1.2.3

# Validate a path or an in-memory logical model.
$Result = Get-WinGetManifestValidationResult -Manifest $Manifest

# Explicitly inspect the detached post-processed model when needed.
$Optimized = Optimize-WinGetManifest -Manifest $Manifest

# Format one authored document without adding or deleting fields.
$Formatted = Format-WinGetManifest -Manifest $InstallerDocument

# Analyze an installer without executing it.
$Analysis = Get-WinGetInstallerAnalysis -Path C:\Installers\setup.exe

# Analyze once, add the proposed installer, and atomically replace the leaf set.
$Suggestion = Get-WinGetInstallerManifestSuggestion `
  -InstallerUrl https://downloads.example.test/setup.exe `
  -InstallerPath C:\Installers\setup.exe `
  -PackageVersion $Manifest.PackageVersion
$Manifest = Add-WinGetManifestInstaller -Manifest $Manifest -Suggestion $Suggestion
Save-WinGetManifest -Manifest $Manifest -Path C:\Manifests\Vendor.Package\1.2.3
```

The logical model stores authored values only. WinGet-generated switches and return codes remain derived evidence. Serialization removes a common `InstallerLocale` and redundant ProductCode, InstallerType, name, and publisher fields from a sole Apps & Features entry. It then moves values shared by every installer to the manifest level, preserving installer overrides, recursive dictionary atoms, and atomic arrays. `Format-WinGetManifest` has no locale-document context and preserves every field.

`Utilities\WinGetManifest.ps1` provides `new`, installer/locale/value add-set-remove operations, `validate`, and `show` for standalone use. Mutating commands stage and validate a complete multi-file set before replacing the target directory. They never submit packages or execute installers.

### Supporting Services

- `WinGetDownload.psm1` reproduces WinGet-style Delivery Optimization and WinINet downloads, redirects, and headers with bounded retries and rate-limit handling.
- `WebDriver.psm1` provides leased Edge/Firefox sessions shared across concurrent tasks.
- `Playwright.psm1` provides a separately leased Patchright/Playwright page and browser context. It uses installed Edge for ordinary sessions and installed Chrome for stealth sessions, restores the pinned Patchright driver runtime, and synchronously unwraps tasks without registering PowerShell as an asynchronous callback.
- `MessageQueue.psm1`, `Telegram.psm1`, and `Matrix.psm1` provide per-target queues, coalescing, splitting, rate limiting, and session updates.
- `StatusReport.psm1` records per-task outcomes from the `AfterTask` hook and merges them with Core's authoritative task states in the `RunnerStopping` hook, writing a static status dashboard (`Outputs/Status/index.html` and `status.json`) that the Automation workflow publishes to GitHub Pages.
- `ARP.psm1` collects raw Apps & Features and MSI ownership evidence. `WinGetMatching.psm1` applies WinGet normalization and manifest matching.
- `Text.psm1` handles encoding, line endings, Base64, and list text. `Format.psm1` normalizes manifest text, while `HTML.psm1` renders HTML, Markdown, and tables. `Conversion.psm1` owns general value conversion, `Object.psm1` parses XML and INI data, and `ProtocolBuffers.psm1` decodes schema-less Protocol Buffers wire data.
- `WinGetGitHubRepo.psm1` and `WinGetLocalRepo.psm1` implement remote and local manifest repository workflows.

### Playwright

Use the scoped API to release the process-wide browser lease on task completion or runner timeout.

```powershell
$Html = Use-PlaywrightPage -Headless {
  param($Page, $Context, $Browser, $Session)

  $null = Wait-PlaywrightTask ($Page.GotoAsync('https://example.com/'))
  Wait-PlaywrightTask ($Page.ContentAsync())
}
```

The default Chromium channel is installed `msedge`. `-Stealth` uses the Apache-2.0 [Patchright](https://github.com/Kaliiiiiiiiii-Vinyzu/patchright) driver with installed `chrome` by default. Patchright is restored from [patchright-dotnet](https://github.com/DevEnterpriseSoftware/patchright-dotnet) and supports Chromium only. Use `Install-PlaywrightBrowser -Browser Chromium` when an installed channel is unsuitable. Media and YouTube requests are blocked by default. Pass `-BlockUrlPattern @()` to disable the filter.

The scoped API exposes the compatible controls used by
[Scrapling StealthyFetcher](https://github.com/D4Vinci/Scrapling), including
locale/timezone fingerprint settings, proxy and headers, init scripts, WebRTC,
WebGL and DNS controls, domain/resource blocking, and browser arguments:

```powershell
$Html = Use-PlaywrightPage -Stealth -Headless -BlockWebRTC -DisableResources `
  -Locale 'en-US' -TimezoneId 'Asia/Singapore' {
    param($Page)
    $null = Wait-PlaywrightTask ($Page.GotoAsync('https://example.com/'))
    Wait-PlaywrightTask ($Page.ContentAsync())
  }
```

For a detached response-like result, use the bounded navigation workflow:

```powershell
$Response = Invoke-PlaywrightFetch https://example.com/ -Stealth -Headless `
  -NetworkIdle -WaitSelector 'main' -MaximumRetryCount 3
$Response.Content
```

`Invoke-PlaywrightFetch` supports cookies, synchronous setup/action blocks, a
Google referer, retries, selector and load waits, compiled XHR capture,
screenshots, and best-effort Cloudflare challenge handling. Patchright's patched
Chromium driver supplies the anti-detection behavior. Dumplings does not claim
Scrapling's adaptive selector model, proxy rotation, ad-list bundle, canvas noise
flag, or multi-page pool.

Do not pass PowerShell scriptblocks to Playwright `RouteAsync`, event handlers, `ExposeBindingAsync`, or similar callback APIs. Playwright may invoke them without the originating PowerShell runspace, causing hangs. Dumplings uses compiled C# route callbacks and waits synchronously with `Wait-PlaywrightTask`.

## Directory Layout

```text
PackageModule/
+-- Index.ps1
+-- PackageModule.psd1
+-- PackageModule.psm1
+-- Assets/
|   +-- Assemblies/    # pinned managed dependencies
|   +-- Providers/     # source-available companion providers and licenses
|   +-- Schemas/       # offline WinGet schemas
|   `-- Source/        # auditable C# loaded with Add-Type
+-- Hooks/             # Core lifecycle integration
+-- Libraries/         # categorized PowerShell modules
+-- Models/            # task classes
+-- Tests/              # domain Pester suites plus non-discoverable Support helpers
`-- Utilities/          # standalone maintenance and validation scripts
```

See [`Assets/README.md`](Assets/README.md) before adding or moving runtime assets. Each owning module selects asset versions and load order. Do not discover assets recursively.

## Design And Security

- Prefer bounded streams and static structures over whole-file buffering and arbitrary text probing.
- Never infer manifest values from ambiguous version strings when explicit registry, MSI, package, or feed evidence exists.
- Preserve authored manifest intent. Update logic does not replace fields such as scope, dependencies, package name, publisher, protocols, or file extensions merely because a parser returned partial evidence.
- Keep installer-family semantics in focused modules and mechanical binary work in shared infrastructure.
- Do not add an external `7z`, extractor executable, or installer execution dependency to core parsing paths.
- Keep GPL parser code behind InstallerParsers' process boundary.

## Tests

Run all PackageModule tests from the Dumplings root:

```powershell
Invoke-Pester .\Modules\PackageModule\Tests
```

Run a focused suite while developing:

```powershell
Invoke-Pester .\Modules\PackageModule\Tests\WinGet\WinGetManifestValidation.Tests.ps1
Invoke-Pester .\Modules\PackageModule\Tests\Installers\ChromiumSetup.Tests.ps1
```

Run ScriptAnalyzer on modified PowerShell modules and use the repository's accepted exclusion rules where documented:

```powershell
Invoke-ScriptAnalyzer .\Modules\PackageModule\Libraries\WinGet\WinGetManifestValidation.psm1
```

Tests are grouped under `Infrastructure`, `Installers`, `Services`, `Tasks`, and `WinGet`. Shared setup and synthetic builders live under non-discoverable `Tests/Support`. Downloaded fixtures use `../Dumplings-TestFixtures/Installers`, curated media uses `Builders`, and synthetic or extracted output uses `$TestDrive`. Tests must not execute installers or depend on user `Downloads` and temporary folders.

## Third-Party Components

Pinned assemblies, vendored WinGet schemas, source-derived implementations, and companion providers are documented in [`Assets/THIRD-PARTY-NOTICES.md`](Assets/THIRD-PARTY-NOTICES.md). Preserve the corresponding source and license material when updating these assets.

## License

Dumplings.PackageModule is licensed under the [Apache License 2.0](LICENSE). See [NOTICE](NOTICE) for attribution.

The following components retain file-level licenses instead of Apache-2.0:

| Components | License and reason |
| --- | --- |
| `Libraries/Infrastructure/{Runtime,Binary,Archive,PE,InstallerEvidence}.psm1`, `Assets/Source/InstallerInfrastructure/{BinaryIO,PatternSearch,PEImageReader}.cs`, and `Tests/Support/{TestFixture,TestBootstrap}.ps1` | MIT; mirrored byte-for-byte into InstallerParsers and usable by its GPL-2.0 parser. |
| `Libraries/Installers/MSI.psm1` | MIT; imported by the GPL-2.0 Advanced Installer parser to inspect nested MSI databases. |
| `Assets/Source/CreateInstall/GenteeLzgeDecoder.cs` | MIT; adaptation of the Gentee decoder. |
| `Assets/Source/WinGet/WinGetDownloadProbe.cs` | MIT; independent implementation grounded in winget-cli's MIT source. |
| Pinned assemblies and `Assets/Providers/SharpCompress.Gentee` | Their own Apache-2.0, MS-RL, MIT, or LGPL licenses as documented. |

Embedded upstream notices in otherwise Apache-2.0 files remain in force for the portions they cover. See [`Assets/THIRD-PARTY-NOTICES.md`](Assets/THIRD-PARTY-NOTICES.md) for complete attribution and redistribution terms.
