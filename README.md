# Dumplings.PackageModule

Dumplings.PackageModule is the Apache-2.0-licensed package automation and WinGet toolkit used by [Dumplings](https://github.com/SpecterShell/Dumplings). It supplies task models, release and download helpers, static installer analysis, manifest modeling and validation, notification transports, and guarded submission workflows.

The module is designed for PowerShell 7.4 or later on Windows.

## Loading

Core loads PackageModule through `Index.ps1` in every task worker. Standalone callers should import the module manifest:

```powershell
Import-Module .\Modules\PackageModule\PackageModule.psd1 -Force
```

`PackageModule.psd1` is the supported entry point. `PackageModule.psm1` imports focused implementation modules in explicit dependency order; each command retains its implementation-module owner so PowerShell exposes one command with its native help and completion metadata. `Index.ps1` imports that manifest globally, then loads the task model classes for Core.

Libraries are grouped by responsibility:

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

Use the [`author-dumplings-task` skill](../../.agents/skills/author-dumplings-task/SKILL.md)
for the supported task layout, state contract, source patterns, provider tasks,
and dry-run workflow.

Use the [`use-dumplings-functions` skill](../../.agents/skills/use-dumplings-functions/SKILL.md) for the curated networking, temporary-file, archive, content, feed, browser, HTML, and YAML helper contracts used by tasks and standalone analysis.

Package submissions are claimed by effective WinGet identifier in process-wide shared storage. The first task owns the claim for the run; duplicate tasks skip submission rather than racing the same package.

### Installer Analysis

`Get-InstallerAnalysis` detects file and installer families from structured content and magic bytes without applying package-provider policy. `Get-WinGetInstallerAnalysis` projects the same evidence into WinGet installer types, architecture recommendations, defaults, and snippets. `DetectedFamilies` contains only structurally confirmed or successfully parsed families; `RoutingHints` and `RejectedCandidates` retain heuristic diagnostics without promoting them to detections. `FamilyCandidates` remains a confirmed-only compatibility projection.

Some implementations are maintained in the separately licensed InstallerParsers submodule. [`InstallerBridge.psm1`](Libraries/Infrastructure/InstallerBridge.psm1) invokes its JSON CLI in a child PowerShell process and returns deserialized evidence. It does not import GPL parser code into PackageModule's process module scope.

Each aggregate parser constructs the canonical identity/ARP envelope directly and returns context-neutral `Diagnostics` plus `UnresolvedFields`; parsers do not write log messages directly. A diagnostic records its stable `Id`, `Source`, `Message`, `Kind`, affected areas and fields, and optional evidence. `FullAnalysis`, `Detection`, `ManifestAuthoring`, `ManifestUpdate`, and `Extraction` resolve that evidence to a log level and blocking decision only when it enters a workflow. This keeps family-specific ARP decisions in the parser that understands the format and prevents a partial manifest update from promoting unrelated parser limitations.

The Apache-2.0 MicaSetup parser reads official v1/v2 CLR Pack/Option initializers and WPF `publish.7z` resources without loading the managed installer assembly. `Get-MicaSetupInfo` returns compiled metadata, scope and ARP evidence, payload architecture and dependencies, system effects, and unresolved custom-code diagnostics; `Expand-MicaSetupInstaller` streams selected payload or raw resource entries through the shared bounded archive infrastructure.

The independently implemented Apache-2.0 Kachina parser reads legacy and indexed PE-overlay TLV streams, validates compact indexes, and streams Zstandard payload records. `Get-KachinaInfo` returns configuration, ARP and scope routes, installed-file architecture and dependencies, patches, and configured or appended runtimes. `Expand-KachinaInstaller` extracts installed files or raw physical records and reconstructs the configured updater and uninstaller without executing them.

Public installer expansion functions resolve source and destination paths against PowerShell's filesystem location before passing them to .NET or a parser child process. Their optional `Name` selector defaults to `*`, so omitting it expands every catalogued payload within the parser's entry and byte limits. Extractors that can produce multiple files accept `CollisionAction Prompt|Error|Skip|Overwrite|Rename`; `Prompt` is the interactive default and offers `Rename` as its preselected choice. Functions and unattended automation that compose extractors pass `Rename` explicitly, allocating deterministic names such as `payload (1).dll` without opening a prompt.

Manifest updates run a known manifest-declared parser before generic detection. If metadata parsing fails, structural evidence classifies the result as matched, mismatched, or indeterminate. Only a definitive incompatible format produces a blocking diagnostic and throws. Matched or indeterminate failures preserve existing fields, and diagnostics unrelated to fields being refreshed stay verbose. The update buffers diagnostics from all installer entries, deduplicates them, and writes them once after processing the manifest.

Submission can bypass this parser stage globally with `-SkipInstallerAnalysis` or per task with `SkipInstallerAnalysis: true` in `Config.yaml`. The bypass preserves existing installer metadata and skips nested payload extraction, family detection, and static parsers; downloads required for SHA-256, release-date handling, manifest formatting, validation, and repository submission still run normally.

Use the [`analyze-winget-installer` skill](../../.agents/skills/analyze-winget-installer/SKILL.md) for the supported workflow, parser routing, manifest interpretation, and VM-only validation rules.

### WinGet Manifests

Manifest processing is separated into explicit layers:

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

The logical model stores authored values, not WinGet-generated default switches or return codes. Complete-manifest serialization first removes a common `InstallerLocale` and redundant ProductCode, InstallerType, name, and publisher fields from a sole Apps & Features entry, then compacts values shared by every installer back to manifest level while preserving installer-level overrides, recursive dictionary atoms, and atomic arrays. The isolated `Format-WinGetManifest` path remains non-destructive because it has no locale-document context.

`Utilities\WinGetManifest.ps1` exposes `new`, installer/locale/value add-set-remove operations, `validate`, and `show` for standalone workflows. Mutating commands stage and validate a complete multi-file set before replacing the target directory; they do not submit packages or execute installers.

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

Use the scoped API so task completion and runner timeouts always release the
process-wide browser lease:

```powershell
$Html = Use-PlaywrightPage -Headless {
  param($Page, $Context, $Browser, $Session)

  $null = Wait-PlaywrightTask ($Page.GotoAsync('https://example.com/'))
  Wait-PlaywrightTask ($Page.ContentAsync())
}
```

The default Chromium channel is installed `msedge`, while `-Stealth` uses the
Apache-2.0 [Patchright](https://github.com/Kaliiiiiiiiii-Vinyzu/patchright)
driver and defaults to installed `chrome`. Patchright is restored from
[patchright-dotnet](https://github.com/DevEnterpriseSoftware/patchright-dotnet)
and supports Chromium only. `Install-PlaywrightBrowser -Browser Chromium`
explicitly installs its bundled browser when an installed channel is unsuitable.
Media and YouTube requests are blocked by default; pass `-BlockUrlPattern @()`
to disable that filter.

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

Do not pass PowerShell scriptblocks to Playwright `RouteAsync`, event handlers,
`ExposeBindingAsync`, or similar callback APIs. Playwright invokes them
asynchronously, potentially without the originating PowerShell runspace. Dumplings
keeps route callbacks in compiled C# and uses `Wait-PlaywrightTask` at the
synchronous PowerShell boundary to avoid callback hangs.

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

See [`Assets/README.md`](Assets/README.md) before adding or moving runtime assets. Do not load assets through recursive discovery; their owning module determines version and load order.

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

Tests are grouped under `Infrastructure`, `Installers`, `Services`, `Tasks`, and `WinGet`; shared setup and synthetic builders live under non-discoverable `Tests/Support`. Downloaded fixtures use canonical paths below `../Dumplings-TestFixtures/Installers`, curated media uses `Builders`, and synthetic or extracted output uses `$TestDrive`. Tests must not execute installers or depend on user `Downloads` and temporary folders.

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
