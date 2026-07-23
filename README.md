# Dumplings.PackageModule

Dumplings.PackageModule is the Apache-2.0-licensed package automation and WinGet toolkit used by [Dumplings](https://github.com/SpecterShell/Dumplings). It supplies task models, release and download helpers, static installer analysis, manifest modeling and validation, notification transports, and guarded submission workflows.

The module is designed for PowerShell 7.4 or later on Windows.

## Loading

Core loads PackageModule automatically by dot-sourcing `Index.ps1` in every task worker. For standalone analysis from the Dumplings root:

```powershell
. .\Modules\PackageModule\Index.ps1
```

`Index.ps1` loads components in deterministic dependency order:

1. Version comparison types.
2. Runtime, binary, compression, archive, PE, and registry infrastructure.
3. General text and messaging helpers.
4. YAML schema and WinGet manifest model/serialization foundations.
5. Installer-family and service libraries.
6. Manifest validation, update, and submission consumers.
7. Task model classes.

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

Package submissions are claimed by effective WinGet identifier in process-wide shared storage. The first task owns the claim for the run; duplicate tasks skip submission rather than racing the same package.

### Installer Analysis

`Get-WinGetInstallerAnalysis` detects file and installer families from structured content and magic bytes, then routes to supported static parsers. Its `DetectedFamilies` output contains only structurally confirmed or successfully parsed families; `RoutingHints` and `RejectedCandidates` retain heuristic diagnostics without promoting them to detections. `FamilyCandidates` remains a confirmed-only compatibility projection. PackageModule includes in-process implementations for PE, MSI/WiX, MSIX/AppX, Burn, InstallShield, Chromium Setup, Zero Install, Squirrel/Velopack, install4j, InstallAnywhere, InstallBuilder, CreateInstall, wrapper formats, portable applications, and other installer families. Their default and file-level licenses are described below.

Some implementations are maintained in the separately licensed InstallerParsers submodule. [`InstallerBridge.psm1`](Libraries/InstallerBridge.psm1) invokes its JSON CLI in a child PowerShell process and returns deserialized evidence. It does not import GPL parser code into PackageModule's process module scope.

Each aggregate parser constructs the canonical identity/ARP envelope directly and returns diagnostics through `Warnings` and `UnresolvedFields`; parsers do not write log messages directly. This keeps family-specific ARP decisions in the parser that understands the format instead of deriving them from a shared normalizer. Family-specific layout, payload, association, scope, and architecture evidence remains additive.

Manifest updates run a known manifest-declared parser before generic detection. If metadata parsing fails, structural evidence classifies the result as matched, mismatched, or indeterminate. Only a definitive incompatible format throws; matched or indeterminate failures preserve existing fields and emit warnings, while resolved fields from a partial successful result are applied independently.

Use the [`analyze-winget-installer` skill](../../.agents/skills/analyze-winget-installer/SKILL.md) for the supported workflow, parser routing, manifest interpretation, and VM-only validation rules.

### WinGet Manifests

Manifest processing is separated into explicit layers:

| Module | Responsibility |
| --- | --- |
| `YamlSchema.psm1` | Offline structured JSON-schema validation for YAML objects. |
| `WinGetManifestSchema.psm1` | WinGet schema selection, field ordering, and vendored schema access. |
| `WinGetManifestModel.psm1` | Logical manifest model, installer inheritance, compaction, and merged projections. |
| `WinGetManifestSerialization.psm1` | Multi-file parsing, formatting, document sets, headers, and YAML output. |
| `WinGetManifestValidation.psm1` | Structural, schema, and semantic validation compatible with WinGet's local validation path. |
| `WinGetManifestUpdate.psm1` | Installer download, matching, parser metadata, and safe updates to existing authored fields. |
| `WinGetSubmission.psm1` | Repository acquisition, manifest generation, validation, duplicate-PR policy, and submission. |
| `SourceIdentity.psm1` | Forge- and storage-aware installer source identity normalization used by task state comparison to detect domain changes. |

Primary entry points include:

```powershell
# Read a singleton or multi-file manifest set into one logical model.
$Manifest = Read-WinGetManifest -Path C:\Manifests\Vendor.Package\1.2.3

# Validate a path or an in-memory logical model.
$Result = Get-WinGetManifestValidationResult -Manifest $Manifest

# Format one authored document without adding or deleting fields.
$Formatted = Format-WinGetManifest -Manifest $InstallerDocument

# Analyze an installer without executing it.
$Analysis = Get-WinGetInstallerAnalysis -Path C:\Installers\setup.exe
```

The logical model stores authored values, not WinGet-generated default switches or return codes. Serialization compacts values shared by every installer back to manifest level while preserving installer-level overrides, recursive dictionary atoms, and atomic arrays.

### Supporting Services

- `WinGetDownload.psm1` reproduces WinGet-style Delivery Optimization and WinINet downloads, redirects, and headers with bounded retries and rate-limit handling.
- `WebDriver.psm1` provides leased Edge/Firefox sessions shared across concurrent tasks.
- `Playwright.psm1` provides a separately leased Patchright/Playwright page and browser context. It uses installed Edge for ordinary sessions and installed Chrome for stealth sessions, restores the pinned Patchright driver runtime, and synchronously unwraps tasks without registering PowerShell as an asynchronous callback.
- `MessageQueue.psm1`, `Telegram.psm1`, and `Matrix.psm1` provide per-target queues, coalescing, splitting, rate limiting, and session updates.
- `WinGetARP.psm1` collects and matches Apps & Features evidence, including MSI ownership scope evidence.
- `TextContent.psm1` and `Format.psm1` normalize release-note HTML, Markdown, tables, Unicode whitespace, and validator-blocked control characters.
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
+-- Assets/
|   +-- Assemblies/    # pinned managed dependencies
|   +-- Providers/     # source-available companion providers and licenses
|   +-- Schemas/       # offline WinGet schemas
|   `-- Source/        # auditable C# loaded with Add-Type
+-- Hooks/             # Core lifecycle integration
+-- Libraries/         # PowerShell modules
+-- Models/            # task classes
+-- Tests/              # Pester suites
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
Invoke-Pester .\Modules\PackageModule\Tests\WinGetManifestValidation.Tests.ps1
Invoke-Pester .\Modules\PackageModule\Tests\ChromiumSetup.Tests.ps1
```

Run ScriptAnalyzer on modified PowerShell modules and use the repository's accepted exclusion rules where documented:

```powershell
Invoke-ScriptAnalyzer .\Modules\PackageModule\Libraries\WinGetManifestValidation.psm1
```

Tests use generated fixtures or the shared persistent installer fixture cache. They must not execute installers or depend on user `Downloads` and temporary folders.

## Third-Party Components

Pinned assemblies, vendored WinGet schemas, source-derived implementations, and companion providers are documented in [`Assets/THIRD-PARTY-NOTICES.md`](Assets/THIRD-PARTY-NOTICES.md). Preserve the corresponding source and license material when updating these assets.

## License

Dumplings.PackageModule is licensed under the [Apache License 2.0](LICENSE). See [NOTICE](NOTICE) for attribution.

The following components retain file-level licenses instead of Apache-2.0:

| Components | License and reason |
| --- | --- |
| `Libraries/{Runtime,Binary,Compression,Archive,PE,RegistryAssociations}.psm1`, `Assets/Source/InstallerInfrastructure/{BinaryIO,PatternSearch,PEImageReader}.cs`, and `Tests/TestFixture.ps1` | MIT; mirrored byte-for-byte into InstallerParsers and usable by its GPL-2.0 parser. |
| `Libraries/MSI.psm1` | MIT; imported by the GPL-2.0 Advanced Installer parser to inspect nested MSI databases. |
| `Assets/Source/CreateInstall/GenteeLzgeDecoder.cs` | MIT; adaptation of the Gentee decoder. |
| `Assets/Source/WinGet/WinGetDownloadProbe.cs` | MIT; independent implementation grounded in winget-cli's MIT source. |
| Pinned assemblies and `Assets/Providers/SharpCompress.Gentee` | Their own Apache-2.0, MS-RL, MIT, or LGPL licenses as documented. |

Embedded upstream notices in otherwise Apache-2.0 files remain in force for the portions they cover. See [`Assets/THIRD-PARTY-NOTICES.md`](Assets/THIRD-PARTY-NOTICES.md) for complete attribution and redistribution terms.
