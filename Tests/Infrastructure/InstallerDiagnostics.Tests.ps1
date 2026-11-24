. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')
. (Join-Path $PSScriptRoot '..\Support\InstallerInfrastructureTestSetup.ps1')

Describe 'Installer diagnostics' {
  It 'creates context-neutral diagnostics' {
    $Diagnostic = New-InstallerDiagnostic -Id 'Test.MetadataMissing' -Source Test -Message 'Metadata is incomplete.' -Kind Incomplete -Areas Metadata -AffectedFields ProductCode

    $Diagnostic.Id | Should -Be 'Test.MetadataMissing'
    $Diagnostic.Level | Should -BeNullOrEmpty
    $Diagnostic.Scenario | Should -BeNullOrEmpty
    $Diagnostic.IsBlocking | Should -BeNullOrEmpty
    $Diagnostic.AffectedFields | Should -Be @('ProductCode')
  }

  It 'generates deterministic identifiers for migrated messages' {
    $First = @(ConvertTo-InstallerDiagnostic -InputObject 'The payload is incomplete.' -Source Test -Kind Incomplete -Areas Extraction)
    $Second = @(ConvertTo-InstallerDiagnostic -InputObject 'The payload is incomplete.' -Source Test -Kind Incomplete -Areas Extraction)

    $First[0].Id | Should -Be $Second[0].Id
  }

  It 'ignores absent optional diagnostic collections' {
    @(ConvertTo-InstallerDiagnostic -InputObject $null -Source Test -Kind Incomplete -Areas Metadata) | Should -BeNullOrEmpty
  }

  It 'resolves the scenario policy' -ForEach @(
    @{ Scenario = 'FullAnalysis'; Kind = 'Information'; Areas = 'Metadata'; Field = @(); Expected = 'Info'; Blocking = $false }
    @{ Scenario = 'FullAnalysis'; Kind = 'Incomplete'; Areas = 'Metadata'; Field = @(); Expected = 'Warning'; Blocking = $false }
    @{ Scenario = 'FullAnalysis'; Kind = 'Invalid'; Areas = 'Detection'; Field = @(); Expected = 'Error'; Blocking = $true }
    @{ Scenario = 'Detection'; Kind = 'Incomplete'; Areas = 'Detection'; Field = @(); Expected = 'Verbose'; Blocking = $false }
    @{ Scenario = 'ManifestAuthoring'; Kind = 'Unsupported'; Areas = 'Installability'; Field = @(); Expected = 'Error'; Blocking = $true }
    @{ Scenario = 'ManifestUpdate'; Kind = 'Incomplete'; Areas = 'Metadata'; Field = @(); Expected = 'Verbose'; Blocking = $false }
    @{ Scenario = 'ManifestUpdate'; Kind = 'Incomplete'; Areas = 'Metadata'; Field = @('ProductCode'); Expected = 'Warning'; Blocking = $false }
    @{ Scenario = 'ManifestUpdate'; Kind = 'Risk'; Areas = 'Security'; Field = @(); Expected = 'Warning'; Blocking = $false }
    @{ Scenario = 'Extraction'; Kind = 'Unsupported'; Areas = 'Extraction'; Field = @(); Expected = 'Warning'; Blocking = $false }
  ) {
    $Diagnostic = New-InstallerDiagnostic -Id "Test.$Scenario.$Kind.$Areas" -Source Test -Message 'Scenario test.' -Kind $Kind -Areas $Areas -AffectedFields ProductCode
    $Result = Resolve-InstallerDiagnostic -Diagnostic $Diagnostic -Scenario $Scenario -AffectedField $Field

    $Result.Level | Should -Be $Expected
    $Result.IsBlocking | Should -Be $Blocking
  }

  It 'promotes confirmed detection failures' {
    $Diagnostic = New-InstallerDiagnostic -Id Test.DetectionFailed -Source Test -Message 'Detection failed.' -Kind Incomplete -Areas Detection
    (Resolve-InstallerDiagnostic -Diagnostic $Diagnostic -Scenario Detection).Level | Should -Be 'Verbose'
    (Resolve-InstallerDiagnostic -Diagnostic $Diagnostic -Scenario Detection -ConfirmedFamily).Level | Should -Be 'Warning'
  }

  It 'blocks conflicting confirmed families during detection' {
    $Diagnostic = New-InstallerDiagnostic -Id Test.FamilyConflict -Source Test -Message 'Two structurally confirmed families conflict.' -Kind Mismatch -Areas Detection
    $Result = Resolve-InstallerDiagnostic -Diagnostic $Diagnostic -Scenario Detection -ConfirmedFamily

    $Result.Level | Should -Be 'Error'
    $Result.IsBlocking | Should -BeTrue
  }

  It 'keeps every supported kind and area resolvable in every scenario' {
    $Kinds = @('Information', 'Fallback', 'Incomplete', 'Ambiguous', 'Unsupported', 'Mismatch', 'ManualValidation', 'Risk', 'Invalid')
    $Areas = @('Detection', 'Metadata', 'Extraction', 'Installability', 'Security')
    $Scenarios = @('FullAnalysis', 'Detection', 'ManifestAuthoring', 'ManifestUpdate', 'Extraction')

    foreach ($Kind in $Kinds) {
      foreach ($Area in $Areas) {
        $Diagnostic = New-InstallerDiagnostic -Id "Test.Matrix.$Kind.$Area" -Source Test -Message 'Policy matrix evidence.' -Kind $Kind -Areas $Area -AffectedFields ProductCode
        foreach ($Scenario in $Scenarios) {
          $Result = Resolve-InstallerDiagnostic -Diagnostic $Diagnostic -Scenario $Scenario -AffectedField ProductCode -ConfirmedFamily
          $Result.Level | Should -BeIn @('Verbose', 'Info', 'Warning', 'Error')
          $Result.Scenario | Should -Be $Scenario
          $Result.IsBlocking | Should -BeOfType [bool]
        }
      }
    }
  }

  It 'deduplicates diagnostics and retains the highest resolved level' {
    $Diagnostic = New-InstallerDiagnostic -Id Test.Duplicate -Source Test -Message 'Repeated evidence.' -Kind Incomplete -Areas Metadata -AffectedFields ProductCode
    $Verbose = Resolve-InstallerDiagnostic -Diagnostic $Diagnostic -Scenario ManifestUpdate
    $Warning = Resolve-InstallerDiagnostic -Diagnostic $Diagnostic -Scenario ManifestUpdate -AffectedField ProductCode

    $Merged = @(Merge-InstallerDiagnostics -Diagnostic @($Verbose, $Warning))
    $Merged | Should -HaveCount 1
    $Merged[0].Level | Should -Be 'Warning'
  }

  It 'matches nested affected fields during partial manifest updates' {
    $Diagnostic = New-InstallerDiagnostic -Id Test.NestedField -Source Test -Message 'Nested field evidence.' -Kind Incomplete -Areas Metadata -AffectedFields AppsAndFeaturesEntries.ProductCode

    (Resolve-InstallerDiagnostic -Diagnostic $Diagnostic -Scenario ManifestUpdate).Level | Should -Be 'Verbose'
    (Resolve-InstallerDiagnostic -Diagnostic $Diagnostic -Scenario ManifestUpdate -AffectedField AppsAndFeaturesEntries).Level | Should -Be 'Warning'
  }

  It 'preserves structured evidence through resolution and merging' {
    $Evidence = [ordered]@{ Offset = 128L; Nested = [ordered]@{ Name = 'payload.msi' } }
    $Diagnostic = New-InstallerDiagnostic -Id Test.Evidence -Source Test -Message 'Structured evidence.' -Kind Incomplete -Areas Extraction -Evidence $Evidence

    $Resolved = Resolve-InstallerDiagnostics -Diagnostic @($Diagnostic, $Diagnostic) -Scenario Extraction
    $Resolved | Should -HaveCount 1
    $Resolved[0].Evidence.Offset | Should -Be 128
    $Resolved[0].Evidence.Nested.Name | Should -Be 'payload.msi'

    $DifferentEvidence = New-InstallerDiagnostic -Id Test.Evidence -Source Test -Message 'Structured evidence.' -Kind Incomplete -Areas Extraction -Evidence ([ordered]@{ Offset = 256L })
    @(Merge-InstallerDiagnostics -Diagnostic @($Diagnostic, $DifferentEvidence)) | Should -HaveCount 2
  }

  It 'rejects malformed diagnostics deterministically' {
    { Merge-InstallerDiagnostics -Diagnostic @([pscustomobject]@{ Message = 'Missing identifier.' }) } | Should -Throw '*non-empty Id and Message*'
    $Diagnostic = [pscustomobject]@{ Id = 'Test.BadKind'; Source = 'Test'; Message = 'Bad kind.'; Kind = 'Unknown'; Areas = @('Metadata'); AffectedFields = @(); Evidence = $null }
    { Resolve-InstallerDiagnostic -Diagnostic $Diagnostic -Scenario FullAnalysis } | Should -Throw "*Unsupported installer diagnostic kind 'Unknown'*"
    $InvalidId = [pscustomobject]@{ Id = 'Bad identifier'; Source = 'Test'; Message = 'Bad identifier.'; Kind = 'Incomplete'; Areas = @('Metadata'); AffectedFields = @(); Evidence = $null }
    { Resolve-InstallerDiagnostic -Diagnostic $InvalidId -Scenario FullAnalysis } | Should -Throw '*valid Id*'
    $InvalidArea = [pscustomobject]@{ Id = 'Test.BadArea'; Source = 'Test'; Message = 'Bad area.'; Kind = 'Incomplete'; Areas = @('Unknown'); AffectedFields = @(); Evidence = $null }
    { Resolve-InstallerDiagnostic -Diagnostic $InvalidArea -Scenario FullAnalysis } | Should -Throw '*unsupported or empty Areas*'
  }

  It 'writes through the supplied logger and returns resolved diagnostics' {
    $Messages = [Collections.Generic.List[object]]::new()
    $Logger = { param($Message, $Level) $Messages.Add([pscustomobject]@{ Message = $Message; Level = $Level }) }
    $Diagnostic = New-InstallerDiagnostic -Id Test.Render -Source Test -Message 'Rendered evidence.' -Kind Incomplete -Areas Metadata -AffectedFields ProductCode

    $Result = @(Write-InstallerDiagnostics -Diagnostic $Diagnostic -Scenario ManifestUpdate -AffectedField ProductCode -Logger $Logger -PassThru)
    $Result | Should -HaveCount 1
    $Messages | Should -HaveCount 1
    $Messages[0].Level | Should -Be 'Warning'
    $Messages[0].Message | Should -Match '\[Test.Render\]'
  }


  It 'does not expose legacy parser diagnostic collection properties' {
    $ModuleRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
    $Files = @(
      Get-ChildItem -LiteralPath (Join-Path $ModuleRoot 'Libraries\Installers') -Filter '*.psm1' -File -Recurse
      Get-Item -LiteralPath (Join-Path $ModuleRoot 'Libraries\Infrastructure\InstallerAnalyzer.psm1')
      Get-Item -LiteralPath (Join-Path $ModuleRoot 'Libraries\WinGet\WinGetManifestAuthoring.psm1')
    )
    $LegacyPropertyPattern = '(?m)^\s*["'']?(?:Warnings|Notices|WrapperWarnings|AppsAndFeaturesNotices|BlockingIssues)["'']?\s*='

    foreach ($File in $Files) {
      [IO.File]::ReadAllText($File.FullName) | Should -Not -Match $LegacyPropertyPattern -Because "$($File.FullName) must expose Diagnostics instead"
    }
  }
}
