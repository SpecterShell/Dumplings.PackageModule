# SPDX-License-Identifier: MIT

BeforeAll {
  $Script:RepositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
  $Script:SkillRoot = Join-Path $Script:RepositoryRoot '.agent\skills'
  $Script:AnalyzeSkillRoot = Join-Path $Script:SkillRoot 'analyze-winget-installer'
  $Script:AnalyzeReferenceRoot = Join-Path $Script:AnalyzeSkillRoot 'references'
  $Script:AuthorSkillRoot = Join-Path $Script:SkillRoot 'author-winget-manifest'
  $Script:AuthorReferenceRoot = Join-Path $Script:AuthorSkillRoot 'references'
}

Describe 'WinGet skill documentation' {
  It 'has no broken relative Markdown links across both skills' {
    $Failures = [Collections.Generic.List[string]]::new()
    $Files = @(
      Get-ChildItem -LiteralPath $Script:AnalyzeSkillRoot -Filter '*.md' -File -Recurse
      Get-ChildItem -LiteralPath $Script:AuthorSkillRoot -Filter '*.md' -File -Recurse
    )
    foreach ($File in $Files) {
      $Text = Get-Content -LiteralPath $File.FullName -Raw
      foreach ($Match in [regex]::Matches($Text, '\[[^\]]+\]\((?<Target>[^)]+)\)')) {
        $Target = $Match.Groups['Target'].Value.Trim('<', '>').Split('#')[0]
        if ([string]::IsNullOrWhiteSpace($Target) -or $Target -match '^(?i:https?|mailto):') { continue }
        $Resolved = [IO.Path]::GetFullPath((Join-Path $File.DirectoryName $Target))
        if (-not (Test-Path -LiteralPath $Resolved)) { $Failures.Add("$($File.FullName): $Target") }
      }
    }
    $Failures | Should -BeNullOrEmpty
  }

  It 'keeps focused workflows in canonical order' {
    $Order = @('When To Use', 'Detection', 'Manifest Shape', 'WinGet Defaults And Overrides', 'Step-By-Step Analysis', 'VM Validation', 'Implementation Sources')
    foreach ($File in Get-ChildItem -LiteralPath $Script:AnalyzeReferenceRoot -Filter 'installer-type-*.md' -File) {
      $Headings = @(Get-Content -LiteralPath $File.FullName | Where-Object { $_ -match '^##\s+' } | ForEach-Object {
          $Heading = $_ -replace '^##\s+', ''
          if ($Heading -like 'Manifest Shape*') { 'Manifest Shape' } else { $Heading }
        })
      foreach ($Required in @('When To Use', 'Detection', 'Manifest Shape', 'WinGet Defaults And Overrides', 'Step-By-Step Analysis', 'VM Validation')) {
        $Headings | Should -Contain $Required -Because "$($File.Name) should expose the focused workflow"
      }
      $Indexes = @($Headings | Where-Object { $_ -in $Order } | ForEach-Object { [Array]::IndexOf($Order, $_) })
      for ($Index = 1; $Index -lt $Indexes.Count; $Index++) {
        $Indexes[$Index] | Should -BeGreaterOrEqual $Indexes[$Index - 1] -Because "$($File.Name) should follow the focused workflow order"
      }
    }
  }

  It 'contains exactly one installer-family route table' {
    $AllText = (Get-ChildItem -LiteralPath $Script:AnalyzeReferenceRoot -Filter '*.md' -File | Get-Content -Raw) -join "`n"
    [regex]::Matches($AllText, '(?m)^\| Analyzer family or decisive evidence \| Focused workflow \|$').Count | Should -Be 1
  }

  It 'routes every focused installer workflow to canonical VM validation once' {
    foreach ($File in Get-ChildItem -LiteralPath $Script:AnalyzeReferenceRoot -Filter 'installer-type-*.md' -File) {
      $Text = Get-Content -LiteralPath $File.FullName -Raw
      [regex]::Matches($Text, 'vm-validation-workflow\.md').Count | Should -Be 1 -Because "$($File.Name) should have one VM route"
      [regex]::Matches($Text, '(?m)^## VM Validation\r?$').Count | Should -Be 1
    }
  }

  It 'contains no removed workflow names or central parser API catalog' {
    $AllText = (Get-ChildItem -LiteralPath $Script:SkillRoot -Filter '*.md' -File -Recurse | Get-Content -Raw) -join "`n"
    $AllText | Should -Not -Match 'reference-map\.md|installer-detection\.md|installer-type-routing\.md|parser-api-reference\.md|parser-architecture\.md|parser-benchmarks\.md|manifest-field-levels\.md|wrapper-installers\.md|installer-associations\.md|winget-arp-matching\.md|vm-validation\.md|source-discovery\.md|download-validation\.md|manifest-fields\.md|locale-manifest\.md|validation-and-pr\.md|dumplings-electron-builder-automation\.md'
    Test-Path -LiteralPath (Join-Path $Script:AnalyzeReferenceRoot 'parser-api-reference.md') | Should -BeFalse
  }

  It 'documents the PowerShell Core Hyper-V compatibility import exactly' {
    $Text = Get-Content -LiteralPath (Join-Path $Script:AnalyzeReferenceRoot 'vm-validation-workflow.md') -Raw
    $Text | Should -Match ([regex]::Escape("`$env:PSModulePath += ';C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules'"))
    $Text | Should -Match ([regex]::Escape('Import-Module Hyper-V -UseWindowsPowerShell -PassThru'))
  }

  It 'documents verbatim desktop release-note selection and conversion' {
    $LocaleText = Get-Content -LiteralPath (Join-Path $Script:AuthorReferenceRoot 'locale-workflow.md') -Raw
    $DiscoveryText = Get-Content -LiteralPath (Join-Path $Script:AuthorReferenceRoot 'package-discovery-workflow.md') -Raw

    $LocaleText | Should -Match ([regex]::Escape('ConvertFrom-Html | Get-TextContent | Format-Text'))
    $LocaleText | Should -Match ([regex]::Escape("Convert-MarkdownToHtml -Extensions 'advanced', 'emojis', 'hardlinebreak'"))
    $LocaleText | Should -Match 'Do not summarize, paraphrase, or rewrite it'
    $DiscoveryText | Should -Match 'CHANGELOG\.md.*RELEASES\.md.*CHANGES\.md'
    $DiscoveryText | Should -Match 'Windows desktop application'
  }

  It 'documents valid winget-pkgs PR shapes and leaf version paths' {
    $Text = Get-Content -LiteralPath (Join-Path $Script:AuthorReferenceRoot 'submission-workflow.md') -Raw
    $Text | Should -Match 'Add the manifests for one version of one package'
    $Text | Should -Match 'Remove the manifests for one version of one package'
    $Text | Should -Match 'Modify the manifests for one existing version of one package'
    $Text | Should -Match 'Add one version and remove one version of the same package'
    $Text | Should -Match ([regex]::Escape('manifests\g\Google\Chrome\150.0.7871.115\'))
    $Text | Should -Match 'microsoft/winget-pkgs/issues/325593'
    $Text | Should -Match 'Get-WinGetPRValidationLog\.ps1'
  }

  It 'references no removed shared helper implementation names' {
    $AllDocumentation = (Get-ChildItem -LiteralPath $Script:AnalyzeReferenceRoot -Filter '*.md' -File | Get-Content -Raw) -join "`n"
    $AllDocumentation | Should -Not -Match 'BinaryPatternSearch\.cs|Dumplings\.Binary\.PatternSearch'
  }
}
