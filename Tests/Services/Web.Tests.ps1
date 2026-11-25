. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

# SPDX-License-Identifier: Apache-2.0

BeforeAll {
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Networking\Web.psm1') -Force
}

Describe 'Get-EmbeddedLinks array contract' -Tag Unit {
  BeforeEach {
    Set-StrictMode -Version 3
  }

  It 'returns a single link as an array supporting Count, Where and indexing' {
    $Links = '<a href="/setup.exe" class="download">Download</a>' | Get-EmbeddedLinks

    ($Links -is [pscustomobject[]]) | Should -BeTrue
    $Links.Count | Should -Be 1
    $Links[0].href | Should -BeExactly '/setup.exe'
    $Links[0].class | Should -BeExactly 'download'
    $Links.Where({ $_.href.EndsWith('.exe') }, 'First')[0].href | Should -BeExactly '/setup.exe'
  }

  It 'returns an empty array when content contains no links' {
    $Links = '<p>No downloads</p>' | Get-EmbeddedLinks

    ($Links -is [pscustomobject[]]) | Should -BeTrue
    $Links.Count | Should -Be 0
    $Links.Where({ $_.href.EndsWith('.exe') }).Count | Should -Be 0
  }

  It 'collects links from every pipeline input in order without nesting arrays' {
    $Links = @(
      '<a href="/first.exe">First</a><a href="/second.zip">Second</a>'
      '<p>No links</p>'
      '<a href="/third.exe">Third</a>'
    ) | Get-EmbeddedLinks

    ($Links -is [pscustomobject[]]) | Should -BeTrue
    $Links.Count | Should -Be 3
    $Links[0].href | Should -BeExactly '/first.exe'
    $Links[1].href | Should -BeExactly '/second.zip'
    $Links[2].href | Should -BeExactly '/third.exe'
    $Selected = $Links | Where-Object { $_.href.EndsWith('.exe') } | Select-Object -ExpandProperty href
    $Selected.Count | Should -Be 2
    $Selected[1] | Should -BeExactly '/third.exe'
  }

  It 'returns an empty array for an empty input pipeline' {
    $Links = @() | Get-EmbeddedLinks

    ($Links -is [pscustomobject[]]) | Should -BeTrue
    $Links.Count | Should -Be 0
  }
}
