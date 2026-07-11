# SPDX-License-Identifier: MIT
# Import-analysis reference: https://github.com/lucasg/Dependencies
# PE import-to-runtime mapping used by portable manifest analysis.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

function Resolve-PortableVCRedistRuntime {
  <#
  .SYNOPSIS
    Map an imported DLL to a Visual C++ runtime generation
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][string]$DllName)
  $Name = [IO.Path]::GetFileName($DllName).ToLowerInvariant()
  switch -Regex ($Name) {
    '^(msvcr80|msvcp80|atl80|mfc80.*|mfcm80.*)\.dll$' { '2005'; break }
    '^(msvcr90|msvcp90|atl90|mfc90.*|mfcm90.*)\.dll$' { '2008'; break }
    '^(msvcr100|msvcp100|mfc100.*|mfcm100.*|vcomp100)\.dll$' { '2010'; break }
    '^(msvcr110|msvcp110|mfc110.*|mfcm110.*|vcomp110)\.dll$' { '2012'; break }
    '^(msvcr120|msvcp120|mfc120.*|mfcm120.*|vcomp120)\.dll$' { '2013'; break }
    '^(vcruntime140.*|msvcp140.*|concrt140|mfc140.*|mfcm140.*|vcomp140|vccorlib140.*)\.dll$' { '2015+'; break }
    default { $null }
  }
}

function Test-PortableUcrtImport {
  <#
  .SYNOPSIS
    Test whether an imported DLL belongs to the Universal C Runtime
  #>
  [OutputType([bool])]
  param ([Parameter(Mandatory)][string]$DllName)
  $Name = [IO.Path]::GetFileName($DllName).ToLowerInvariant()
  return $Name -eq 'ucrtbase.dll' -or $Name -like 'api-ms-win-crt-*.dll'
}

function Get-PortableVCRedistPackageIdentifier {
  <#
  .SYNOPSIS
    Build a concrete WinGet VCRedist package identifier
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][ValidateSet('2005', '2008', '2010', '2012', '2013', '2015+')][string]$RuntimeVersion,
    [Parameter(Mandatory)][ValidateSet('x86', 'x64', 'arm64')][string]$Architecture
  )
  if ($Architecture -eq 'arm64' -and $RuntimeVersion -ne '2015+') { return $null }
  return "Microsoft.VCRedist.$RuntimeVersion.$Architecture"
}

Export-ModuleMember -Function Resolve-PortableVCRedistRuntime, Test-PortableUcrtImport, Get-PortableVCRedistPackageIdentifier
