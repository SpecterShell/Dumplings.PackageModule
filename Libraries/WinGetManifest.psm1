# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }
# Force stop on error
$ErrorActionPreference = 'Stop'
# Force stop on undefined variables or properties
Set-StrictMode -Version 3

$ManifestHeader = '# Created with YamlCreate.ps1 Dumplings Mod'

$Culture = 'en-US'
$WinGetUserAgent = 'Microsoft-Delivery-Optimization/10.0'
$WinGetBackupUserAgent = 'winget-cli WindowsPackageManager/1.7.10661 DesktopAppInstaller/Microsoft.DesktopAppInstaller v1.22.10661.0'
$WinGetTempInstallerFiles = [ordered]@{}
$WinGetInstallerFiles = [ordered]@{}

class WinGetManifestRaw {
  [string]$Version
  [string]$Installer
  [System.Collections.Generic.IDictionary[string, string]]$Locale
}

filter UniqueItems {
  [string]$($_.Split(',').Trim() | Select-Object -Unique)
}

filter ToLower {
  [string]$_.ToLower()
}

filter NoWhitespace {
  [string]$_ -replace '\s+', '-'
}

$ToNatural = { [regex]::Replace($_, '\d+', { $args[0].Value.PadLeft(20) }) }

function Get-WinGetLocalRepoPath {
  <#
  .SYNOPSIS
    Get the location of the local winget-pkgs repo
  .PARAMETER RepoName
    The name of the upstream repo
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, HelpMessage = 'The name of the upstream repo')]
    [string]$RepoName = 'winget-pkgs'
  )

  if ((Test-Path -Path 'Variable:\DumplingsPreference') -and -not [string]::IsNullOrWhiteSpace($Global:DumplingsPreference['LocalRepoPath']) -and (Test-Path -Path ($Path = Join-Path $Global:DumplingsPreference.LocalRepoPath 'manifests'))) {
    return Resolve-Path -Path $Path
  } elseif ((Test-Path -Path 'Env:\GITHUB_WORKSPACE') -and (Test-Path -Path ($Path = Join-Path $Env:GITHUB_WORKSPACE $RepoName 'manifests'))) {
    return Resolve-Path -Path $Path
  } elseif ((Test-Path -Path 'Variable:\DumplingsRoot') -and (Test-Path -Path ($Path = Join-Path $Global:DumplingsRoot '..' $RepoName 'manifests'))) {
    return Resolve-Path -Path $Path
  } elseif (Test-Path -Path ($Path = Join-Path $PSScriptRoot '..' '..' '..' '..' $RepoName 'manifests')) {
    return Resolve-Path -Path $Path
  } else {
    throw 'Could not locate local winget-pkgs repo'
  }
}

function Get-WinGetLocalPackageVersion {
  <#
  .SYNOPSIS
    Get the versions of a package
  .DESCRIPTION
    Get the versions of a package from the winget-pkgs repo
  .PARAMETER PackageIdentifier
    The identifier of the package
  .PARAMETER Root
    The root path to the manifests folder of the winget-pkgs repo
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The identifier of the package')]
    [string]$PackageIdentifier,

    [Parameter(Position = 1, HelpMessage = 'The root path to the manifests folder of the winget-pkgs repo')]
    [string]$Root = (Get-WinGetLocalRepoPath)
  )

  process {
    @(
      Join-Path $Root $PackageIdentifier.ToLower().Chars(0) $PackageIdentifier.Replace('.', '\') '*' "${PackageIdentifier}.yaml" |
        Get-ChildItem -File |
        Split-Path -Parent | Split-Path -Leaf |
        Sort-Object $Script:ToNatural -Culture $Script:Culture -Stable
    )
  }
}

function Move-KeysToInstallerLevel {
  param (
    [Parameter(Position = 0, Mandatory)]
    [System.Collections.IDictionary]$Manifest,
    [Parameter(Position = 1, Mandatory)]
    [System.Collections.IDictionary[]]$Installers,
    [Parameter(Position = 2)]
    [string[]]$Property,
    [Parameter()]
    [int]$Depth = 2,
    [Parameter(DontShow)]
    [int]$CurrentDepth = 0
  )

  if ($CurrentDepth -ge $Depth) { return }
  foreach ($Key in @($Manifest.Keys)) {
    if ($Property -and $Key -cnotin $Property) { continue }
    $ToRemove = $true
    if ($Manifest.$Key -is [System.Collections.IDictionary]) {
      $PreservedManifestKeys = [System.Collections.Generic.HashSet[string]]::new()
      foreach ($Installer in $Installers) {
        $ManifestEntry = $Manifest.$Key | Copy-Object
        $InstallerEntry = $Installer.Contains($Key) -and $Installer.$Key ? $Installer.$Key : [ordered]@{}
        Move-KeysToInstallerLevel -Manifest $ManifestEntry -Installers $InstallerEntry -Depth $Depth -CurrentDepth ($CurrentDepth + 1)
        $PreservedManifestKeys.UnionWith([string[]]($ManifestEntry.Keys))
        if ($InstallerEntry.Count -gt 0) { $Installer.$Key = $InstallerEntry }
      }
      if ($PreservedManifestKeys.Count -gt 0) {
        $ToRemove = $false
        foreach ($KeyToRemove in $Manifest.$Key.Keys.Where({ $_ -cnotin $PreservedManifestKeys })) { $Manifest.$Key.Remove($KeyToRemove) }
      }
    } elseif ($Manifest.$Key -is [System.Collections.IEnumerable] -and $Manifest.$Key -isnot [string]) {
      $ManifestEntry = $Manifest.$Key
      $ManifestEntryHash = ConvertTo-Json -InputObject $ManifestEntry -Depth 10 -Compress
      foreach ($Installer in $Installers) {
        if (-not $Installer.Contains($Key)) {
          $Installer.$Key = $Manifest.$Key
        } elseif ($Installer.Contains($Key) -and -not $Installer.$Key) {
          $Installer.$Key = $Manifest.$Key
        } elseif ($Installer.Contains($Key) -and (ConvertTo-Json -InputObject $Installer.$Key -Depth 10 -Compress) -cne $ManifestEntryHash) {
          $ToRemove = $false
        }
      }
    } else {
      foreach ($Installer in $Installers) {
        if (-not $Installer.Contains($Key)) {
          $Installer.$Key = $Manifest.$Key
        } elseif ($Installer.Contains($Key) -and -not $Installer.$Key) {
          $Installer.$Key = $Manifest.$Key
        } elseif ($Installer.Contains($Key) -and $Installer.$Key -cne $Manifest.$Key) {
          $ToRemove = $false
        }
      }
    }
    if ($ToRemove) {
      $Manifest.Remove($Key)
    }
  }
}

function Move-KeysToManifestLevel {
  param (
    [Parameter(Position = 0, Mandatory)]
    [System.Collections.IDictionary[]]$Installers,
    [Parameter(Position = 1, Mandatory)]
    [System.Collections.IDictionary]$Manifest,
    [Parameter(Position = 2)]
    [string[]]$Property,
    [Parameter()]
    [int]$Depth = 2,
    [Parameter(DontShow)]
    [int]$CurrentDepth = 0
  )

  if ($CurrentDepth -ge $Depth) { return }
  $AllKeys = @($Installers | ForEach-Object -Process { $_.Keys } | Select-Object -Unique)
  foreach ($Key in $AllKeys) {
    if ($Property -and $Key -cnotin $Property) { continue }
    if ($Installers.Where({ $_.Contains($Key) -and $_.$Key -is [System.Collections.IDictionary] })) {
      $InstallersEntry = @($Installers | ForEach-Object -Process { $_.Contains($Key) -and $_.$Key ? $_.$Key : [ordered]@{} })
      $ManifestEntry = $Manifest.Contains($Key) -and $Manifest.$Key ? $Manifest.$Key : [ordered]@{}

      # Move the same elements across all the objects to the manifest level
      Move-KeysToManifestLevel -Installers $InstallersEntry -Manifest $ManifestEntry -Depth $Depth -CurrentDepth ($CurrentDepth + 1)

      # If the manifest entry is not empty, add it to the manifest
      if ($ManifestEntry.Count -gt 0) {
        $Manifest.$Key = $ManifestEntry
      }
      # If the installer entry is empty, remove it from the installers
      foreach ($Installer in $Installers) {
        if ($Installer.Contains($Key) -and $Installer.$Key.Count -eq 0) {
          $Installer.Remove($Key)
        }
      }
    } elseif ($Installers.Where({ $_.Contains($Key) -and $_.$Key -is [System.Collections.IEnumerable] -and $_.$Key -isnot [string] })) {
      if ($Manifest.Contains($Key)) {
        $ManifestEntryHash = ConvertTo-Json -InputObject $Manifest.$Key -Depth 10 -Compress
        foreach ($Installer in $Installers) {
          $InstallersEntryHash = ConvertTo-Json -InputObject $Installer.$Key -Depth 10 -Compress
          if ($ManifestEntryHash -ceq $InstallersEntryHash) {
            $Installer.Remove($Key)
          }
        }
      } elseif (-not $Manifest.Contains($Key) -and -not ($Installers.Where({ -not $_.Contains($Key) })) -and @($Installers | Sort-Object -Property { ConvertTo-Json -InputObject $_.$Key -Depth 10 -Compress } -Unique).Count -eq 1) {
        $Manifest.$Key = $Installers[0].$Key
        foreach ($Installer in $Installers) {
          $Installer.Remove($Key)
        }
      }
    } else {
      if ($Manifest.Contains($Key)) {
        foreach ($Installer in $Installers) {
          if ($Installer.$Key -ceq $Manifest.$Key) {
            $Installer.Remove($Key)
          }
        }
      } elseif (-not $Manifest.Contains($Key) -and -not ($Installers.Where({ -not $_.Contains($Key) })) -and @($Installers | Sort-Object -Property { $_.$Key } -Unique).Count -eq 1) {
        $Manifest.$Key = $Installers[0].$Key
        foreach ($Installer in $Installers) {
          $Installer.Remove($Key)
        }
      }
    }
  }
}

function Update-WinGetInstallerManifestInstallerMetadata {
  <#
  .SYNOPSIS
    Update the metadata of the installer entry
  .DESCRIPTION
    Update the metadata of the installer entry using the provided installer metadata
  .PARAMETER Installer
    The installer to update
  .PARAMETER OldInstaller
    The old installer for reference
  .PARAMETER InstallerEntry
    The installer entry to use for updating the installer
  .PARAMETER Installers
    The installers that have updated for reference (e.g., hashes)
  #>
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The installer to update')]
    [System.Collections.IDictionary]$Installer,
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The old installer for reference')]
    [System.Collections.IDictionary]$OldInstaller,
    [Parameter(Mandatory, HelpMessage = 'The installer entry to use for updating the installer')]
    [System.Collections.IDictionary]$InstallerEntry,
    [Parameter(HelpMessage = 'The installers that have updated for reference')]
    [System.Collections.IDictionary[]]$Installers = @(),
    [Parameter(HelpMessage = 'The hashtable of downloaded installer files, with installer URL as the key and installer path as the value')]
    [System.Collections.IDictionary]$InstallerFiles
  )

  # Replace the whitespace in the installer URL with %20 to make it clickable
  # Keep the original URL for reference in downloading
  $OriginalInstallerUrl = $Installer.InstallerUrl
  $Installer.InstallerUrl = $Installer.InstallerUrl.Replace(' ', '%20')

  # Update the installer using the matching installer
  $MatchingInstaller = $Installers | Where-Object -FilterScript { $_.InstallerUrl -ceq $Installer.InstallerUrl } | Select-Object -First 1
  if ($MatchingInstaller -and ($Installer.Contains('NestedInstallerFiles') ? ((ConvertTo-Json -InputObject $Installer.NestedInstallerFiles -Depth 10 -Compress) -ceq (ConvertTo-Json -InputObject $MatchingInstaller.NestedInstallerFiles -Depth 10 -Compress)) : $true)) {
    foreach ($Key in @('InstallerSha256', 'SignatureSha256', 'PackageFamilyName', 'ProductCode', 'ReleaseDate', 'AppsAndFeaturesEntries')) {
      if ($MatchingInstaller.Contains($Key) -and -not $InstallerEntry.Contains($Key)) {
        $Installer.$Key = $MatchingInstaller.$Key
      } elseif (-not $MatchingInstaller.Contains($Key) -and $Installer.Contains($Key)) {
        $Installer.Remove($Key)
      }
    }
  }

  # Download and analyze the installer file
  # Skip if there is matching installer, or the "InstallerSha256" is explicitly specified
  if (-not $Installer.Contains('InstallerSha256')) {
    if ($Script:WinGetTempInstallerFiles.Contains($OriginalInstallerUrl) -and (Test-Path -Path $Script:WinGetTempInstallerFiles[$OriginalInstallerUrl])) {
      # Skip downloading if the installer file is already downloaded
      $InstallerPath = $Script:WinGetTempInstallerFiles[$OriginalInstallerUrl]
    } elseif ($InstallerFiles.Contains($OriginalInstallerUrl) -and (Test-Path -Path $InstallerFiles[$OriginalInstallerUrl])) {
      # Skip downloading if the installer file was previously downloaded
      $InstallerPath = $InstallerFiles[$OriginalInstallerUrl]
    } elseif ($Script:WinGetInstallerFiles.Contains($OriginalInstallerUrl) -and (Test-Path -Path $Script:WinGetInstallerFiles[$OriginalInstallerUrl])) {
      # Skip downloading if the installer file was previously downloaded
      $InstallerPath = $Script:WinGetInstallerFiles[$OriginalInstallerUrl]
    } else {
      # $Task.Log("Downloading $($Installer.InstallerUrl)", 'Verbose')
      try {
        $Script:WinGetTempInstallerFiles[$OriginalInstallerUrl] = $InstallerPath = Get-TempFile -Uri $Installer.InstallerUrl -UserAgent $Script:WinGetUserAgent
      } catch {
        # $Task.Log('Failed to download with the Delivery-Optimization User Agent. Try again with the WinINet User Agent...', 'Warning')
        $Script:WinGetTempInstallerFiles[$OriginalInstallerUrl] = $InstallerPath = Get-TempFile -Uri $Installer.InstallerUrl -UserAgent $Script:WinGetBackupUserAgent
      }
    }

    # $Task.Log('Processing installer data...', 'Verbose')

    # Get installer SHA256
    $Installer.InstallerSha256 = (Get-FileHash -Path $InstallerPath -Algorithm SHA256).Hash

    # If the installer is an archive and the nested installer is msi or wix, expand the archive to get the nested installer
    $EffectiveInstallerType = $Installer.Contains('NestedInstallerType') ? $Installer.NestedInstallerType : $Installer.InstallerType
    $EffectiveInstallerPath = $Installer.InstallerType -cin @('zip') -and $Installer.NestedInstallerType -cne 'portable' ? (Expand-TempArchive -Path $InstallerPath | Join-Path -ChildPath $Installer.NestedInstallerFiles[0].RelativeFilePath) : $InstallerPath

    # Update ProductCode, UpgradeCode and ProductVersion if the installer is msi, wix or burn, and such fields exist in the old installer
    # ProductCode
    $ProductCode = $null
    if ($EffectiveInstallerType -cin @('msi', 'wix')) {
      $ProductCode = $EffectiveInstallerPath | Read-ProductCodeFromMsi -ErrorAction 'Continue'
    } elseif ($EffectiveInstallerType -ceq 'burn') {
      $ProductCode = $EffectiveInstallerPath | Read-ProductCodeFromBurn -ErrorAction 'Continue'
    }
    if (-not $InstallerEntry.Contains('ProductCode') -and $EffectiveInstallerType -cin @('msi', 'wix', 'burn') -and $Installer.Contains('ProductCode')) {
      if (-not [string]::IsNullOrWhiteSpace($ProductCode)) {
        $Installer.ProductCode = $ProductCode
      } else {
        throw 'Failed to get ProductCode'
      }
    }
    if (-not $InstallerEntry.Contains('AppsAndFeaturesEntries') -and $EffectiveInstallerType -cin @('msi', 'wix', 'burn') -and $Installer['AppsAndFeaturesEntries']) {
      # UpgradeCode
      $UpgradeCode = $null
      if ($EffectiveInstallerType -cin @('msi', 'wix')) {
        $UpgradeCode = $EffectiveInstallerPath | Read-UpgradeCodeFromMsi -ErrorAction 'Continue'
      } elseif ($EffectiveInstallerType -ceq 'burn') {
        $UpgradeCode = $EffectiveInstallerPath | Read-UpgradeCodeFromBurn -ErrorAction 'Continue'
      }
      # DisplayVersion
      $DisplayVersion = $null
      if ($EffectiveInstallerType -cin @('msi', 'wix')) {
        $DisplayVersion = $EffectiveInstallerPath | Read-ProductVersionFromMsi -ErrorAction 'Continue'
      } elseif ($EffectiveInstallerType -ceq 'burn') {
        $DisplayVersion = $EffectiveInstallerPath | Read-ProductVersionFromExe -ErrorAction 'Continue'
      }
      # DisplayName
      $DisplayName = $null
      if ($EffectiveInstallerType -cin @('msi', 'wix')) {
        $DisplayName = $EffectiveInstallerPath | Read-ProductNameFromMsi -ErrorAction 'Continue'
      } elseif ($EffectiveInstallerType -ceq 'burn') {
        $DisplayName = $EffectiveInstallerPath | Read-ProductNameFromBurn -ErrorAction 'Continue'
      }
      # Match the AppsAndFeaturesEntries that...
      $Installer.AppsAndFeaturesEntries | Where-Object -FilterScript {
        # ...have the same UpgradeCode as the new installer, or...
        ($UpgradeCode -and $_['UpgradeCode'] -and $UpgradeCode -ceq $_.UpgradeCode) -or
        # ...have the same ProductCode as the old installer, or...
        ($OldInstaller['ProductCode'] -and $_['ProductCode'] -and $OldInstaller.ProductCode -ceq $_.ProductCode) -or
        # ...is the only entry in the installer
        ($Installer.AppsAndFeaturesEntries.Count -eq 1)
      } | ForEach-Object -Process {
        if ($_.Contains('DisplayName')) {
          if (-not [string]::IsNullOrWhiteSpace($DisplayName)) {
            $_.DisplayName = $DisplayName
          } else {
            throw 'Failed to get DisplayName'
          }
        }
        if ($_.Contains('DisplayVersion')) {
          if (-not [string]::IsNullOrWhiteSpace($DisplayVersion)) {
            $_.DisplayVersion = $DisplayVersion
          } else {
            throw 'Failed to get DisplayVersion'
          }
        }
        if ($_.Contains('ProductCode')) {
          if (-not [string]::IsNullOrWhiteSpace($ProductCode)) {
            $_.ProductCode = $ProductCode
          } else {
            throw 'Failed to get ProductCode'
          }
        }
        if ($_.Contains('UpgradeCode')) {
          if (-not [string]::IsNullOrWhiteSpace($UpgradeCode)) {
            $_.UpgradeCode = $UpgradeCode
          } else {
            throw 'Failed to get UpgradeCode'
          }
        }
      }
    }

    # Update SignatureSha256 and PackageFamilyName if the installer is msix or appx
    if ($Installer.InstallerType -cin @('msix', 'appx')) {
      # SignatureSha256
      $SignatureSha256 = $InstallerPath | Get-MSIXSignatureHash
      if (-not [string]::IsNullOrWhiteSpace($SignatureSha256)) {
        $Installer.SignatureSha256 = $SignatureSha256
      } elseif ($Installer.Contains('SignatureSha256')) {
        # $Task.Log('Failed to get SignatureSha256', 'Warning')
        $Installer.Remove('SignatureSha256')
      }

      # PackageFamilyName
      $PackageFamilyName = $InstallerPath | Read-FamilyNameFromMSIX
      if (-not [string]::IsNullOrWhiteSpace($PackageFamilyName)) {
        $Installer.PackageFamilyName = $PackageFamilyName
      } elseif ($Installer.Contains('PackageFamilyName')) {
        # $Task.Log('Failed to get PackageFamilyName', 'Warning')
        $Installer.Remove('PackageFamilyName')
      }
    }
  }

  # Beautify entries
  if ($Installer.Contains('Commands')) { $Installer.Commands = @($Installer.Commands | NoWhitespace | UniqueItems | Sort-Object -Culture $Script:Culture) }
  if ($Installer.Contains('Protocols')) { $Installer.Protocols = @($Installer.Protocols | ToLower | NoWhitespace | UniqueItems | Sort-Object -Culture $Script:Culture) }
  if ($Installer.Contains('FileExtensions')) { $Installer.FileExtensions = @($Installer.FileExtensions | ToLower | NoWhitespace | UniqueItems | Sort-Object -Culture $Script:Culture) }

  return $Installer
}

function Update-WinGetInstallerManifestInstallers {
  <#
  .SYNOPSIS
    Update the installers of the manifest
  .DESCRIPTION
    Iterate over the installers of the old manifest and update them using the provided installer entries
  .PARAMETER OldInstallers
    The old installers to update
  .PARAMETER InstallerEntries
    The installer entries to use for updating the installers
  #>
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The old installers to update')]
    [System.Collections.IDictionary[]]$OldInstallers,
    [Parameter(Mandatory, HelpMessage = 'The installer entries to use for updating the installers')]
    [System.Collections.IDictionary[]]$InstallerEntries,
    [Parameter(DontShow, HelpMessage = 'The hashtable of downloaded installer files, with installer URL as the key and installer path as the value')]
    [System.Collections.IDictionary]$InstallerFiles
  )

  $iteration = 0
  $Installers = @()
  foreach ($OldInstaller in $OldInstallers) {
    $iteration += 1
    # $Task.Log("Updating installer #${iteration}/$($OldInstallers.Count) [$($OldInstaller['InstallerLocale']), $($OldInstaller['Architecture']), $($OldInstaller['InstallerType']), $($OldInstaller['NestedInstallerType']), $($OldInstaller['Scope'])]", 'Verbose')

    # Apply inputs
    $MatchingInstallerEntry = $null
    foreach ($InstallerEntry in $InstallerEntries) {
      $Updatable = $true
      # Find matching installer entry
      if ($InstallerEntry.Contains('Query')) {
        if ($InstallerEntry.Query -is [scriptblock]) {
          # The installer entry will be chosen if the scriptblock passed with the installer entry returns something
          if (-not (Invoke-Command -ScriptBlock $InstallerEntry.Query -InputObject $OldInstaller)) {
            $Updatable = $false
          }
        } elseif ($InstallerEntry.Query -is [System.Collections.IDictionary]) {
          # The installer entry will be chosen if the installer contain all the keys present in the installer entry Query field, and their values are the same
          foreach ($Key in $InstallerEntry.Query.Keys) {
            if ($OldInstaller.Contains($Key) -and $OldInstaller.$Key -cne $InstallerEntry.Query.$Key) {
              # Skip this entry if the installer has this key, but with a different value
              $Updatable = $false
            } elseif (-not $OldInstaller.Contains($Key)) {
              # Skip this entry if the installer doesn't have this key
              $Updatable = $false
            }
          }
        } else {
          throw 'The installer entry Query field should be either a scriptblock or a dictionary'
        }
      } else {
        # The installer entry will be chosen if the installer contain all the keys present in the installer entry, and their values are the same
        foreach ($Key in @('InstallerLocale', 'Architecture', 'InstallerType', 'NestedInstallerType', 'Scope')) {
          if ($InstallerEntry.Contains($Key) -and $OldInstaller.Contains($Key) -and $OldInstaller.$Key -cne $InstallerEntry.$Key) {
            # Skip this entry if the installer has this key, but with a different value
            $Updatable = $false
          } elseif ($InstallerEntry.Contains($Key) -and -not $OldInstaller.Contains($Key)) {
            # Skip this entry if the installer doesn't have this key
            $Updatable = $false
          }
        }
      }
      # If the installer entry matches the installer, use the last matching entry for updating the installer
      if ($Updatable) {
        $MatchingInstallerEntry = $InstallerEntry
      }
    }
    # If no matching installer entry is found, throw an error
    if (-not $MatchingInstallerEntry) {
      throw "No matching installer entry for [$($OldInstaller['InstallerLocale']), $($OldInstaller['Architecture']), $($OldInstaller['InstallerType']), $($OldInstaller['tNestedInstallerType']), $($OldInstaller['Scope'])]"
    }

    # Deep copy the old installer
    $Installer = $OldInstaller | Copy-Object

    # Clean up volatile fields
    $Installer.Remove('InstallerSha256')
    if ($Installer.Contains('ReleaseDate')) { $Installer.Remove('ReleaseDate') }

    # Update the installer using the matching installer entry
    foreach ($Key in $MatchingInstallerEntry.Keys) {
      if ($Key -ceq 'Query') {
        # Skip the entries used for matching
        continue
      } elseif (-not $MatchingInstallerEntry.Contains('Query') -and $Key -cin @('InstallerLocale', 'Architecture', 'InstallerType', 'NestedInstallerType', 'Scope')) {
        # Skip the entries used for matching if Query is not present
        continue
      } elseif ($Key -cnotin (Get-WinGetManifestSchema -ManifestType installer).definitions.Installer.properties.Keys) {
        # Check if the key is a valid installer property
        throw "The installer entry has an invalid key: ${Key}"
      } else {
        try {
          $null = Test-YamlObject -InputObject $MatchingInstallerEntry.$Key -Schema (Get-WinGetManifestSchema -ManifestType installer).properties.Installers.items.properties.$Key -WarningAction Stop
          $Installer.$Key = $MatchingInstallerEntry.$Key
        } catch {
          # $Task.Log("The new value of the installer property `"${Key}`" is invalid and thus discarded: ${_}", 'Warning')
        }
      }
    }

    $Installer = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller $OldInstaller -InstallerEntry $MatchingInstallerEntry -Installers $Installers -InstallerFiles $InstallerFiles

    # Add the updated installer to the new installers array
    $Installers += $Installer
  }

  # Remove the downloaded files
  foreach ($InstallerPath in $Script:WinGetTempInstallerFiles.Values) {
    Remove-Item -Path $InstallerPath -Force -ErrorAction 'Continue'
  }
  $Script:WinGetTempInstallerFiles.Clear()

  return $Installers
}

function Set-WinGetInstallerManifestInstallers {
  <#
  .SYNOPSIS
    Update the installers of the manifest
  .DESCRIPTION
    Iterate over the installer entries and update the matching installers using the provided installer entries
  .PARAMETER OldInstallers
    The old installers to update
  .PARAMETER InstallerEntries
    The installer entries to use for updating the installers
  #>
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The old installers to update')]
    [System.Collections.IDictionary[]]$OldInstallers,
    [Parameter(Mandatory, HelpMessage = 'The installer entries to use for updating the installers')]
    [System.Collections.IDictionary[]]$InstallerEntries,
    [Parameter(DontShow, HelpMessage = 'The hashtable of downloaded installer files, with installer URL as the key and installer path as the value')]
    [System.Collections.IDictionary]$InstallerFiles
  )

  $iteration = 0
  $Installers = @()
  foreach ($InstallerEntry in $InstallerEntries) {
    $iteration += 1
    # $Task.Log("Applying installer entry #${iteration}/$($InstallerEntries.Count)", 'Verbose')

    # Find matching installer
    $MatchingInstaller = $null
    foreach ($OldInstaller in $OldInstallers) {
      $Updatable = $true
      # If Query is present, select the installer based on the query. If not, select the first installer
      if ($InstallerEntry.Contains('Query')) {
        # The installer will be chosen if the scriptblock passed with the installer returns something
        if ($InstallerEntry.Query -is [scriptblock]) {
          if (-not (Invoke-Command -ScriptBlock $InstallerEntry.Query -InputObject $OldInstaller)) {
            $Updatable = $false
          }
        } elseif ($InstallerEntry.Query -is [System.Collections.IDictionary]) {
          # The installer will be chosen if the installer contain all the keys present in the installer entry Query field, and their values are the same
          foreach ($Key in $InstallerEntry.Query.Keys) {
            if ($OldInstaller.Contains($Key) -and $OldInstaller.$Key -cne $InstallerEntry.Query.$Key) {
              # Skip this entry if the installer has this key, but with a different value
              $Updatable = $false
            } elseif (-not $OldInstaller.Contains($Key)) {
              # Skip this entry if the installer doesn't have this key
              $Updatable = $false
            }
          }
        } else {
          throw 'The installer entry Query field should be either a scriptblock or a dictionary'
        }
      }
      # If the installer entry matches the installers, use the first matching installer for updating
      if ($Updatable) {
        $MatchingInstaller = $OldInstaller
        break
      }
    }
    # If no matching installer entry is found, throw an error
    if (-not $MatchingInstaller) {
      throw 'No matching installer for the installer entry'
    }

    # Deep copy the old installer
    $Installer = $MatchingInstaller | Copy-Object

    # Clean up volatile fields
    $Installer.Remove('InstallerSha256')
    if ($Installer.Contains('ReleaseDate')) { $Installer.Remove('ReleaseDate') }

    # Update the installer using the matching installer entry
    foreach ($Key in $InstallerEntry.Keys) {
      if ($Key -ceq 'Query') {
        # Skip the entries used for matching
        continue
      } elseif ($Key -cnotin (Get-WinGetManifestSchema -ManifestType installer).definitions.Installer.properties.Keys) {
        # Check if the key is a valid installer property
        throw "The installer entry has an invalid key: ${Key}"
      } else {
        try {
          $null = Test-YamlObject -InputObject $InstallerEntry.$Key -Schema (Get-WinGetManifestSchema -ManifestType installer).properties.Installers.items.properties.$Key -WarningAction Stop
          $Installer.$Key = $InstallerEntry.$Key
        } catch {
          # $Task.Log("The new value of the installer property `"${Key}`" is invalid and thus discarded: ${_}", 'Warning')
        }
      }
    }

    $Installer = Update-WinGetInstallerManifestInstallerMetadata -Installer $Installer -OldInstaller $MatchingInstaller -InstallerEntry $InstallerEntry -Installers $Installers -InstallerFiles $InstallerFiles

    # Add the updated installer to the new installers array
    $Installers += $Installer
  }

  # Remove the downloaded files
  foreach ($InstallerPath in $Script:WinGetTempInstallerFiles.Values) {
    Remove-Item -Path $InstallerPath -Force -ErrorAction 'Continue'
  }
  $Script:WinGetTempInstallerFiles.Clear()

  return $Installers
}

function Update-WinGetVersionManifest {
  <#
  .SYNOPSIS
    Update the version manifest
  .DESCRIPTION
    Update the version manifest using the provided package version
  .PARAMETER OldVersionManifest
    The old version manifest to update
  .PARAMETER PackageVersion
    The package version to use for updating the version manifest
  #>
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The old version manifest to update')]
    [System.Collections.IDictionary]$OldVersionManifest,
    [Parameter(Mandatory, HelpMessage = 'The package version to use for updating the version manifest')]
    [string]$PackageVersion
  )

  # Deep copy the old version manifest
  $VersionManifest = $OldVersionManifest | Copy-Object

  # Bump package version
  $VersionManifest.PackageVersion = $PackageVersion
  # Bump manifest version
  $VersionManifest.ManifestVersion = $ManifestVersion

  return ConvertTo-SortedYamlObject -InputObject $VersionManifest -Schema (Get-WinGetManifestSchema -ManifestType version) -Culture $Script:Culture
}

function Update-WinGetInstallerManifest {
  <#
  .SYNOPSIS
    Update the installer manifest
  .DESCRIPTION
    Update the installer manifest using the provided installer entries
  .PARAMETER OldInstallerManifest
    The old installer manifest to update
  .PARAMETER InstallerEntries
    The installer entries to use for updating the installer manifest
  .PARAMETER PackageVersion
    The package version to use for updating the installer manifest
  .PARAMETER Replace
    Replace the installers rather than updating them
  #>
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The old installer manifest to update')]
    [System.Collections.IDictionary]$OldInstallerManifest,
    [Parameter(Mandatory, HelpMessage = 'The installer entries to use for updating the installer manifest')]
    [System.Collections.IDictionary[]]$InstallerEntries,
    [Parameter(Mandatory, HelpMessage = 'The package version to use for updating the installer manifest')]
    [string]$PackageVersion,
    [Parameter(DontShow, HelpMessage = 'The hashtable of downloaded installer files, with installer URL as the key and installer path as the value')]
    [System.Collections.IDictionary]$InstallerFiles,
    [Parameter(HelpMessage = 'Replace the installers rather than updating them')]
    [switch]$Replace = $false
  )

  # Deep copy the old installer manifest
  $InstallerManifest = $OldInstallerManifest | Copy-Object

  # Bump package version
  $InstallerManifest.PackageVersion = $PackageVersion
  # Bump manifest version
  $InstallerManifest.ManifestVersion = $ManifestVersion

  # Move Manifest Level Keys to installer Level
  $InstallerSchema = Get-WinGetManifestSchema -ManifestType installer
  Move-KeysToInstallerLevel -Manifest $InstallerManifest -Installers $InstallerManifest.Installers -Property $InstallerSchema.definitions.Installer.properties.Keys.Where({ $_ -cin $InstallerSchema.properties.Keys })
  # Update installer entries
  if (-not $Replace) {
    $InstallerManifest.Installers = Update-WinGetInstallerManifestInstallers -OldInstallers $InstallerManifest.Installers -InstallerEntries $InstallerEntries -InstallerFiles $InstallerFiles
  } else {
    $InstallerManifest.Installers = Set-WinGetInstallerManifestInstallers -OldInstallers $InstallerManifest.Installers -InstallerEntries $InstallerEntries -InstallerFiles $InstallerFiles
  }
  # Move Installer Level Keys to Manifest Level
  $InstallerSchema = Get-WinGetManifestSchema -ManifestType installer
  Move-KeysToManifestLevel -Installers $InstallerManifest.Installers -Manifest $InstallerManifest -Property $InstallerSchema.definitions.Installer.properties.Keys.Where({ $_ -cin $InstallerSchema.properties.Keys })

  return ConvertTo-SortedYamlObject -InputObject $InstallerManifest -Schema $InstallerSchema -Culture $Script:Culture
}

function Update-WinGetLocaleManifest {
  <#
  .SYNOPSIS
    Update the locale manifest
  .DESCRIPTION
    Update the locale manifest using the provided locale entries
  .PARAMETER PackageVersion
    The package version to use for updating the locale manifest
  #>
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The old locale manifests to update')]
    [System.Collections.IDictionary[]]$OldLocaleManifests,
    [Parameter(HelpMessage = 'The locale entries to use for updating the locale manifests')]
    [System.Collections.IDictionary[]]$LocaleEntries = @(),
    [Parameter(Mandatory, HelpMessage = 'The package version to use for updating the locale manifest')]
    [string]$PackageVersion
  )

  $LocaleManifests = @()

  # Copy over all locale files from previous version that aren't the same
  foreach ($OldLocaleManifest in $OldLocaleManifests) {
    $LocaleManifest = $OldLocaleManifest | Copy-Object

    # Bump package version
    $LocaleManifest.PackageVersion = $PackageVersion
    # Bump manifest version
    $LocaleManifest.ManifestVersion = $ManifestVersion
    # Clean up volatile fields
    if ($LocaleManifest.Contains('ReleaseNotes')) { $LocaleManifest.Remove('ReleaseNotes') }

    # Apply inputs
    if ($LocaleEntries) {
      foreach ($LocaleEntry in $LocaleEntries) {
        if (-not $LocaleEntry.Contains('Key') -or -not $LocaleEntry.Contains('Value') -or [string]::IsNullOrWhiteSpace($LocaleEntry.Key)) {
          # Check if the locale entry contains the required properties
          throw 'The locale entry does not contain the required properties'
        } elseif ($LocaleEntry.Key -cnotin (Get-WinGetManifestSchema -ManifestType locale).properties.Keys) {
          # Check if the key property is a valid locale property
          throw "The locale entry has an invalid key `"$($LocaleEntry.Key)`""
        } elseif ($LocaleEntry.Contains('Locale') -and $LocaleEntry.Locale -notmatch (Get-WinGetManifestSchema -ManifestType locale).properties.PackageLocale.pattern) {
          # Check if the locale property is a valid locale
          throw "The locale entry has an invalid locale `"$($LocaleEntry.Locale)`" contains an invalid locale"
        } elseif ($LocaleEntry.Contains('Locale') -and $LocaleEntry.Locale -notcontains $LocaleManifest.PackageLocale) {
          # If the locale entry contains a locale property, only match the locale manifests with these locales
          continue
        } elseif ($null -ceq $LocaleEntry.Value) {
          # If the value is null, remove the key from the locale manifest
          $LocaleManifest.Remove($LocaleEntry.Key)
        } else {
          try {
            if (Test-YamlObject -InputObject $LocaleEntry.Value -Schema (Get-WinGetManifestSchema -ManifestType locale).properties[$LocaleEntry.Key] -WarningAction Stop) {
              $LocaleManifest[$LocaleEntry.Key] = $LocaleEntry.Value
            } else {
              # $Task.Log("The locale entry `"$($LocaleEntry.Key)`" has an invalid value and thus discarded", 'Warning')
            }
          } catch {
            # $Task.Log("The locale entry `"$($LocaleEntry.Key)`" has an invalid value and thus discarded: ${_}", 'Warning')
          }
        }
      }
    }

    if ($LocaleManifest.Contains('Tags')) { $LocaleManifest.Tags = @($LocaleManifest.Tags | ToLower | NoWhitespace | UniqueItems | Sort-Object -Culture $Script:Culture) }
    if ($LocaleManifest.Contains('Moniker')) {
      if ($LocaleManifest.ManifestType -ceq 'defaultLocale') {
        $LocaleManifest['Moniker'] = $LocaleManifest['Moniker'] | ToLower | NoWhitespace
      } else {
        $LocaleManifest.Remove('Moniker')
      }
    }
    # Remove ReleaseNotes if too long
    if ($LocaleManifest.Contains('ReleaseNotes') -and $LocaleManifest.ReleaseNotes.Length -gt (Get-WinGetManifestSchema -ManifestType locale).properties.ReleaseNotes.maxLength) { $LocaleManifest.Remove('ReleaseNotes') }

    $Schema = $LocaleManifest.ManifestType -ceq 'defaultLocale' ? (Get-WinGetManifestSchema -ManifestType defaultLocale) : (Get-WinGetManifestSchema -ManifestType locale)
    $LocaleManifests += ConvertTo-SortedYamlObject -InputObject $LocaleManifest -Schema $Schema -Culture $Script:Culture
  }

  return $LocaleManifests
}

function Update-WinGetManifests {
  <#
  .SYNOPSIS
    Update WinGet package manifests
  .DESCRIPTION
    Update WinGet package manifests using the provided installer and locale entries
  .PARAMETER PackageVersion
    The package version of the manifest
  .PARAMETER VersionManifest
    The version manifest to update
  .PARAMETER InstallerManifest
    The installer manifest to update
  .PARAMETER LocaleManifests
    The locale manifests to update
  .PARAMETER InstallerEntries
    The installer entries to be applied to the installer manifest
  .PARAMETER LocaleEntries
    The locale entries to be applied to the locale manifest
  .PARAMETER ReplaceInstallers
    Replace the installers rather than updating them
  #>
  [OutputType([System.Collections.Specialized.OrderedDictionary])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The package version of the manifest')]
    [string]$PackageVersion,
    [Parameter(Mandatory, HelpMessage = 'The version manifest to update')]
    [System.Collections.IDictionary]$VersionManifest,
    [Parameter(Mandatory, HelpMessage = 'The installer manifest to update')]
    [System.Collections.IDictionary]$InstallerManifest,
    [Parameter(Mandatory, HelpMessage = 'The locale manifests to update')]
    [System.Collections.IDictionary[]]$LocaleManifests,
    [Parameter(Mandatory, HelpMessage = 'The installer entries to be applied to the installer manifest')]
    [System.Collections.IDictionary[]]$InstallerEntries,
    [Parameter(HelpMessage = 'The locale entries to be applied to the locale manifest')]
    [System.Collections.IDictionary[]]$LocaleEntries = @(),
    [Parameter(DontShow, HelpMessage = 'The hashtable of downloaded installer files, with installer URL as the key and installer path as the value')]
    [System.Collections.IDictionary]$InstallerFiles = @(),
    [Parameter(HelpMessage = 'Replace the installers rather than updating them')]
    [switch]$ReplaceInstallers = $false
  )

  return [ordered]@{
    Installer = Update-WinGetInstallerManifest -OldInstallerManifest $InstallerManifest -InstallerEntries $InstallerEntries -PackageVersion $PackageVersion -InstallerFiles $InstallerFiles -Replace:$ReplaceInstallers
    Locale    = Update-WinGetLocaleManifest -OldLocaleManifests $LocaleManifests -LocaleEntries $LocaleEntries -PackageVersion $PackageVersion
    Version   = Update-WinGetVersionManifest -OldVersionManifest $VersionManifest -PackageVersion $PackageVersion
  }
}

function Convert-WinGetManifestsFromYaml {
  <#
  .SYNOPSIS
    Read the manifests for a package
  .DESCRIPTION
    Read the installer, locale and version manifests for a package using the provided package identifier and manifests path
  .PARAMETER Manifests
    The manifest(s) to read
  #>
  [OutputType([System.Collections.Specialized.OrderedDictionary])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The manifest(s) to read')]
    $Manifests
  )

  process {
    # Read the main manifest to check the manifest type
    $MainManifest = $Manifests.Version | ConvertFrom-Yaml -Ordered
    if ($MainManifest.ManifestType -ceq 'version') {
      $ManifestType = 'MultiManifest'
      $PackageLocale = $MainManifest.DefaultLocale
    } elseif ($MainManifest.ManifestType -ceq 'singleton') {
      $ManifestType = 'SingletonManifest'
      $PackageLocale = $MainManifest.PackageLocale
    } else {
      throw "Unrecognized manifest type $($MainManifest.ManifestType)"
    }

    if ($ManifestType -ceq 'MultiManifest') {
      # If the manifest type is MultiManifest, read the remaining installer and locale manifests
      $VersionManifest = $MainManifest
      if ([string]::IsNullOrWhiteSpace($Manifests.Installer)) { throw 'The installer manifest is missing or empty' }
      $InstallerManifest = $Manifests.Installer | ConvertFrom-Yaml -Ordered
      if (-not $Manifests.Locale) { throw 'The locale manifest is missing' }
      $LocaleManifests = $Manifests.Locale.GetEnumerator().ForEach({ if ([string]::IsNullOrWhiteSpace($_.Value)) { throw 'One of the locale manifests is empty' }; ConvertFrom-Yaml -Yaml $_.Value -Ordered })
    } elseif ($ManifestType -ceq 'Singleton') {
      $SingletonManifest = $MainManifest
      # Parse version keys to version manifest
      $VersionManifest = [ordered]@{}
      foreach ($Key in $SingletonManifest.Keys.Where({ $_ -cin (Get-WinGetManifestSchema -ManifestType version).properties.Keys })) {
        $VersionManifest[$Key] = $SingletonManifest.$Key
      }
      $VersionManifest['DefaultLocale'] = $PackageLocale
      $VersionManifest['ManifestType'] = 'version'
      # Parse installer keys to installer manifest
      $InstallerManifest = [ordered]@{}
      foreach ($Key in $SingletonManifest.Keys.Where({ $_ -cin (Get-WinGetManifestSchema -ManifestType installer).properties.Keys })) {
        $InstallerManifest[$Key] = $SingletonManifest.$Key
      }
      $InstallerManifest['ManifestType'] = 'installer'
      # Parse default locale keys to default locale manifest
      $DefaultLocaleManifest = [ordered]@{}
      foreach ($Key in $SingletonManifest.Keys.Where({ $_ -cin (Get-WinGetManifestSchema -ManifestType locale).properties.Keys })) {
        $DefaultLocaleManifest[$Key] = $SingletonManifest.$Key
      }
      $DefaultLocaleManifest['ManifestType'] = 'defaultLocale'
      # Create locale manifests
      $LocaleManifests = @($DefaultLocaleManifest)
    } else {
      throw "Version ${LastVersion} does not contain the required manifests"
    }

    return [ordered]@{
      Installer = $InstallerManifest
      Locale    = $LocaleManifests
      Version   = $VersionManifest
    }
  }
}

function Convert-WinGetManifestContentToYaml {
  param (
    [Parameter(Position = 1, Mandatory)]
    [System.Collections.IDictionary]$Manifest,
    [Parameter(Position = 2, Mandatory)]
    [string]$SchemaUri
  )

  @"
${Script:ManifestHeader}
# yaml-language-server: `$schema=${SchemaUri}

$((ConvertTo-Yaml -Data $Manifest -Options DisableAliases).TrimEnd())

"@
}

function Convert-WinGetManifestsToYaml {
  <#
  .SYNOPSIS
    Write the new manifests for a WinGet package
  .DESCRIPTION
    Write the new manifests for a WinGet package using the provided version, installer and locale manifests
  .PARAMETER Manifests
    The manifest(s) to write
  #>
  [OutputType([System.Collections.Specialized.OrderedDictionary])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The manifest(s) to write')]
    [System.Object[]]$Manifests
  )

  process {
    $LocaleManifestContent = [System.Collections.Generic.OrderedDictionary[string, string]]::new()
    $Manifests.Locale | ForEach-Object -Process { $LocaleManifestContent[$_.PackageLocale] = Convert-WinGetManifestContentToYaml -Manifest $_ -SchemaUri (Get-WinGetManifestSchemaUrl -ManifestType ($_.ManifestType -ceq 'defaultLocale' ? 'defaultLocale' : 'locale')) }

    [ordered]@{
      Installer = Convert-WinGetManifestContentToYaml -Manifest $Manifests.Installer -SchemaUri (Get-WinGetManifestSchemaUrl -ManifestType 'installer')
      Locale    = $LocaleManifestContent
      Version   = Convert-WinGetManifestContentToYaml -Manifest $Manifests.Version -Schema (Get-WinGetManifestSchemaUrl -ManifestType 'version')
    }
  }
}

Export-ModuleMember -Function '*' -Variable 'WinGetUserAgent', 'WinGetBackupUserAgent', 'WinGetInstallerFiles'
