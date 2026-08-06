# SPDX-License-Identifier: Apache-2.0
# Provider-neutral Add/Remove Programs and MSI installation-context evidence.

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }
Set-StrictMode -Version 3

$script:ArpSubKeyPath = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
$script:MsiUpgradeCodesSubKeyPath = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UpgradeCodes'
$script:MsiUserDataSubKeyPath = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData'

function Get-ARPRecordValue {
  param (
    [Parameter()]
    $InputObject,

    [Parameter(Mandatory)]
    [string]$Key
  )

  if ($null -eq $InputObject) { return $null }

  if ($InputObject -is [System.Collections.IDictionary]) {
    if ($InputObject.Contains($Key)) { return $InputObject[$Key] }
    return $null
  }

  $Property = $InputObject.PSObject.Properties[$Key]
  if ($Property) { return $Property.Value }

  return $null
}

function ConvertFrom-MsiPackedGuid {
  <#
  .SYNOPSIS
    Convert an MSI packed registry GUID to normal GUID format
  .PARAMETER PackedGuid
    The packed 32-character MSI registry GUID
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The packed 32-character MSI registry GUID')]
    [string]$PackedGuid
  )

  process {
    if ($PackedGuid -cnotmatch '^[0-9A-Fa-f]{32}$') { return $null }

    $Map = @(8, 7, 6, 5, 4, 3, 2, 1, 13, 12, 11, 10, 18, 17, 16, 15, 21, 20, 23, 22, 26, 25, 28, 27, 30, 29, 32, 31, 34, 33, 36, 35)
    $Unpacked = [char[]]'{00000000-0000-0000-0000-000000000000}'

    for ($Index = 0; $Index -lt $PackedGuid.Length; $Index++) {
      $Unpacked[$Map[$Index]] = [char]::ToUpperInvariant($PackedGuid[$Index])
    }

    [string]::new($Unpacked)
  }
}

function ConvertTo-MsiPackedGuid {
  <#
  .SYNOPSIS
    Convert a normal GUID to the MSI packed registry GUID format
  .PARAMETER Guid
    The GUID to pack
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The GUID to pack')]
    [string]$Guid
  )

  process {
    $NormalizedGuid = $Guid.Trim()
    if ($NormalizedGuid -cnotmatch '^\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?$') {
      return $null
    }

    $Unpacked = [char[]]($NormalizedGuid.Trim('{', '}').ToUpperInvariant())
    $Packed = [char[]]'00000000000000000000000000000000'
    $Map = @(8, 7, 6, 5, 4, 3, 2, 1, 13, 12, 11, 10, 18, 17, 16, 15, 21, 20, 23, 22, 26, 25, 28, 27, 30, 29, 32, 31, 34, 33, 36, 35)

    for ($Index = 0; $Index -lt $Map.Count; $Index++) {
      $Packed[$Index] = $Unpacked[$Map[$Index] - 1]
    }

    [string]::new($Packed)
  }
}

function Get-CurrentUserSid {
  [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
}

function Get-MsiUpgradeCodeMap {
  $Map = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  $BaseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)

  try {
    $UpgradeCodesKey = $BaseKey.OpenSubKey($script:MsiUpgradeCodesSubKeyPath)
    if (-not $UpgradeCodesKey) { return $Map }

    try {
      foreach ($PackedUpgradeCode in $UpgradeCodesKey.GetSubKeyNames()) {
        $UpgradeCode = ConvertFrom-MsiPackedGuid -PackedGuid $PackedUpgradeCode
        if (-not $UpgradeCode) { continue }

        $UpgradeCodeKey = $UpgradeCodesKey.OpenSubKey($PackedUpgradeCode)
        if (-not $UpgradeCodeKey) { continue }

        try {
          foreach ($PackedProductCode in $UpgradeCodeKey.GetValueNames()) {
            $ProductCode = ConvertFrom-MsiPackedGuid -PackedGuid $PackedProductCode
            if ($ProductCode) { $Map[$ProductCode] = $UpgradeCode }
          }
        } finally {
          $UpgradeCodeKey.Dispose()
        }
      }
    } finally {
      $UpgradeCodesKey.Dispose()
    }
  } finally {
    $BaseKey.Dispose()
  }

  return $Map
}

function Get-MsiUserDataProductEntry {
  <#
  .SYNOPSIS
    Find MSI Installer\UserData product entries for a ProductCode
  .DESCRIPTION
    Inspect HKLM Installer\UserData SID keys to find whether the MSI product appears under S-1-5-18, the current user SID, or another user SID.
    This is additional Dumplings validation evidence and is not currently used by WinGet matching.
  .PARAMETER ProductCode
    The MSI ProductCode to find
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The MSI ProductCode to find')]
    [string]$ProductCode
  )

  begin {
    $CurrentUserSid = Get-CurrentUserSid
  }

  process {
    $PackedProductCode = ConvertTo-MsiPackedGuid -Guid $ProductCode
    if ([string]::IsNullOrWhiteSpace($PackedProductCode)) { return }

    $BaseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    try {
      $UserDataKey = $BaseKey.OpenSubKey($script:MsiUserDataSubKeyPath)
      if (-not $UserDataKey) { return }

      try {
        foreach ($Sid in $UserDataKey.GetSubKeyNames()) {
          $ProductSubKeyPath = "$Sid\Products\$PackedProductCode"
          $ProductKey = $UserDataKey.OpenSubKey($ProductSubKeyPath)
          if (-not $ProductKey) { continue }

          try {
            $InstallPropertiesKey = $ProductKey.OpenSubKey('InstallProperties')
            try {
              $Context = if ($Sid -ceq 'S-1-5-18') {
                'machine'
              } elseif ($Sid -ceq $CurrentUserSid) {
                'user'
              } else {
                'otherUser'
              }

              [pscustomobject]@{
                ProductCode       = $ProductCode
                PackedProductCode = $PackedProductCode
                Sid               = $Sid
                Context           = $Context
                IsMachine         = $Sid -ceq 'S-1-5-18'
                IsCurrentUser     = $Sid -ceq $CurrentUserSid
                RegistryPath      = "HKLM\$script:MsiUserDataSubKeyPath\$ProductSubKeyPath"
                DisplayName       = $InstallPropertiesKey ? (Get-ARPRegistryStringValue -Key $InstallPropertiesKey -Name 'DisplayName') : $null
                Publisher         = $InstallPropertiesKey ? (Get-ARPRegistryStringValue -Key $InstallPropertiesKey -Name 'Publisher') : $null
                DisplayVersion    = $InstallPropertiesKey ? (Get-ARPRegistryStringValue -Key $InstallPropertiesKey -Name 'DisplayVersion') : $null
                LocalPackage      = $InstallPropertiesKey ? (Get-ARPRegistryStringValue -Key $InstallPropertiesKey -Name 'LocalPackage' -AllowExpandString) : $null
              }
            } finally {
              if ($InstallPropertiesKey) { $InstallPropertiesKey.Dispose() }
            }
          } finally {
            $ProductKey.Dispose()
          }
        }
      } finally {
        $UserDataKey.Dispose()
      }
    } finally {
      $BaseKey.Dispose()
    }
  }
}

function Resolve-MsiARPInstallContext {
  <#
  .SYNOPSIS
    Resolve MSI ARP install context from Installer\UserData evidence
  .DESCRIPTION
    Classify MSI ProductCode evidence as machine, user, otherUser, mixed, or unknown based on Installer\UserData SID keys.
    S-1-5-18 indicates machine context. The current user SID indicates current-user context. Any other SID indicates another user's context.
  .PARAMETER ProductCode
    The MSI ProductCode to classify
  .PARAMETER UserDataEntry
    Pre-collected UserData entries, mainly for tests or offline analysis
  .PARAMETER CurrentUserSid
    The current user SID used to classify user versus otherUser
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The MSI ProductCode to classify')]
    [string]$ProductCode,

    [Parameter(Position = 1, ValueFromPipeline, HelpMessage = 'Pre-collected UserData entries, mainly for tests or offline analysis')]
    [psobject[]]$UserDataEntry,

    [Parameter(HelpMessage = 'The current user SID used to classify user versus otherUser')]
    [string]$CurrentUserSid = (Get-CurrentUserSid)
  )

  begin {
    $Entries = [System.Collections.Generic.List[psobject]]::new()
  }

  process {
    if ($UserDataEntry) {
      foreach ($Entry in $UserDataEntry) { $Entries.Add($Entry) }
    }
  }

  end {
    if ($Entries.Count -eq 0 -and -not $PSBoundParameters.ContainsKey('UserDataEntry')) {
      foreach ($Entry in Get-MsiUserDataProductEntry -ProductCode $ProductCode) { $Entries.Add($Entry) }
    }

    $MachineEntries = @($Entries | Where-Object -FilterScript { (Get-ARPRecordValue -InputObject $_ -Key 'Sid') -ceq 'S-1-5-18' -or (Get-ARPRecordValue -InputObject $_ -Key 'Context') -ceq 'machine' })
    $CurrentUserEntries = @($Entries | Where-Object -FilterScript {
        $Sid = Get-ARPRecordValue -InputObject $_ -Key 'Sid'
        ($Sid -and $Sid -ceq $CurrentUserSid) -or (Get-ARPRecordValue -InputObject $_ -Key 'Context') -ceq 'user'
      })
    $OtherUserEntries = @($Entries | Where-Object -FilterScript {
        $Sid = Get-ARPRecordValue -InputObject $_ -Key 'Sid'
        ($Sid -and $Sid -cne 'S-1-5-18' -and $Sid -cne $CurrentUserSid) -or (Get-ARPRecordValue -InputObject $_ -Key 'Context') -ceq 'otherUser'
      })

    $Context = if ($MachineEntries.Count -gt 0 -and $CurrentUserEntries.Count -eq 0 -and $OtherUserEntries.Count -eq 0) {
      'machine'
    } elseif ($MachineEntries.Count -eq 0 -and $CurrentUserEntries.Count -gt 0 -and $OtherUserEntries.Count -eq 0) {
      'user'
    } elseif ($MachineEntries.Count -eq 0 -and $CurrentUserEntries.Count -eq 0 -and $OtherUserEntries.Count -gt 0) {
      'otherUser'
    } elseif ($Entries.Count -gt 0) {
      'mixed'
    } else {
      'unknown'
    }

    [pscustomobject]@{
      ProductCode     = $ProductCode
      InstallContext  = $Context
      IsMachine       = $MachineEntries.Count -gt 0
      IsCurrentUser   = $CurrentUserEntries.Count -gt 0
      IsOtherUser     = $OtherUserEntries.Count -gt 0
      MachineSid      = $MachineEntries.Count -gt 0 ? 'S-1-5-18' : $null
      CurrentUserSid  = $CurrentUserEntries.Count -gt 0 ? $CurrentUserSid : $null
      OtherUserSids   = @($OtherUserEntries | ForEach-Object -Process { Get-ARPRecordValue -InputObject $_ -Key 'Sid' } | Where-Object -FilterScript { $_ } | Sort-Object -Unique)
      UserDataEntries = $Entries.ToArray()
    }
  }
}

function Get-ARPRegistryValue {
  param (
    [Parameter(Mandatory)]
    [Microsoft.Win32.RegistryKey]$Key,

    [Parameter(Mandatory)]
    [string]$Name,

    [Parameter()]
    [Microsoft.Win32.RegistryValueKind[]]$Kind
  )

  try {
    $ValueKind = $Key.GetValueKind($Name)
  } catch {
    return $null
  }

  if ($Kind -and $ValueKind -cnotin $Kind) { return $null }

  [pscustomobject]@{
    Kind  = $ValueKind
    Value = $Key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
  }
}

function Get-ARPRegistryStringValue {
  param (
    [Parameter(Mandatory)]
    [Microsoft.Win32.RegistryKey]$Key,

    [Parameter(Mandatory)]
    [string]$Name,

    [Parameter()]
    [switch]$AllowExpandString
  )

  $Kinds = $AllowExpandString ? @([Microsoft.Win32.RegistryValueKind]::String, [Microsoft.Win32.RegistryValueKind]::ExpandString) : @([Microsoft.Win32.RegistryValueKind]::String)
  $Value = Get-ARPRegistryValue -Key $Key -Name $Name -Kind $Kinds
  if ($null -eq $Value) { return $null }

  [string]$Value.Value
}

function Get-ARPRegistryDWordValue {
  param (
    [Parameter(Mandatory)]
    [Microsoft.Win32.RegistryKey]$Key,

    [Parameter(Mandatory)]
    [string]$Name
  )

  $Value = Get-ARPRegistryValue -Key $Key -Name $Name -Kind ([Microsoft.Win32.RegistryValueKind]::DWord)
  if ($null -eq $Value) { return $null }

  [uint32]$Value.Value
}

function Get-ARPDisplayVersion {
  param (
    [Parameter(Mandatory)]
    [Microsoft.Win32.RegistryKey]$Key
  )

  $DisplayVersion = Get-ARPRegistryStringValue -Key $Key -Name 'DisplayVersion'
  if (-not [string]::IsNullOrEmpty($DisplayVersion)) { return $DisplayVersion }

  foreach ($Pair in @(@('VersionMajor', 'VersionMinor'), @('MajorVersion', 'MinorVersion'))) {
    $Major = Get-ARPRegistryDWordValue -Key $Key -Name $Pair[0]
    $Minor = Get-ARPRegistryDWordValue -Key $Key -Name $Pair[1]
    if ($null -ne $Major -or $null -ne $Minor) {
      $Major = $null -ne $Major ? $Major : 0
      $Minor = $null -ne $Minor ? $Minor : 0
      if ($Major -ne 0 -or $Minor -ne 0) { return "${Major}.${Minor}" }
    }
  }

  $Version = Get-ARPRegistryDWordValue -Key $Key -Name 'Version'
  if ($null -ne $Version -and $Version -ne 0) {
    return "$(($Version -band 0xFF000000) -shr 24).$(($Version -band 0x00FF0000) -shr 16).$($Version -band 0x0000FFFF)"
  }

  return 'Unknown'
}

function ConvertTo-Bcp47Tag {
  param (
    [Parameter()]
    [uint32]$LocaleId
  )

  if ($LocaleId -eq 0) { return $null }

  try {
    [System.Globalization.CultureInfo]::GetCultureInfo([int]$LocaleId).Name
  } catch {
    $null
  }
}

function Get-ARPRegistryRoot {
  $Roots = [System.Collections.Generic.List[pscustomobject]]::new()
  $Is64Bit = [Environment]::Is64BitOperatingSystem
  $NativeArchitecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()

  if ($Is64Bit) {
    # WinGet reads native machine-scope ARP entries from the 64-bit registry view.
    $Roots.Add([pscustomobject]@{
        Hive             = [Microsoft.Win32.RegistryHive]::LocalMachine
        HiveName         = 'HKLM'
        Scope            = 'machine'
        RegistryView     = [Microsoft.Win32.RegistryView]::Registry64
        RegistryViewName = '64-bit'
        ArchitectureView = $NativeArchitecture
        RegistryPath     = "HKLM\$script:ArpSubKeyPath"
      })

    # WinGet reads x86 machine-scope ARP entries from the 32-bit registry view.
    $Roots.Add([pscustomobject]@{
        Hive             = [Microsoft.Win32.RegistryHive]::LocalMachine
        HiveName         = 'HKLM'
        Scope            = 'machine'
        RegistryView     = [Microsoft.Win32.RegistryView]::Registry32
        RegistryViewName = '32-bit'
        ArchitectureView = 'x86'
        RegistryPath     = 'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
      })

    # WinGet does not enumerate a separate x86 user-scope ARP view.
    $Roots.Add([pscustomobject]@{
        Hive             = [Microsoft.Win32.RegistryHive]::CurrentUser
        HiveName         = 'HKCU'
        Scope            = 'user'
        RegistryView     = [Microsoft.Win32.RegistryView]::Registry64
        RegistryViewName = '64-bit'
        ArchitectureView = $NativeArchitecture
        RegistryPath     = "HKCU\$script:ArpSubKeyPath"
      })
  } else {
    $ProcessArchitecture = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString().ToLowerInvariant()

    $Roots.Add([pscustomobject]@{
        Hive             = [Microsoft.Win32.RegistryHive]::LocalMachine
        HiveName         = 'HKLM'
        Scope            = 'machine'
        RegistryView     = [Microsoft.Win32.RegistryView]::Default
        RegistryViewName = 'default'
        ArchitectureView = $ProcessArchitecture
        RegistryPath     = "HKLM\$script:ArpSubKeyPath"
      })

    $Roots.Add([pscustomobject]@{
        Hive             = [Microsoft.Win32.RegistryHive]::CurrentUser
        HiveName         = 'HKCU'
        Scope            = 'user'
        RegistryView     = [Microsoft.Win32.RegistryView]::Default
        RegistryViewName = 'default'
        ArchitectureView = $ProcessArchitecture
        RegistryPath     = "HKCU\$script:ArpSubKeyPath"
      })
  }

  $Roots
}

function Get-InstalledARPEntry {
  <#
  .SYNOPSIS
    Collect WinGet-visible non-AppX/MSIX installed entries from Add/Remove Programs registry keys
  .DESCRIPTION
    Collect visible ARP entries using the same registry roots and filtering rules that winget-cli uses for its predefined ARP source.
    Entries with SystemComponent set to a non-zero DWORD are skipped unless IncludeSystemComponent is specified.
  .PARAMETER IncludeSystemComponent
    Include entries hidden from WinGet's installed source by SystemComponent=1
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(HelpMessage = 'Include entries hidden from WinGet installed source by SystemComponent=1')]
    [switch]$IncludeSystemComponent
  )

  $UpgradeCodes = Get-MsiUpgradeCodeMap

  foreach ($Root in Get-ARPRegistryRoot) {
    $BaseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey($Root.Hive, $Root.RegistryView)
    try {
      $UninstallKey = $BaseKey.OpenSubKey($script:ArpSubKeyPath)
      if (-not $UninstallKey) { continue }

      try {
        foreach ($ProductCode in $UninstallKey.GetSubKeyNames()) {
          $EntryKey = $UninstallKey.OpenSubKey($ProductCode)
          if (-not $EntryKey) { continue }

          try {
            $SystemComponentValue = Get-ARPRegistryDWordValue -Key $EntryKey -Name 'SystemComponent'
            $SystemComponent = $null -ne $SystemComponentValue -and $SystemComponentValue -ne 0
            if ($SystemComponent -and -not $IncludeSystemComponent) { continue }

            # WinGet skips entries without a REG_SZ DisplayName.
            $DisplayName = Get-ARPRegistryStringValue -Key $EntryKey -Name 'DisplayName'
            if ([string]::IsNullOrEmpty($DisplayName)) { continue }

            $Publisher = Get-ARPRegistryStringValue -Key $EntryKey -Name 'Publisher'
            $DisplayVersion = Get-ARPRegistryStringValue -Key $EntryKey -Name 'DisplayVersion'
            $WindowsInstallerValue = Get-ARPRegistryDWordValue -Key $EntryKey -Name 'WindowsInstaller'
            $WindowsInstaller = $null -ne $WindowsInstallerValue -and $WindowsInstallerValue -ne 0
            $WinGetInstallerType = Get-ARPRegistryStringValue -Key $EntryKey -Name 'WinGetInstallerType'
            $InstallerType = if ($WindowsInstaller) { 'msi' } elseif ($WinGetInstallerType -ceq 'portable') { 'portable' } else { 'exe' }
            $UpgradeCode = $WindowsInstaller -and $UpgradeCodes.ContainsKey($ProductCode) ? $UpgradeCodes[$ProductCode] : $null
            $LanguageId = Get-ARPRegistryDWordValue -Key $EntryKey -Name 'Language'
            $NoModifyValue = Get-ARPRegistryDWordValue -Key $EntryKey -Name 'NoModify'
            $NoRepairValue = Get-ARPRegistryDWordValue -Key $EntryKey -Name 'NoRepair'
            $MsiInstallContext = $WindowsInstaller ? (Resolve-MsiARPInstallContext -ProductCode $ProductCode) : $null

            [pscustomobject]@{
              Source                    = 'ARP'
              ProductCode               = $ProductCode
              UpgradeCode               = $UpgradeCode
              PackageFamilyName         = $null
              DisplayName               = $DisplayName
              PackageName               = $DisplayName
              Publisher                 = $Publisher
              Version                   = Get-ARPDisplayVersion -Key $EntryKey
              DisplayVersion            = $DisplayVersion
              InstallerType             = $InstallerType
              WindowsInstaller          = $WindowsInstaller
              MsiInstallContext         = $MsiInstallContext ? $MsiInstallContext.InstallContext : $null
              MsiUserDataMachineSid     = $MsiInstallContext ? $MsiInstallContext.MachineSid : $null
              MsiUserDataCurrentUserSid = $MsiInstallContext ? $MsiInstallContext.CurrentUserSid : $null
              MsiUserDataOtherUserSids  = $MsiInstallContext ? $MsiInstallContext.OtherUserSids : @()
              Scope                     = $Root.Scope
              RegistryHive              = $Root.HiveName
              RegistryView              = $Root.RegistryViewName
              ArchitectureView          = $Root.ArchitectureView
              RegistryPath              = "$($Root.RegistryPath)\$ProductCode"
              IsSystemComponent         = $SystemComponent
              InstallLocation           = Get-ARPRegistryStringValue -Key $EntryKey -Name 'InstallLocation' -AllowExpandString
              UninstallString           = Get-ARPRegistryStringValue -Key $EntryKey -Name 'UninstallString' -AllowExpandString
              QuietUninstallString      = Get-ARPRegistryStringValue -Key $EntryKey -Name 'QuietUninstallString' -AllowExpandString
              ModifyPath                = Get-ARPRegistryStringValue -Key $EntryKey -Name 'ModifyPath' -AllowExpandString
              NoModify                  = $null -ne $NoModifyValue -and $NoModifyValue -ne 0
              NoRepair                  = $null -ne $NoRepairValue -and $NoRepairValue -ne 0
              Language                  = $LanguageId ? (ConvertTo-Bcp47Tag -LocaleId $LanguageId) : $null
            }
          } finally {
            $EntryKey.Dispose()
          }
        }
      } finally {
        $UninstallKey.Dispose()
      }
    } finally {
      $BaseKey.Dispose()
    }
  }
}

Export-ModuleMember -Function ConvertFrom-MsiPackedGuid, ConvertTo-MsiPackedGuid, Get-MsiUserDataProductEntry, Resolve-MsiARPInstallContext, Get-InstalledARPEntry
