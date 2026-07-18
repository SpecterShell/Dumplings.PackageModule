# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Force stop on error
$ErrorActionPreference = 'Stop'
# Force stop on undefined variables or properties
Set-StrictMode -Version 3

$script:WinGetArpSubKeyPath = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
$script:WinGetMsiUpgradeCodesSubKeyPath = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UpgradeCodes'
$script:WinGetMsiUserDataSubKeyPath = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData'
$script:WinGetLegalEntitySuffixes = @(
  'AB', 'AD', 'AG', 'APS', 'AS', 'ASA', 'BV', 'CO', 'COMPANY', 'CORP', 'CORPORATION', 'CV', 'DOO',
  'EV', 'GES', 'GESMBH', 'GMBH', 'HOLDING', 'HOLDINGS', 'INC', 'INCORPORATED', 'KG', 'KS', 'LIMITED',
  'LLC', 'LP', 'LTD', 'LTDA', 'MBH', 'NV', 'PLC', 'PS', 'PTY', 'PVT', 'SA', 'SARL', 'SC', 'SCA',
  'SL', 'SP', 'SPA', 'SRL', 'SRO', 'SUBSIDIARY'
)

function Get-WinGetDictionaryValue {
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

function ConvertTo-WinGetArray {
  param (
    [Parameter()]
    $InputObject
  )

  if ($null -eq $InputObject) { return @() }
  if ($InputObject -is [string]) { return @($InputObject) }
  if ($InputObject -is [System.Collections.IDictionary]) { return @($InputObject) }
  if ($InputObject -is [System.Collections.IEnumerable]) { return @($InputObject) }
  return @($InputObject)
}

function Add-WinGetUniqueString {
  param (
    [Parameter()]
    [System.Collections.Generic.List[string]]$List,

    [Parameter()]
    [System.Collections.Generic.HashSet[string]]$Set,

    [Parameter()]
    $Value
  )

  if ($null -eq $Value) { return }

  $StringValue = [string]$Value
  if ([string]::IsNullOrWhiteSpace($StringValue)) { return }

  if ($Set.Add($StringValue)) { $List.Add($StringValue) }
}

function ConvertFrom-WinGetMsiPackedGuid {
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

function ConvertTo-WinGetMsiPackedGuid {
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

function Get-WinGetCurrentUserSid {
  [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
}

function Get-WinGetMsiUpgradeCodeMap {
  $Map = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  $BaseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)

  try {
    $UpgradeCodesKey = $BaseKey.OpenSubKey($script:WinGetMsiUpgradeCodesSubKeyPath)
    if (-not $UpgradeCodesKey) { return $Map }

    try {
      foreach ($PackedUpgradeCode in $UpgradeCodesKey.GetSubKeyNames()) {
        $UpgradeCode = ConvertFrom-WinGetMsiPackedGuid -PackedGuid $PackedUpgradeCode
        if (-not $UpgradeCode) { continue }

        $UpgradeCodeKey = $UpgradeCodesKey.OpenSubKey($PackedUpgradeCode)
        if (-not $UpgradeCodeKey) { continue }

        try {
          foreach ($PackedProductCode in $UpgradeCodeKey.GetValueNames()) {
            $ProductCode = ConvertFrom-WinGetMsiPackedGuid -PackedGuid $PackedProductCode
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

function Get-WinGetMsiUserDataProductEntry {
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
    $CurrentUserSid = Get-WinGetCurrentUserSid
  }

  process {
    $PackedProductCode = ConvertTo-WinGetMsiPackedGuid -Guid $ProductCode
    if ([string]::IsNullOrWhiteSpace($PackedProductCode)) { return }

    $BaseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    try {
      $UserDataKey = $BaseKey.OpenSubKey($script:WinGetMsiUserDataSubKeyPath)
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
                RegistryPath      = "HKLM\$script:WinGetMsiUserDataSubKeyPath\$ProductSubKeyPath"
                DisplayName       = $InstallPropertiesKey ? (Get-WinGetRegistryStringValue -Key $InstallPropertiesKey -Name 'DisplayName') : $null
                Publisher         = $InstallPropertiesKey ? (Get-WinGetRegistryStringValue -Key $InstallPropertiesKey -Name 'Publisher') : $null
                DisplayVersion    = $InstallPropertiesKey ? (Get-WinGetRegistryStringValue -Key $InstallPropertiesKey -Name 'DisplayVersion') : $null
                LocalPackage      = $InstallPropertiesKey ? (Get-WinGetRegistryStringValue -Key $InstallPropertiesKey -Name 'LocalPackage' -AllowExpandString) : $null
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

function Resolve-WinGetMsiARPInstallContext {
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
    [string]$CurrentUserSid = (Get-WinGetCurrentUserSid)
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
      foreach ($Entry in Get-WinGetMsiUserDataProductEntry -ProductCode $ProductCode) { $Entries.Add($Entry) }
    }

    $MachineEntries = @($Entries | Where-Object -FilterScript { (Get-WinGetDictionaryValue -InputObject $_ -Key 'Sid') -ceq 'S-1-5-18' -or (Get-WinGetDictionaryValue -InputObject $_ -Key 'Context') -ceq 'machine' })
    $CurrentUserEntries = @($Entries | Where-Object -FilterScript {
        $Sid = Get-WinGetDictionaryValue -InputObject $_ -Key 'Sid'
        ($Sid -and $Sid -ceq $CurrentUserSid) -or (Get-WinGetDictionaryValue -InputObject $_ -Key 'Context') -ceq 'user'
      })
    $OtherUserEntries = @($Entries | Where-Object -FilterScript {
        $Sid = Get-WinGetDictionaryValue -InputObject $_ -Key 'Sid'
        ($Sid -and $Sid -cne 'S-1-5-18' -and $Sid -cne $CurrentUserSid) -or (Get-WinGetDictionaryValue -InputObject $_ -Key 'Context') -ceq 'otherUser'
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
      OtherUserSids   = @($OtherUserEntries | ForEach-Object -Process { Get-WinGetDictionaryValue -InputObject $_ -Key 'Sid' } | Where-Object -FilterScript { $_ } | Sort-Object -Unique)
      UserDataEntries = $Entries.ToArray()
    }
  }
}

function Get-WinGetRegistryValue {
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

function Get-WinGetRegistryStringValue {
  param (
    [Parameter(Mandatory)]
    [Microsoft.Win32.RegistryKey]$Key,

    [Parameter(Mandatory)]
    [string]$Name,

    [Parameter()]
    [switch]$AllowExpandString
  )

  $Kinds = $AllowExpandString ? @([Microsoft.Win32.RegistryValueKind]::String, [Microsoft.Win32.RegistryValueKind]::ExpandString) : @([Microsoft.Win32.RegistryValueKind]::String)
  $Value = Get-WinGetRegistryValue -Key $Key -Name $Name -Kind $Kinds
  if ($null -eq $Value) { return $null }

  [string]$Value.Value
}

function Get-WinGetRegistryDWordValue {
  param (
    [Parameter(Mandatory)]
    [Microsoft.Win32.RegistryKey]$Key,

    [Parameter(Mandatory)]
    [string]$Name
  )

  $Value = Get-WinGetRegistryValue -Key $Key -Name $Name -Kind ([Microsoft.Win32.RegistryValueKind]::DWord)
  if ($null -eq $Value) { return $null }

  [uint32]$Value.Value
}

function Get-WinGetArpDisplayVersion {
  param (
    [Parameter(Mandatory)]
    [Microsoft.Win32.RegistryKey]$Key
  )

  $DisplayVersion = Get-WinGetRegistryStringValue -Key $Key -Name 'DisplayVersion'
  if (-not [string]::IsNullOrEmpty($DisplayVersion)) { return $DisplayVersion }

  foreach ($Pair in @(@('VersionMajor', 'VersionMinor'), @('MajorVersion', 'MinorVersion'))) {
    $Major = Get-WinGetRegistryDWordValue -Key $Key -Name $Pair[0]
    $Minor = Get-WinGetRegistryDWordValue -Key $Key -Name $Pair[1]
    if ($null -ne $Major -or $null -ne $Minor) {
      $Major = $null -ne $Major ? $Major : 0
      $Minor = $null -ne $Minor ? $Minor : 0
      if ($Major -ne 0 -or $Minor -ne 0) { return "${Major}.${Minor}" }
    }
  }

  $Version = Get-WinGetRegistryDWordValue -Key $Key -Name 'Version'
  if ($null -ne $Version -and $Version -ne 0) {
    return "$(($Version -band 0xFF000000) -shr 24).$(($Version -band 0x00FF0000) -shr 16).$($Version -band 0x0000FFFF)"
  }

  return 'Unknown'
}

function ConvertTo-WinGetBcp47Tag {
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

function Get-WinGetArpRegistryRoot {
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
        RegistryPath     = "HKLM\$script:WinGetArpSubKeyPath"
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
        RegistryPath     = "HKCU\$script:WinGetArpSubKeyPath"
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
        RegistryPath     = "HKLM\$script:WinGetArpSubKeyPath"
      })

    $Roots.Add([pscustomobject]@{
        Hive             = [Microsoft.Win32.RegistryHive]::CurrentUser
        HiveName         = 'HKCU'
        Scope            = 'user'
        RegistryView     = [Microsoft.Win32.RegistryView]::Default
        RegistryViewName = 'default'
        ArchitectureView = $ProcessArchitecture
        RegistryPath     = "HKCU\$script:WinGetArpSubKeyPath"
      })
  }

  $Roots
}

function ConvertTo-WinGetNameWithoutNoise {
  param (
    [Parameter()]
    [string]$Value,

    [Parameter()]
    [switch]$Publisher
  )

  if ([string]::IsNullOrWhiteSpace($Value)) { return '' }

  $Result = $Value.Normalize([System.Text.NormalizationForm]::FormC).Trim()
  $AtIndex = $Result.IndexOf('@@', 3, [System.StringComparison]::Ordinal)
  if ($AtIndex -ge 0) { $Result = $Result.Substring(0, $AtIndex).Trim() }

  while ($Result.Length -ge 2 -and (($Result[0] -eq '"' -and $Result[-1] -eq '"') -or ($Result[0] -eq '(' -and $Result[-1] -eq ')'))) {
    $Result = $Result.Substring(1, $Result.Length - 2).Trim()
  }

  if (-not $Publisher) {
    $Result = $Result -replace '\((KB\d+)\)', '$1'
    $Result = $Result -replace '(?i)(?<=^|[^\p{L}\p{Nd}])((64[\\/]|32[\\/])?32[\\/ ]?64[\p{Pd}\p{Pc}\p{Z}]?bit)s?(?:\s+edition)?(?=\P{Nd}|$)', ' '
    $Result = $Result -replace '(?i)(?<=^|[^\p{L}\p{Nd}])(x64|amd64|x86[\p{Pd}\p{Pc}]64|64[\p{Pd}\p{Pc}\p{Z}]?bit)s?(?:\s+edition)?(?=\P{Nd}|$)', ' '
    $Result = $Result -replace '(?i)(?<=^|[^\p{L}\p{Nd}])(x32|x86|32[\p{Pd}\p{Pc}\p{Z}]?bit)s?(?:\s+edition)?(?=\P{Nd}|$)', ' '
    $Result = $Result -replace '(?i)(?<![A-Z])(?:[A-Z]{2,3}(?:-(?:CANS|CYRL|LATN|MONG))?-[A-Z]{2}(?:-VALENCIA)?)(?![A-Z])', ' '
    $Result = $Result -replace '(?i)^\(.*?\)', ' '
    $Result = $Result -replace '(?i)(\(\s*\)|\[\s*\]|"\s*")', ' '
    $Result = $Result -replace '(?i)\(change #\d{1,2} to [CDEF]:\\(.+?\\)*[^\s]*\\?\)', ' '
    $Result = $Result -replace '(?i)\([CDEF]:\\(.+?\\)*[^\s]*\\?\)', ' '
    $Result = $Result -replace '(?i)"[CDEF]:\\(.+?\\)*[^\s]*\\?"', ' '
    $Result = $Result -replace '(?i)((installed\s+at|in)\s+)?[CDEF]:\\(.+?\\)*[^\s]*\\?', ' '
    $Result = $Result -replace '(?i)(?<!\p{L})(?:http[s]?|ftp)://', ' '
    $Result = $Result -replace '(?i)((?<!\p{L})(?:v|ver|version|versie|wersja|build|release|rc|sp)\P{L}?)?\p{Nd}+([\p{Po}\p{Pd}\p{Pc}]\p{Nd}?(rc|b|a|r|sp|k)?\p{Nd}+)+([\p{Po}\p{Pd}\p{Pc}]?[\p{L}\p{Nd}]+)*', ' '
    $Result = $Result -replace '(?i)(for\s)?(?<!\p{L})(?:p|v|r|ver|version|versie|wersja|build|release|rc|sp)(?:\P{L}|\P{L}\p{L})?(\p{Nd}|\.\p{Nd})+(?:rc|b|a|r|v|sp)?\p{Nd}?', ' '
    $Result = $Result -replace '(?i)(?<!\p{L})(?:(?:v|ver|version|versie|wersja|build|release|rc|sp)\P{L})?\p{Lu}\p{Nd}+(?:[\p{Po}\p{Pd}\p{Pc}]\p{Nd}+)+', ' '
    $Result = $Result -replace '(?i)\([^\(\)]*\)|\[[^\[\]]*\]', ' '
    $Result = $Result -replace '(?i)(?:\p{Ps}.*\p{Pe}|".*")', ' '
    $Result = $Result -replace '(?i)\sEN\s*$', ' '
    $Result = $Result -replace '^[^\p{L}\p{Nd}]+', ' '
    $Result = $Result -replace '[^\p{L}\p{Nd}]+$', ' '
  } else {
    $Result = $Result -replace '(?i)(?<!\p{L})(?:http[s]?|ftp)://', ' '
    $Result = $Result -replace '(?i)((?<!\p{L})(?:v|ver|version|versie|wersja|build|release|rc|sp)\P{L}?)?\p{Nd}+([\p{Po}\p{Pd}\p{Pc}]\p{Nd}?(rc|b|a|r|sp|k)?\p{Nd}+)+([\p{Po}\p{Pd}\p{Pc}]?[\p{L}\p{Nd}]+)*', ' '
    $Result = $Result -replace '(?i)(for\s)?(?<!\p{L})(?:p|v|r|ver|version|versie|wersja|build|release|rc|sp)(?:\P{L}|\P{L}\p{L})?(\p{Nd}|\.\p{Nd})+(?:rc|b|a|r|v|sp)?\p{Nd}?', ' '
    $Result = $Result -replace '(?i)\([^\(\)]*\)|\[[^\[\]]*\]', ' '
    $Result = $Result -replace '(?i)(?:\p{Ps}.*\p{Pe}|".*")', ' '
    $Result = $Result -replace '(?i)(?<=^|\s)[^\p{L}]+(?=\s|$)', ' '
    $Result = $Result -replace '\P{L}+$', ' '
  }

  return $Result.Trim()
}

function ConvertTo-WinGetNormalizedTokenString {
  param (
    [Parameter()]
    [string]$Value,

    [Parameter()]
    [switch]$Publisher
  )

  $Cleaned = ConvertTo-WinGetNameWithoutNoise -Value $Value -Publisher:$Publisher
  if ([string]::IsNullOrWhiteSpace($Cleaned)) { return '' }

  $SplitExpression = $Publisher ? '[^\p{L}\p{Nd}]+' : '[^\p{L}\p{Nd}\+&]+'
  $Tokens = [regex]::Split($Cleaned, $SplitExpression) | Where-Object -FilterScript { -not [string]::IsNullOrWhiteSpace($_) }

  $Output = [System.Collections.Generic.List[string]]::new()
  foreach ($Token in $Tokens) {
    $FoldedToken = $Token.ToUpperInvariant()

    if ($Output.Count -gt 0 -and $script:WinGetLegalEntitySuffixes -ccontains $FoldedToken) {
      if ($Publisher) { break }
      continue
    }

    $Output.Add($Token)
  }

  ([string]::Concat($Output) -replace '[^\p{L}\p{Nd}]', '')
}

function ConvertTo-WinGetNormalizedNameAndPublisher {
  <#
  .SYNOPSIS
    Generate a WinGet-style normalized name and publisher pair
  .DESCRIPTION
    Generate the normalized package name, normalized publisher, and combined normalized pair used by Dumplings installed-entry matching.
    This follows WinGet's NameNormalizer behavior closely enough for validation workflows, but WinGet itself remains the authority for final repository matching.
  .PARAMETER Name
    The package display name to normalize
  .PARAMETER Publisher
    The package publisher to normalize
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, Mandatory, ValueFromPipelineByPropertyName, HelpMessage = 'The package display name to normalize')]
    [Alias('DisplayName', 'PackageName')]
    [string]$Name,

    [Parameter(Position = 1, ValueFromPipelineByPropertyName, HelpMessage = 'The package publisher to normalize')]
    [AllowNull()]
    [string]$Publisher
  )

  process {
    $NormalizedName = ConvertTo-WinGetNormalizedTokenString -Value $Name
    $NormalizedPublisher = ConvertTo-WinGetNormalizedTokenString -Value $Publisher -Publisher

    [pscustomobject]@{
      Name                       = $Name
      Publisher                  = $Publisher
      NormalizedName             = $NormalizedName
      NormalizedPublisher        = $NormalizedPublisher
      NormalizedNameAndPublisher = "${NormalizedPublisher}.${NormalizedName}"
    }
  }
}

function Get-WinGetInstalledARPEntry {
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

  $UpgradeCodes = Get-WinGetMsiUpgradeCodeMap

  foreach ($Root in Get-WinGetArpRegistryRoot) {
    $BaseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey($Root.Hive, $Root.RegistryView)
    try {
      $UninstallKey = $BaseKey.OpenSubKey($script:WinGetArpSubKeyPath)
      if (-not $UninstallKey) { continue }

      try {
        foreach ($ProductCode in $UninstallKey.GetSubKeyNames()) {
          $EntryKey = $UninstallKey.OpenSubKey($ProductCode)
          if (-not $EntryKey) { continue }

          try {
            $SystemComponentValue = Get-WinGetRegistryDWordValue -Key $EntryKey -Name 'SystemComponent'
            $SystemComponent = $null -ne $SystemComponentValue -and $SystemComponentValue -ne 0
            if ($SystemComponent -and -not $IncludeSystemComponent) { continue }

            # WinGet skips entries without a REG_SZ DisplayName.
            $DisplayName = Get-WinGetRegistryStringValue -Key $EntryKey -Name 'DisplayName'
            if ([string]::IsNullOrEmpty($DisplayName)) { continue }

            $Publisher = Get-WinGetRegistryStringValue -Key $EntryKey -Name 'Publisher'
            $DisplayVersion = Get-WinGetRegistryStringValue -Key $EntryKey -Name 'DisplayVersion'
            $WindowsInstallerValue = Get-WinGetRegistryDWordValue -Key $EntryKey -Name 'WindowsInstaller'
            $WindowsInstaller = $null -ne $WindowsInstallerValue -and $WindowsInstallerValue -ne 0
            $WinGetInstallerType = Get-WinGetRegistryStringValue -Key $EntryKey -Name 'WinGetInstallerType'
            $InstallerType = if ($WindowsInstaller) { 'msi' } elseif ($WinGetInstallerType -ceq 'portable') { 'portable' } else { 'exe' }
            $UpgradeCode = $WindowsInstaller -and $UpgradeCodes.ContainsKey($ProductCode) ? $UpgradeCodes[$ProductCode] : $null
            $LanguageId = Get-WinGetRegistryDWordValue -Key $EntryKey -Name 'Language'
            $NoModifyValue = Get-WinGetRegistryDWordValue -Key $EntryKey -Name 'NoModify'
            $NoRepairValue = Get-WinGetRegistryDWordValue -Key $EntryKey -Name 'NoRepair'
            $MsiInstallContext = $WindowsInstaller ? (Resolve-WinGetMsiARPInstallContext -ProductCode $ProductCode) : $null
            $Normalized = ConvertTo-WinGetNormalizedNameAndPublisher -Name $DisplayName -Publisher $Publisher

            [pscustomobject]@{
              Source                     = 'ARP'
              ProductCode                = $ProductCode
              UpgradeCode                = $UpgradeCode
              PackageFamilyName          = $null
              DisplayName                = $DisplayName
              PackageName                = $DisplayName
              Publisher                  = $Publisher
              Version                    = Get-WinGetArpDisplayVersion -Key $EntryKey
              DisplayVersion             = $DisplayVersion
              InstallerType              = $InstallerType
              WindowsInstaller           = $WindowsInstaller
              MsiInstallContext          = $MsiInstallContext ? $MsiInstallContext.InstallContext : $null
              MsiUserDataMachineSid      = $MsiInstallContext ? $MsiInstallContext.MachineSid : $null
              MsiUserDataCurrentUserSid  = $MsiInstallContext ? $MsiInstallContext.CurrentUserSid : $null
              MsiUserDataOtherUserSids   = $MsiInstallContext ? $MsiInstallContext.OtherUserSids : @()
              Scope                      = $Root.Scope
              RegistryHive               = $Root.HiveName
              RegistryView               = $Root.RegistryViewName
              ArchitectureView           = $Root.ArchitectureView
              RegistryPath               = "$($Root.RegistryPath)\$ProductCode"
              IsSystemComponent          = $SystemComponent
              InstallLocation            = Get-WinGetRegistryStringValue -Key $EntryKey -Name 'InstallLocation' -AllowExpandString
              UninstallString            = Get-WinGetRegistryStringValue -Key $EntryKey -Name 'UninstallString' -AllowExpandString
              QuietUninstallString       = Get-WinGetRegistryStringValue -Key $EntryKey -Name 'QuietUninstallString' -AllowExpandString
              ModifyPath                 = Get-WinGetRegistryStringValue -Key $EntryKey -Name 'ModifyPath' -AllowExpandString
              NoModify                   = $null -ne $NoModifyValue -and $NoModifyValue -ne 0
              NoRepair                   = $null -ne $NoRepairValue -and $NoRepairValue -ne 0
              Language                   = $LanguageId ? (ConvertTo-WinGetBcp47Tag -LocaleId $LanguageId) : $null
              NormalizedName             = $Normalized.NormalizedName
              NormalizedPublisher        = $Normalized.NormalizedPublisher
              NormalizedNameAndPublisher = $Normalized.NormalizedNameAndPublisher
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

function Get-WinGetInstalledAppXEntry {
  <#
  .SYNOPSIS
    Collect installed AppX/MSIX packages for PackageFamilyName matching
  .DESCRIPTION
    Collect installed AppX/MSIX packages with Get-AppxPackage and return the PackageFamilyName values WinGet uses for AppX/MSIX matching.
  .PARAMETER AllUsers
    Query packages for all users. This may require elevation.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(HelpMessage = 'Query packages for all users. This may require elevation.')]
    [switch]$AllUsers
  )

  $Command = Get-Command -Name 'Get-AppxPackage' -ErrorAction 'SilentlyContinue'
  if (-not $Command) { return }

  $Parameters = @{}
  if ($AllUsers) { $Parameters['AllUsers'] = $true }

  Get-AppxPackage @Parameters | ForEach-Object -Process {
    $Publisher = [string]($_.PublisherDisplayName ?? $_.Publisher)
    $Normalized = ConvertTo-WinGetNormalizedNameAndPublisher -Name $_.Name -Publisher $Publisher

    [pscustomobject]@{
      Source                     = 'AppX'
      ProductCode                = $null
      UpgradeCode                = $null
      PackageFamilyName          = [string]$_.PackageFamilyName
      PackageFullName            = [string]$_.PackageFullName
      DisplayName                = [string]$_.Name
      PackageName                = [string]$_.Name
      Publisher                  = $Publisher
      Version                    = [string]$_.Version
      DisplayVersion             = [string]$_.Version
      InstallerType              = 'msix'
      Architecture               = [string]$_.Architecture
      Scope                      = $AllUsers ? 'allUsers' : 'user'
      IsFramework                = [bool]$_.IsFramework
      IsResourcePackage          = [bool]$_.IsResourcePackage
      NonRemovable               = [bool]$_.NonRemovable
      SignatureKind              = [string]$_.SignatureKind
      Status                     = [string]$_.Status
      InstallLocation            = [string]$_.InstallLocation
      PackageUserInformation     = $_.PackageUserInformation
      NormalizedName             = $Normalized.NormalizedName
      NormalizedPublisher        = $Normalized.NormalizedPublisher
      NormalizedNameAndPublisher = $Normalized.NormalizedNameAndPublisher
    }
  }
}

function Get-WinGetInstalledEntry {
  <#
  .SYNOPSIS
    Collect WinGet-matchable installed entries
  .DESCRIPTION
    Collect non-AppX/MSIX ARP entries and AppX/MSIX installed packages in the shape used by Dumplings dynamic validation.
  .PARAMETER Kind
    The installed entry source to collect
  .PARAMETER IncludeSystemComponent
    Include ARP entries hidden from WinGet's installed source by SystemComponent=1
  .PARAMETER AllUsers
    Query AppX/MSIX packages for all users. This may require elevation.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(HelpMessage = 'The installed entry source to collect')]
    [ValidateSet('All', 'ARP', 'AppX')]
    [string]$Kind = 'All',

    [Parameter(HelpMessage = 'Include ARP entries hidden from WinGet installed source by SystemComponent=1')]
    [switch]$IncludeSystemComponent,

    [Parameter(HelpMessage = 'Query AppX/MSIX packages for all users. This may require elevation.')]
    [switch]$AllUsers
  )

  if ($Kind -cin @('All', 'ARP')) { Get-WinGetInstalledARPEntry -IncludeSystemComponent:$IncludeSystemComponent }
  if ($Kind -cin @('All', 'AppX')) { Get-WinGetInstalledAppXEntry -AllUsers:$AllUsers }
}

function Get-WinGetManifestBundleForMatching {
  param (
    [Parameter(Mandatory)]
    $Manifest
  )

  # The logical model already contains effective authored installers. Adapt it
  # to the small internal view used by the matching helpers without rebuilding
  # a physical installer/default-locale manifest set.
  if ($Manifest.PSTypeNames -contains 'Dumplings.WinGet.ManifestModel') {
    $DefaultLocale = Copy-WinGetManifestValue -Value $Manifest.DefaultLocalization
    $DefaultLocale['ManifestType'] = 'defaultLocale'
    $Locales = [System.Collections.Generic.List[object]]::new()
    $Locales.Add($DefaultLocale)
    foreach ($Localization in @($Manifest.Localizations)) {
      $Locale = Copy-WinGetManifestValue -Value $Localization
      $Locale['ManifestType'] = 'locale'
      $Locales.Add($Locale)
    }
    return [pscustomobject]@{
      Installer = [ordered]@{ Installers = @($Manifest.Installers) }
      Locale    = $Locales.ToArray()
      Version   = [ordered]@{ DefaultLocale = [string]$Manifest.DefaultLocalization['PackageLocale'] }
    }
  }

  $InstallerManifest = Get-WinGetDictionaryValue -InputObject $Manifest -Key 'Installer'
  $LocaleManifests = Get-WinGetDictionaryValue -InputObject $Manifest -Key 'Locale'
  $VersionManifest = Get-WinGetDictionaryValue -InputObject $Manifest -Key 'Version'

  if ($InstallerManifest -and $VersionManifest) {
    return [pscustomobject]@{
      Installer = $InstallerManifest
      Locale    = ConvertTo-WinGetArray -InputObject $LocaleManifests
      Version   = $VersionManifest
    }
  }

  return [pscustomobject]@{
    Installer = $Manifest
    Locale    = @($Manifest)
    Version   = $Manifest
  }
}

function Get-WinGetManifestLocalizationForMatching {
  param (
    [Parameter(Mandatory)]
    $Bundle
  )

  $VersionManifest = $Bundle.Version
  $Locales = ConvertTo-WinGetArray -InputObject $Bundle.Locale
  $DefaultLocaleName = Get-WinGetDictionaryValue -InputObject $VersionManifest -Key 'DefaultLocale'
  if (-not $DefaultLocaleName) { $DefaultLocaleName = Get-WinGetDictionaryValue -InputObject $VersionManifest -Key 'PackageLocale' }

  $DefaultLocale = $Locales | Where-Object -FilterScript {
    (Get-WinGetDictionaryValue -InputObject $_ -Key 'ManifestType') -ceq 'defaultLocale' -or
    ($DefaultLocaleName -and (Get-WinGetDictionaryValue -InputObject $_ -Key 'PackageLocale') -ceq $DefaultLocaleName)
  } | Select-Object -First 1

  if (-not $DefaultLocale) {
    $DefaultLocale = $Locales | Where-Object -FilterScript { Get-WinGetDictionaryValue -InputObject $_ -Key 'PackageName' } | Select-Object -First 1
  }

  [pscustomobject]@{
    DefaultName      = [string](Get-WinGetDictionaryValue -InputObject $DefaultLocale -Key 'PackageName')
    DefaultPublisher = [string](Get-WinGetDictionaryValue -InputObject $DefaultLocale -Key 'Publisher')
    Localizations    = @($Locales | Where-Object -FilterScript { $_ -ne $DefaultLocale })
  }
}

function Get-WinGetManifestInstallersForMatching {
  param (
    [Parameter(Mandatory)]
    $InstallerManifest
  )

  $Installers = ConvertTo-WinGetArray -InputObject (Get-WinGetDictionaryValue -InputObject $InstallerManifest -Key 'Installers')
  foreach ($Installer in $Installers) {
    $MergedInstaller = [ordered]@{}

    if ($Installer -is [System.Collections.IDictionary]) {
      foreach ($Key in $Installer.Keys) { $MergedInstaller[$Key] = $Installer[$Key] }
    } else {
      foreach ($Property in $Installer.PSObject.Properties) { $MergedInstaller[$Property.Name] = $Property.Value }
    }

    # These fields can be authored at installer-manifest level and copied to installer entries by WinGet/Dumplings.
    foreach ($InheritedKey in @('PackageFamilyName', 'ProductCode', 'AppsAndFeaturesEntries')) {
      if (-not $MergedInstaller.Contains($InheritedKey)) {
        $InheritedValue = Get-WinGetDictionaryValue -InputObject $InstallerManifest -Key $InheritedKey
        if ($null -ne $InheritedValue) { $MergedInstaller[$InheritedKey] = $InheritedValue }
      }
    }

    $MergedInstaller
  }
}

function Add-WinGetManifestNamePair {
  param (
    [Parameter()]
    [System.Collections.Generic.List[pscustomobject]]$List,

    [Parameter()]
    [System.Collections.Generic.HashSet[string]]$Set,

    [Parameter()]
    [string]$Name,

    [Parameter()]
    [AllowNull()]
    [string]$Publisher,

    [Parameter()]
    [string]$Source
  )

  if ([string]::IsNullOrWhiteSpace($Name)) { return }

  $Normalized = ConvertTo-WinGetNormalizedNameAndPublisher -Name $Name -Publisher $Publisher
  if ($Set.Add($Normalized.NormalizedNameAndPublisher)) {
    $List.Add([pscustomobject]@{
        Source                     = $Source
        Name                       = $Name
        Publisher                  = $Publisher
        NormalizedName             = $Normalized.NormalizedName
        NormalizedPublisher        = $Normalized.NormalizedPublisher
        NormalizedNameAndPublisher = $Normalized.NormalizedNameAndPublisher
      })
  }
}

function Get-WinGetManifestMatchKey {
  <#
  .SYNOPSIS
    Build WinGet-style exact-match keys from manifests
  .DESCRIPTION
    Build the ProductCode, UpgradeCode, PackageFamilyName, and NormalizedNameAndPublisher candidates used to match installed entries.
    The input is the logical model returned by Read-WinGetManifest or
    ConvertFrom-WinGetManifestYaml.
  .PARAMETER Manifest
    The manifest object to inspect
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The manifest object to inspect')]
    $Manifest
  )

  process {
    $Bundle = Get-WinGetManifestBundleForMatching -Manifest $Manifest
    $Localization = Get-WinGetManifestLocalizationForMatching -Bundle $Bundle
    $Installers = @(Get-WinGetManifestInstallersForMatching -InstallerManifest $Bundle.Installer)

    $ProductCodes = [System.Collections.Generic.List[string]]::new()
    $ProductCodeSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $UpgradeCodes = [System.Collections.Generic.List[string]]::new()
    $UpgradeCodeSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $PackageFamilyNames = [System.Collections.Generic.List[string]]::new()
    $PackageFamilyNameSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $NamePairs = [System.Collections.Generic.List[pscustomobject]]::new()
    $NamePairSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    Add-WinGetManifestNamePair -List $NamePairs -Set $NamePairSet -Name $Localization.DefaultName -Publisher $Localization.DefaultPublisher -Source 'DefaultLocalization'

    foreach ($Locale in $Localization.Localizations) {
      $LocaleName = Get-WinGetDictionaryValue -InputObject $Locale -Key 'PackageName'
      $LocalePublisher = Get-WinGetDictionaryValue -InputObject $Locale -Key 'Publisher'
      if ($LocaleName -or $LocalePublisher) {
        Add-WinGetManifestNamePair -List $NamePairs -Set $NamePairSet -Name ($LocaleName ?? $Localization.DefaultName) -Publisher ($LocalePublisher ?? $Localization.DefaultPublisher) -Source 'Localization'
      }
    }

    foreach ($Installer in $Installers) {
      Add-WinGetUniqueString -List $ProductCodes -Set $ProductCodeSet -Value (Get-WinGetDictionaryValue -InputObject $Installer -Key 'ProductCode')
      Add-WinGetUniqueString -List $PackageFamilyNames -Set $PackageFamilyNameSet -Value (Get-WinGetDictionaryValue -InputObject $Installer -Key 'PackageFamilyName')

      foreach ($Entry in ConvertTo-WinGetArray -InputObject (Get-WinGetDictionaryValue -InputObject $Installer -Key 'AppsAndFeaturesEntries')) {
        $EntryDisplayName = Get-WinGetDictionaryValue -InputObject $Entry -Key 'DisplayName'
        $EntryPublisher = Get-WinGetDictionaryValue -InputObject $Entry -Key 'Publisher'

        if ($EntryDisplayName) {
          Add-WinGetManifestNamePair -List $NamePairs -Set $NamePairSet -Name $EntryDisplayName -Publisher ($EntryPublisher ?? $Localization.DefaultPublisher) -Source 'AppsAndFeaturesEntries'
        }

        Add-WinGetUniqueString -List $ProductCodes -Set $ProductCodeSet -Value (Get-WinGetDictionaryValue -InputObject $Entry -Key 'ProductCode')
        Add-WinGetUniqueString -List $UpgradeCodes -Set $UpgradeCodeSet -Value (Get-WinGetDictionaryValue -InputObject $Entry -Key 'UpgradeCode')
      }
    }

    [pscustomobject]@{
      PackageIdentifier          = [string](Get-WinGetDictionaryValue -InputObject $Bundle.Version -Key 'PackageIdentifier')
      PackageVersion             = [string](Get-WinGetDictionaryValue -InputObject $Bundle.Version -Key 'PackageVersion')
      ProductCodes               = $ProductCodes.ToArray()
      UpgradeCodes               = $UpgradeCodes.ToArray()
      PackageFamilyNames         = $PackageFamilyNames.ToArray()
      NormalizedNameAndPublisher = $NamePairs.ToArray()
    }
  }
}

function Find-WinGetManifestInstalledEntryMatch {
  <#
  .SYNOPSIS
    Find installed entries that can be matched by a WinGet manifest
  .DESCRIPTION
    Compare manifest exact-match keys against installed entries collected by Get-WinGetInstalledEntry or provided explicitly.
    This function reports ProductCode, UpgradeCode, PackageFamilyName, and NormalizedNameAndPublisher matches.
  .PARAMETER Manifest
    The manifest object to inspect
  .PARAMETER InstalledEntry
    Installed entries to check. If omitted, the current system is queried.
  .PARAMETER IncludeNonMatching
    Return all checked entries, including entries that did not match
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The manifest object to inspect')]
    $Manifest,

    [Parameter(Position = 1, ValueFromPipeline, HelpMessage = 'Installed entries to check. If omitted, the current system is queried.')]
    [psobject[]]$InstalledEntry,

    [Parameter(HelpMessage = 'Return all checked entries, including entries that did not match')]
    [switch]$IncludeNonMatching
  )

  begin {
    $Keys = Get-WinGetManifestMatchKey -Manifest $Manifest
    $ProductCodes = [System.Collections.Generic.HashSet[string]]::new([string[]]$Keys.ProductCodes, [System.StringComparer]::OrdinalIgnoreCase)
    $UpgradeCodes = [System.Collections.Generic.HashSet[string]]::new([string[]]$Keys.UpgradeCodes, [System.StringComparer]::OrdinalIgnoreCase)
    $PackageFamilyNames = [System.Collections.Generic.HashSet[string]]::new([string[]]$Keys.PackageFamilyNames, [System.StringComparer]::OrdinalIgnoreCase)
    $NormalizedNamePairs = [System.Collections.Generic.HashSet[string]]::new([string[]]($Keys.NormalizedNameAndPublisher | ForEach-Object -Process { $_.NormalizedNameAndPublisher }), [System.StringComparer]::OrdinalIgnoreCase)
    $Entries = [System.Collections.Generic.List[psobject]]::new()
  }

  process {
    if ($InstalledEntry) {
      foreach ($Entry in $InstalledEntry) { $Entries.Add($Entry) }
    }
  }

  end {
    if ($Entries.Count -eq 0 -and -not $PSBoundParameters.ContainsKey('InstalledEntry')) {
      foreach ($Entry in Get-WinGetInstalledEntry) { $Entries.Add($Entry) }
    }

    foreach ($Entry in $Entries) {
      $MatchedFields = [System.Collections.Generic.List[string]]::new()
      $MatchedValues = [ordered]@{}

      $ProductCode = [string](Get-WinGetDictionaryValue -InputObject $Entry -Key 'ProductCode')
      if (-not [string]::IsNullOrWhiteSpace($ProductCode) -and $ProductCodes.Contains($ProductCode)) {
        $MatchedFields.Add('ProductCode')
        $MatchedValues['ProductCode'] = $ProductCode
      }

      $UpgradeCode = [string](Get-WinGetDictionaryValue -InputObject $Entry -Key 'UpgradeCode')
      if (-not [string]::IsNullOrWhiteSpace($UpgradeCode) -and $UpgradeCodes.Contains($UpgradeCode)) {
        $MatchedFields.Add('UpgradeCode')
        $MatchedValues['UpgradeCode'] = $UpgradeCode
      }

      $PackageFamilyName = [string](Get-WinGetDictionaryValue -InputObject $Entry -Key 'PackageFamilyName')
      if (-not [string]::IsNullOrWhiteSpace($PackageFamilyName) -and $PackageFamilyNames.Contains($PackageFamilyName)) {
        $MatchedFields.Add('PackageFamilyName')
        $MatchedValues['PackageFamilyName'] = $PackageFamilyName
      }

      $NormalizedNameAndPublisher = [string](Get-WinGetDictionaryValue -InputObject $Entry -Key 'NormalizedNameAndPublisher')
      if ([string]::IsNullOrWhiteSpace($NormalizedNameAndPublisher)) {
        $Name = [string]((Get-WinGetDictionaryValue -InputObject $Entry -Key 'DisplayName') ?? (Get-WinGetDictionaryValue -InputObject $Entry -Key 'PackageName'))
        $Publisher = [string](Get-WinGetDictionaryValue -InputObject $Entry -Key 'Publisher')
        if (-not [string]::IsNullOrWhiteSpace($Name)) {
          $NormalizedNameAndPublisher = (ConvertTo-WinGetNormalizedNameAndPublisher -Name $Name -Publisher $Publisher).NormalizedNameAndPublisher
        }
      }

      if (-not [string]::IsNullOrWhiteSpace($NormalizedNameAndPublisher) -and $NormalizedNamePairs.Contains($NormalizedNameAndPublisher)) {
        $MatchedFields.Add('NormalizedNameAndPublisher')
        $MatchedValues['NormalizedNameAndPublisher'] = $NormalizedNameAndPublisher
      }

      if ($MatchedFields.Count -gt 0 -or $IncludeNonMatching) {
        [pscustomobject]@{
          IsMatch       = $MatchedFields.Count -gt 0
          MatchFields   = $MatchedFields.ToArray()
          MatchedValues = $MatchedValues
          Entry         = $Entry
        }
      }
    }
  }
}

function Test-WinGetManifestInstalledEntryMatch {
  <#
  .SYNOPSIS
    Test whether a manifest can match at least one installed entry
  .PARAMETER Manifest
    The manifest object to inspect
  .PARAMETER InstalledEntry
    Installed entries to check. If omitted, the current system is queried.
  #>
  [OutputType([bool])]
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'The manifest object to inspect')]
    $Manifest,

    [Parameter(Position = 1, ValueFromPipeline, HelpMessage = 'Installed entries to check. If omitted, the current system is queried.')]
    [psobject[]]$InstalledEntry
  )

  begin {
    $Entries = [System.Collections.Generic.List[psobject]]::new()
  }

  process {
    if ($InstalledEntry) {
      foreach ($Entry in $InstalledEntry) { $Entries.Add($Entry) }
    }
  }

  end {
    if ($PSBoundParameters.ContainsKey('InstalledEntry')) {
      return [bool](Find-WinGetManifestInstalledEntryMatch -Manifest $Manifest -InstalledEntry $Entries | Select-Object -First 1)
    }

    return [bool](Find-WinGetManifestInstalledEntryMatch -Manifest $Manifest | Select-Object -First 1)
  }
}

function Get-WinGetInstalledEntryIdentity {
  param (
    [Parameter(Mandatory)]
    $Entry
  )

  $Source = [string](Get-WinGetDictionaryValue -InputObject $Entry -Key 'Source')
  $Version = [string](Get-WinGetDictionaryValue -InputObject $Entry -Key 'Version')

  if ($Source -ceq 'AppX') {
    return "AppX|$((Get-WinGetDictionaryValue -InputObject $Entry -Key 'PackageFamilyName'))|${Version}"
  }

  return "ARP|$((Get-WinGetDictionaryValue -InputObject $Entry -Key 'Scope'))|$((Get-WinGetDictionaryValue -InputObject $Entry -Key 'ArchitectureView'))|$((Get-WinGetDictionaryValue -InputObject $Entry -Key 'ProductCode'))|${Version}"
}

function Compare-WinGetInstalledEntrySnapshot {
  <#
  .SYNOPSIS
    Compare installed-entry snapshots before and after installation
  .DESCRIPTION
    Compare snapshots from Get-WinGetInstalledEntry and return NewOrUpdated, Removed, and Unchanged entries using the same identity idea as winget-cli's ARP snapshot.
  .PARAMETER Before
    Installed entries collected before installation
  .PARAMETER After
    Installed entries collected after installation
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, Mandatory, HelpMessage = 'Installed entries collected before installation')]
    [psobject[]]$Before,

    [Parameter(Position = 1, Mandatory, HelpMessage = 'Installed entries collected after installation')]
    [psobject[]]$After
  )

  $BeforeMap = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  foreach ($Entry in $Before) { $null = $BeforeMap.Add((Get-WinGetInstalledEntryIdentity -Entry $Entry)) }

  $AfterMap = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  foreach ($Entry in $After) { $null = $AfterMap.Add((Get-WinGetInstalledEntryIdentity -Entry $Entry)) }

  foreach ($Entry in $After) {
    $Identity = Get-WinGetInstalledEntryIdentity -Entry $Entry
    [pscustomobject]@{
      Status   = $BeforeMap.Contains($Identity) ? 'Unchanged' : 'NewOrUpdated'
      Identity = $Identity
      Entry    = $Entry
    }
  }

  foreach ($Entry in $Before) {
    $Identity = Get-WinGetInstalledEntryIdentity -Entry $Entry
    if (-not $AfterMap.Contains($Identity)) {
      [pscustomobject]@{
        Status   = 'Removed'
        Identity = $Identity
        Entry    = $Entry
      }
    }
  }
}

Export-ModuleMember -Function Get-WinGetInstalledARPEntry, Get-WinGetInstalledAppXEntry, Get-WinGetInstalledEntry, ConvertTo-WinGetNormalizedNameAndPublisher, ConvertFrom-WinGetMsiPackedGuid, ConvertTo-WinGetMsiPackedGuid, Get-WinGetMsiUserDataProductEntry, Resolve-WinGetMsiARPInstallContext, Get-WinGetManifestMatchKey, Find-WinGetManifestInstalledEntryMatch, Test-WinGetManifestInstalledEntryMatch, Compare-WinGetInstalledEntrySnapshot
