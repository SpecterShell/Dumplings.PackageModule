# Static Windows protocol and file-extension association helpers. These
# functions interpret explicit registry writes only; they never query or modify
# the local registry and never infer associations from arbitrary strings.

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

function ConvertTo-InstallerClassRegistryWrite {
  <#
  .SYNOPSIS
    Normalize an explicit registry write beneath Windows Classes roots
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][psobject]$RegistryWrite)

  $Root = [string]$RegistryWrite.Root
  $Key = [string]$RegistryWrite.Key
  if ($Key -match '^(?<Root>HKEY_CLASSES_ROOT|HKCR|HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU)\\?(?<Key>.*)$') {
    $Root = $Matches.Root
    $Key = $Matches.Key
  }
  $NormalizedRoot = switch -Regex ($Root) {
    '^(HKEY_CLASSES_ROOT|HKCR|0)$' { 'HKCR'; break }
    '^(HKEY_CURRENT_USER|HKCU|1)$' { 'HKCU'; break }
    '^(HKEY_LOCAL_MACHINE|HKLM|2)$' { 'HKLM'; break }
    default { return $null }
  }

  $RelativeKey = if ($NormalizedRoot -eq 'HKCR') {
    $Key -replace '^(?i:Software\\Classes\\?)', ''
  } elseif ($Key -match '^(?i:Software\\Classes\\)(?<Key>.+)$') {
    $Matches.Key
  } else {
    return $null
  }
  $RelativeKey = $RelativeKey.Trim('\\')
  if ([string]::IsNullOrWhiteSpace($RelativeKey)) { return $null }

  [pscustomobject]@{
    Root        = $NormalizedRoot
    RelativeKey = $RelativeKey
    Name        = $RegistryWrite.Name
    Value       = if ($RegistryWrite.PSObject.Properties['Value']) { $RegistryWrite.Value } elseif ($RegistryWrite.PSObject.Properties['Data']) { $RegistryWrite.Data } else { $null }
    Type        = $RegistryWrite.Type
    Source      = $RegistryWrite
  }
}

function Test-InstallerDefaultRegistryValueName {
  [OutputType([bool])]
  param([AllowNull()][object]$Name)
  return $null -eq $Name -or [string]::IsNullOrWhiteSpace([string]$Name) -or [string]$Name -in @('(Default)', '@', '*')
}

function Get-InstallerClassDefaultValue {
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][object[]]$RegistryWrite,
    [Parameter(Mandatory)][string]$Root,
    [Parameter(Mandatory)][string]$RelativeKey
  )
  $Write = @($RegistryWrite | Where-Object {
      $_.Root -eq $Root -and $_.RelativeKey -ieq $RelativeKey -and (Test-InstallerDefaultRegistryValueName -Name $_.Name)
    } | Select-Object -Last 1)
  if ($Write.Count -eq 0 -or $null -eq $Write[0].Value) { return $null }
  $Value = [string]$Write[0].Value
  if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
  return $Value
}

function Get-InstallerRegistryAssociationInfo {
  <#
  .SYNOPSIS
    Extract protocol and file-extension associations from explicit registry writes
  .DESCRIPTION
    Supports HKCR and HKLM/HKCU Software\Classes writes. Protocols require an
    explicit URL Protocol value. File extensions are resolved from their default
    ProgID and OpenWithProgids values, with optional open-command and icon data.
  .PARAMETER RegistryWrite
    Objects with Root, Key, Name, Value, and optional Type properties.
  #>
  [OutputType([pscustomobject])]
  param ([AllowNull()][object[]]$RegistryWrite)

  $ClassWrites = @($RegistryWrite | ForEach-Object {
      if ($null -ne $_) { ConvertTo-InstallerClassRegistryWrite -RegistryWrite $_ }
    } | Where-Object { $_ })
  $Warnings = [System.Collections.Generic.List[string]]::new()
  $ProtocolAssociations = [System.Collections.Generic.List[object]]::new()
  $FileExtensionAssociations = [System.Collections.Generic.List[object]]::new()
  $SeenProtocols = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $SeenExtensions = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

  foreach ($Write in @($ClassWrites | Where-Object {
      $_.RelativeKey.IndexOf('\') -lt 0 -and [string]$_.Name -ieq 'URL Protocol'
    })) {
    $Protocol = $Write.RelativeKey.Trim()
    if ($Protocol -notmatch '^[A-Za-z][A-Za-z0-9+.-]{0,254}$') {
      $Warnings.Add("Ignored non-literal protocol key '$Protocol'.")
      continue
    }
    $Identity = "$($Write.Root)`0$Protocol"
    if (-not $SeenProtocols.Add($Identity)) { continue }
    $Command = Get-InstallerClassDefaultValue -RegistryWrite $ClassWrites -Root $Write.Root -RelativeKey "$Protocol\shell\open\command"
    if ([string]::IsNullOrWhiteSpace($Command)) { $Warnings.Add("Protocol '$Protocol' has URL Protocol evidence but no literal open command.") }
    $ProtocolAssociations.Add([pscustomobject]@{
        Protocol    = $Protocol.ToLowerInvariant()
        Root        = $Write.Root
        Description = Get-InstallerClassDefaultValue -RegistryWrite $ClassWrites -Root $Write.Root -RelativeKey $Protocol
        Command     = $Command
        DefaultIcon = Get-InstallerClassDefaultValue -RegistryWrite $ClassWrites -Root $Write.Root -RelativeKey "$Protocol\DefaultIcon"
        Evidence    = @($Write.Source)
      })
  }

  $ExtensionKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Write in $ClassWrites) {
    if ($Write.RelativeKey -match '^(?<Extension>\.[^\\]+)(?:\\OpenWithProgids)?$') {
      $null = $ExtensionKeys.Add("$($Write.Root)`0$($Matches.Extension)")
    }
  }
  foreach ($Identity in $ExtensionKeys) {
    $Parts = $Identity -split [char]0, 2
    $Root = $Parts[0]
    $Extension = $Parts[1]
    if ($Extension -notmatch '^\.[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$') {
      $Warnings.Add("Ignored non-literal file extension key '$Extension'.")
      continue
    }
    if (-not $SeenExtensions.Add($Identity)) { continue }
    $ProgIds = [System.Collections.Generic.List[string]]::new()
    $DefaultProgId = Get-InstallerClassDefaultValue -RegistryWrite $ClassWrites -Root $Root -RelativeKey $Extension
    if ($DefaultProgId) { $ProgIds.Add($DefaultProgId) }
    foreach ($Write in @($ClassWrites | Where-Object {
        $_.Root -eq $Root -and $_.RelativeKey -ieq "$Extension\OpenWithProgids" -and -not (Test-InstallerDefaultRegistryValueName -Name $_.Name)
      })) {
      $ProgId = [string]$Write.Name
      if (-not [string]::IsNullOrWhiteSpace($ProgId) -and -not $ProgIds.Contains($ProgId)) { $ProgIds.Add($ProgId) }
    }
    $PrimaryProgId = $ProgIds | Select-Object -First 1
    if (-not $PrimaryProgId) { $Warnings.Add("File extension '$Extension' has no literal ProgID association.") }
    $FileExtensionAssociations.Add([pscustomobject]@{
        FileExtension = $Extension.TrimStart('.').ToLowerInvariant()
        Extension     = $Extension.ToLowerInvariant()
        Root          = $Root
        DefaultProgId = $DefaultProgId
        ProgIds       = @($ProgIds)
        Description   = if ($PrimaryProgId) { Get-InstallerClassDefaultValue -RegistryWrite $ClassWrites -Root $Root -RelativeKey $PrimaryProgId } else { $null }
        Command       = if ($PrimaryProgId) { Get-InstallerClassDefaultValue -RegistryWrite $ClassWrites -Root $Root -RelativeKey "$PrimaryProgId\shell\open\command" } else { $null }
        DefaultIcon   = if ($PrimaryProgId) { Get-InstallerClassDefaultValue -RegistryWrite $ClassWrites -Root $Root -RelativeKey "$PrimaryProgId\DefaultIcon" } else { $null }
        Evidence      = @($ClassWrites | Where-Object { $_.Root -eq $Root -and $_.RelativeKey -match "^(?i:$([regex]::Escape($Extension)))(?:\\|$)" } | ForEach-Object Source)
      })
  }

  [pscustomobject]@{
    Protocols                 = @($ProtocolAssociations | Select-Object -ExpandProperty Protocol -Unique | Sort-Object)
    FileExtensions            = @($FileExtensionAssociations | Select-Object -ExpandProperty FileExtension -Unique | Sort-Object)
    ProtocolAssociations      = @($ProtocolAssociations)
    FileExtensionAssociations = @($FileExtensionAssociations)
    RegistryWrites            = @($ClassWrites | ForEach-Object Source)
    Warnings                  = @($Warnings | Select-Object -Unique)
  }
}

Export-ModuleMember -Function Get-InstallerRegistryAssociationInfo
