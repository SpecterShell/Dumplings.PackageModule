# SPDX-License-Identifier: MIT
# Format sources: https://github.com/wixtoolset/wix

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Force stop on error
$ErrorActionPreference = 'Stop'

function Get-Assembly {
  <#
  .SYNOPSIS
    Get the Microsoft.Deployment.Compression.Cab.dll assembly
  #>
  [OutputType([string])]
  param ()

  if (Test-Path -Path ($Path = Join-Path $PSScriptRoot '..' 'Assets' 'Microsoft.Deployment.Compression.Cab.dll')) {
    return (Get-Item -Path $Path -Force)
  } else {
    throw 'The Microsoft.Deployment.Compression.Cab.dll assembly could not be found'
  }
}

function Import-Assembly {
  <#
  .SYNOPSIS
    Load the Microsoft.Deployment.Compression.Cab.dll assembly
  #>

  # Check if the assembly is already loaded to prevent double loading
  if (-not ([System.Management.Automation.PSTypeName]'Microsoft.Deployment.Compression.Cab').Type) {
    Add-Type -Path (Get-Assembly).FullName
  }
}

Import-Assembly

# Constants
$IMAGE_DOS_HEADER_SIZE = 64
$IMAGE_DOS_HEADER_OFFSET_MAGIC = 0
$IMAGE_DOS_HEADER_OFFSET_NTHEADER = 60
$IMAGE_DOS_SIGNATURE = 0x5A4D

$IMAGE_NT_HEADER_SIZE = 24
$IMAGE_NT_HEADER_OFFSET_SIGNATURE = 0
$IMAGE_NT_HEADER_OFFSET_MACHINE = 4
$IMAGE_NT_HEADER_OFFSET_NUMBEROFSECTIONS = 6
$IMAGE_NT_HEADER_OFFSET_SIZEOFOPTIONALHEADER = 20
$IMAGE_NT_SIGNATURE = 0x00004550

$IMAGE_SECTION_HEADER_SIZE = 40
$IMAGE_SECTION_HEADER_OFFSET_NAME = 0
$IMAGE_SECTION_HEADER_OFFSET_SIZEOFRAWDATA = 16
$IMAGE_SECTION_HEADER_OFFSET_POINTERTORAWDATA = 20
$IMAGE_SECTION_WIXBURN_NAME = 0x6E7275627869772E # ".wixburn" as qword

$BURN_SECTION_OFFSET_MAGIC = 0
$BURN_SECTION_OFFSET_VERSION = 4
$BURN_SECTION_OFFSET_BUNDLEGUID = 8
$BURN_SECTION_OFFSET_STUBSIZE = 24
$BURN_SECTION_OFFSET_ORIGINALCHECKSUM = 28
$BURN_SECTION_OFFSET_ORIGINALSIGNATUREOFFSET = 32
$BURN_SECTION_OFFSET_ORIGINALSIGNATURESIZE = 36
$BURN_SECTION_OFFSET_FORMAT = 40
$BURN_SECTION_OFFSET_COUNT = 44
$BURN_SECTION_OFFSET_UXSIZE = 48
$BURN_SECTION_MAGIC = 0x00f14300
$BURN_SECTION_VERSION = 0x00000002

function Get-BurnInfo {
  <#
  .SYNOPSIS
    Get metadata from a WiX bundle file
  .PARAMETER Path
    The path to the WiX bundle file
  .PARAMETER Stream
    The binary stream of the WiX bundle file
  .LINK
    https://github.com/wixtoolset/wix/blob/main/src/wix/WixToolset.Core.Burn/Bundles/BurnCommon.cs
  #>
  [CmdletBinding()]
  param(
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the WiX bundle file')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Stream', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The binary stream of the WiX bundle file')]
    [System.IO.Stream]$Stream
  )

  process {
    # Open file stream
    $Stream = switch ($PSCmdlet.ParameterSetName) {
      'Path' { [System.IO.File]::OpenRead((Get-Item -Path $Path -Force).FullName) }
      'Stream' { $Stream }
      default { throw 'Invalid parameter set.' }
    }
    $Reader = [System.IO.BinaryReader]::new($Stream)

    try {
      # DOS header
      $Stream.Seek(0, 'Begin') | Out-Null
      $DosHeader = $Reader.ReadBytes($Script:IMAGE_DOS_HEADER_SIZE)
      if ([System.BitConverter]::ToUInt16($DosHeader, $Script:IMAGE_DOS_HEADER_OFFSET_MAGIC) -ne $Script:IMAGE_DOS_SIGNATURE) { throw "Not a valid DOS executable (missing 'MZ' signature)." }
      $PEOffset = [System.BitConverter]::ToUInt32($DosHeader, $Script:IMAGE_DOS_HEADER_OFFSET_NTHEADER)

      # NT header
      $Stream.Seek($PEOffset, 'Begin') | Out-Null
      $NTHeader = $Reader.ReadBytes($Script:IMAGE_NT_HEADER_SIZE)
      if ([System.BitConverter]::ToUInt32($NTHeader, $Script:IMAGE_NT_HEADER_OFFSET_SIGNATURE) -ne $Script:IMAGE_NT_SIGNATURE) { throw 'Not a valid PE executable (missing NT signature).' }
      $MachineType = [System.BitConverter]::ToUInt16($NTHeader, $Script:IMAGE_NT_HEADER_OFFSET_MACHINE)
      $Sections = [System.BitConverter]::ToUInt16($NTHeader, $Script:IMAGE_NT_HEADER_OFFSET_NUMBEROFSECTIONS)
      $OptionalHeaderSize = [System.BitConverter]::ToUInt16($NTHeader, $Script:IMAGE_NT_HEADER_OFFSET_SIZEOFOPTIONALHEADER)
      $FirstSectionOffset = $PEOffset + $Script:IMAGE_NT_HEADER_SIZE + $OptionalHeaderSize

      # Find ".wixburn" section
      $WixBurnSectionIndex = -1
      $WixBurnSectionBytes = $null
      $Stream.Seek($FirstSectionOffset, 'Begin') | Out-Null
      for ($i = 0; $i -lt $Sections; $i++) {
        $SectionBytes = $Reader.ReadBytes($Script:IMAGE_SECTION_HEADER_SIZE)
        if ([System.BitConverter]::ToUInt64($SectionBytes, $Script:IMAGE_SECTION_HEADER_OFFSET_NAME) -eq $Script:IMAGE_SECTION_WIXBURN_NAME) {
          $WixBurnSectionIndex = $i
          $WixBurnSectionBytes = $SectionBytes
          break
        }
      }
      if ($WixBurnSectionIndex -eq -1) { throw 'Missing .wixburn section. Not a WiX Burn installer.' }

      $WixBurnRawDataSize = [System.BitConverter]::ToUInt32($WixBurnSectionBytes, $Script:IMAGE_SECTION_HEADER_OFFSET_SIZEOFRAWDATA)
      $WixBurnDataOffset = [System.BitConverter]::ToUInt32($WixBurnSectionBytes, $Script:IMAGE_SECTION_HEADER_OFFSET_POINTERTORAWDATA)
      $BURN_SECTION_MIN_SIZE = $Script:BURN_SECTION_OFFSET_UXSIZE
      if ($WixBurnRawDataSize -lt $BURN_SECTION_MIN_SIZE) { throw '.wixburn section too small. Invalid installer.' }
      $WixBurnMaxContainers = ($WixBurnRawDataSize - $Script:BURN_SECTION_OFFSET_UXSIZE) / 4

      # Read .wixburn section raw data
      $Stream.Seek($WixBurnDataOffset, 'Begin') | Out-Null
      $WixBurnBytes = $Reader.ReadBytes($WixBurnRawDataSize)

      # Validate magic/version/format
      $magic = [System.BitConverter]::ToUInt32($WixBurnBytes, $Script:BURN_SECTION_OFFSET_MAGIC)
      if ($magic -ne $Script:BURN_SECTION_MAGIC) { throw 'Invalid WiX Burn magic number.' }
      $Version = [System.BitConverter]::ToUInt32($WixBurnBytes, $Script:BURN_SECTION_OFFSET_VERSION)
      if ($Version -ne $Script:BURN_SECTION_VERSION) { throw "Unsupported WiX Burn section version: $Version" }
      $Format = [System.BitConverter]::ToUInt32($WixBurnBytes, $Script:BURN_SECTION_OFFSET_FORMAT)
      if ($Format -ne 1) { throw "Unknown container format: $Format" }

      $BundleCode = [Guid]::new([byte[]]$WixBurnBytes[$Script:BURN_SECTION_OFFSET_BUNDLEGUID..($Script:BURN_SECTION_OFFSET_BUNDLEGUID + 15)])
      $StubSize = [System.BitConverter]::ToUInt32($WixBurnBytes, $Script:BURN_SECTION_OFFSET_STUBSIZE)
      $OriginalChecksum = [System.BitConverter]::ToUInt32($WixBurnBytes, $Script:BURN_SECTION_OFFSET_ORIGINALCHECKSUM)
      $OriginalSignatureOffset = [System.BitConverter]::ToUInt32($WixBurnBytes, $Script:BURN_SECTION_OFFSET_ORIGINALSIGNATUREOFFSET)
      $OriginalSignatureSize = [System.BitConverter]::ToUInt32($WixBurnBytes, $Script:BURN_SECTION_OFFSET_ORIGINALSIGNATURESIZE)
      $ContainerCount = [System.BitConverter]::ToUInt32($WixBurnBytes, $Script:BURN_SECTION_OFFSET_COUNT)
      if ($ContainerCount -gt $WixBurnMaxContainers) { throw 'Container count exceeds maximum. Corrupt installer.' }

      $AttachedContainers = @()
      $UXSize = 0
      if ($ContainerCount -gt 0) {
        for ($j = 0; $j -lt $ContainerCount; $j++) {
          $SizeOffset = $Script:BURN_SECTION_OFFSET_UXSIZE + ($j * 4)
          $Size = [System.BitConverter]::ToUInt32($WixBurnBytes, $SizeOffset)
          $AttachedContainers += [pscustomobject]@{ Index = $j; Size = $Size }
        }
        $UXSize = $AttachedContainers[0].Size
      }

      # Calculate Engine Size
      $EngineSize = 0
      if ($OriginalSignatureOffset -gt 0) {
        $EngineSize = $OriginalSignatureOffset + $OriginalSignatureSize
      } elseif ($ContainerCount -lt 2) {
        # Fallback: use stub + UX container
        $EngineSize = $StubSize + $UXSize
      }

      # Return metadata
      [PSCustomObject]@{
        Path                    = $Path
        MachineType             = $MachineType
        BundleCode              = $BundleCode
        Version                 = $Version
        StubSize                = $StubSize
        OriginalChecksum        = $OriginalChecksum
        OriginalSignatureOffset = $OriginalSignatureOffset
        OriginalSignatureSize   = $OriginalSignatureSize
        ContainerCount          = $ContainerCount
        AttachedContainers      = $AttachedContainers
        EngineSize              = $EngineSize
        WixburnRawDataSize      = $WixBurnRawDataSize
        WixburnDataOffset       = $WixBurnDataOffset
      }
    } finally {
      switch ($PSCmdlet.ParameterSetName) {
        'Path' { $Reader.Close(); $Stream.Close() }
        'Stream' { } # Do not close user-provided stream
        default { throw 'Invalid parameter set.' }
      }
    }
  }
}

function Get-BurnStub {
  <#
  .SYNOPSIS
    Extract the Burn stub (embedded CAB) from a WiX bundle file and return its path
  .PARAMETER Path
    The path to the WiX bundle file
  .PARAMETER Stream
    The binary stream of the WiX bundle file
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the WiX bundle file')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Stream', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The binary stream of the WiX bundle file')]
    [System.IO.Stream]$Stream
  )

  process {
    # Open file stream
    $BurnStream = switch ($PSCmdlet.ParameterSetName) {
      'Path' { [System.IO.File]::OpenRead((Get-Item -Path $Path -Force).FullName) }
      'Stream' { $Stream }
      default { throw 'Invalid parameter set.' }
    }
    $CabPath = [System.IO.Path]::GetTempFileName()
    $CabStream = [System.IO.File]::OpenWrite($CabPath)

    try {
      $BurnInfo = Get-BurnInfo -Stream $BurnStream
      $null = $BurnStream.Seek($BurnInfo.StubSize, 'Begin')
      $BurnStream.CopyTo($CabStream, $BurnInfo.AttachedContainers[0].Size)
      $CabPath
    } finally {
      $CabStream.Close()
      switch ($PSCmdlet.ParameterSetName) {
        'Path' { $BurnStream.Close() }
        'Stream' { } # Do not close user-provided stream
        default { throw 'Invalid parameter set.' }
      }
    }
  }
}

function Get-BurnManifest {
  <#
  .SYNOPSIS
    Get the Burn manifest from a WiX bundle file
  .PARAMETER Path
    The path to the WiX bundle file
  .PARAMETER StubPath
    The path to the extracted Burn stub CAB file
  #>
  [OutputType([xml])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the WiX bundle file')]
    [string]$Path,

    [Parameter(ParameterSetName = 'StubPath', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the extracted Burn stub CAB file')]
    [string]$StubPath
  )

  process {
    $StubPath = switch ($PSCmdlet.ParameterSetName) {
      'Path' { Get-BurnStub -Path $Path }
      'StubPath' { (Test-Path -Path $StubPath) ? $StubPath : (throw "The specified Burn stub path '$StubPath' is invalid.") }
      default { throw 'Invalid parameter set.' }
    }
    $Stub = [Microsoft.Deployment.Compression.Cab.CabInfo]::new($StubPath)
    $ManifestReader = $Stub.OpenText('0')

    try {
      [xml]$ManifestReader.ReadToEnd()
    } finally {
      $ManifestReader.Close()
      switch ($PSCmdlet.ParameterSetName) {
        'Path' { Remove-Item -Path $StubPath -Force -ErrorAction 'Continue' }
        'StubPath' { } # Do not delete user-provided stub path
        default { throw 'Invalid parameter set.' }
      }
    }
  }
}

function Get-BurnUXPayload {
  <#
  .SYNOPSIS
    Get the Burn BootstrapperApplicationData from a WiX bundle file
  .PARAMETER Path
    The path to the WiX bundle file
  .PARAMETER StubPath
    The path to the extracted Burn stub CAB file
  .PARAMETER Name
    The name of the UX payload to extract (e.g. BootstrapperApplicationData.xml)
  #>
  [OutputType([Microsoft.Deployment.Compression.Cab.CabFileInfo])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the WiX bundle file')]
    [string]$Path,

    [Parameter(ParameterSetName = 'StubPath', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the extracted Burn stub CAB file')]
    [string]$StubPath,

    [Parameter(Position = 1, HelpMessage = 'The name of the UX payload to extract (e.g. BootstrapperApplicationData.xml)')]
    [string]$Name
  )

  process {
    $StubPath = switch ($PSCmdlet.ParameterSetName) {
      'Path' { Get-BurnStub -Path $Path }
      'StubPath' { (Test-Path -Path $StubPath) ? $StubPath : (throw "The specified Burn stub path '$StubPath' is invalid.") }
      default { throw 'Invalid parameter set.' }
    }
    $Manifest = Get-BurnManifest -StubPath $StubPath
    $Stub = [Microsoft.Deployment.Compression.Cab.CabInfo]::new($StubPath)

    $NamespaceManager = [System.Xml.XmlNamespaceManager]::new($Manifest.NameTable)
    $NamespaceManager.AddNamespace('burn', $Manifest.DocumentElement.NamespaceURI)
    if ($Name) {
      $UXPayloads = $Manifest.SelectSingleNode("/burn:BurnManifest/burn:UX/burn:Payload[@FilePath='${Name}']", $NamespaceManager)
      if (-not $UXPayloads) { throw "The UX Payload with the name '${Name}' could not be found." }
    } else {
      $UXPayloads = $Manifest.SelectNodes('/burn:BurnManifest/burn:UX/burn:Payload', $NamespaceManager)
      if (-not $UXPayloads) { throw 'No UX Payloads found in the manifest.' }
    }
    foreach ($UXPayload in $UXPayloads) {
      $UXFileInfo = $Stub.GetFiles($UXPayload.SourcePath)[0]
      Add-Member -InputObject $UXFileInfo -MemberType 'NoteProperty' -Name 'RealName' -Value $UXPayload.FilePath
      Write-Output -InputObject $UXFileInfo
    }
  }
}

function Get-BurnBootstrapperApplicationData {
  <#
  .SYNOPSIS
    Get the Burn BootstrapperApplicationData from a WiX bundle file
  .PARAMETER Path
    The path to the WiX bundle file
  .PARAMETER StubPath
    The path to the extracted Burn stub CAB file
  #>
  [OutputType([xml])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the WiX bundle file')]
    [string]$Path,

    [Parameter(ParameterSetName = 'StubPath', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the extracted Burn stub CAB file')]
    [string]$StubPath
  )

  process {
    $Reader = (Get-BurnUXPayload @PSBoundParameters -Name 'BootstrapperApplicationData.xml').OpenText()
    try {
      [xml]$Reader.ReadToEnd()
    } finally {
      $Reader.Close()
    }
  }
}

function Convert-BurnMachineTypeToArchitecture {
  <#
  .SYNOPSIS
    Convert a PE machine type to a WinGet architecture name
  .PARAMETER MachineType
    The PE machine type value
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The PE machine type value')]
    [int]$MachineType
  )

  switch ($MachineType) {
    0x014C { 'x86' }
    0x8664 { 'x64' }
    0xAA64 { 'arm64' }
    0x01C4 { 'arm' }
    default { "unknown:0x$($MachineType.ToString('X4'))" }
  }
}

function Test-BurnArchitectureCondition {
  <#
  .SYNOPSIS
    Evaluate simple Burn architecture conditions for a Windows architecture
  .PARAMETER Condition
    The Burn condition text
  .PARAMETER Architecture
    The WinGet architecture to test
  #>
  [OutputType([bool])]
  param (
    [AllowNull()]
    [string]$Condition,

    [Parameter(Mandatory, HelpMessage = 'The WinGet architecture to test')]
    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture
  )

  if ([string]::IsNullOrWhiteSpace($Condition)) { return $true }

  $NativeMachine = switch ($Architecture) {
    'x86' { 332 }
    'x64' { 34404 }
    'arm64' { 43620 }
  }
  $Values = @{
    VersionNT64   = $Architecture -in @('x64', 'arm64')
    NativeMachine = $NativeMachine
  }

  $Expression = $Condition
  $Expression = [regex]::Replace($Expression, '(?i)\b(NOT|AND|OR)\b', { param($Match) $Match.Value.ToLowerInvariant() })
  foreach ($Name in $Values.Keys) {
    $Expression = [regex]::Replace($Expression, "(?i)\b$([regex]::Escape($Name))\b", [string]$Values[$Name])
  }

  # Keep only the common boolean/numeric subset used by Burn architecture
  # guards. Unknown variables are treated as true to avoid false negatives.
  $Expression = [regex]::Replace($Expression, '(?i)\b[A-Z_][A-Z0-9_]*\b', 'True')
  $Expression = $Expression -replace '<>', '-ne'
  $Expression = $Expression -replace '>=', '-ge'
  $Expression = $Expression -replace '<=', '-le'
  $Expression = $Expression -replace '(?<![<>=!])=(?!=)', '-eq'
  $Expression = $Expression -replace '(?i)\bnot\b', '-not'
  $Expression = $Expression -replace '(?i)\band\b', '-and'
  $Expression = $Expression -replace '(?i)\bor\b', '-or'

  try {
    return [bool]([scriptblock]::Create($Expression).Invoke())
  } catch {
    return $true
  }
}

function Get-BurnPackageArchitectureInfo {
  <#
  .SYNOPSIS
    Read supported and unsupported Windows architectures from Burn package conditions
  .PARAMETER Path
    The path to the WiX bundle file
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the WiX bundle file')]
    [string]$Path
  )

  process {
    $BurnInfo = Get-BurnInfo -Path $Path
    $BootstrapperApplicationData = $null
    try {
      $BootstrapperApplicationData = Get-BurnBootstrapperApplicationData -Path $Path
    } catch {
      $BootstrapperApplicationData = $null
    }

    $PackageNodes = @()
    if ($BootstrapperApplicationData) {
      $PackageNodes = @($BootstrapperApplicationData.GetElementsByTagName('WixPackageProperties'))
    }

    $RelevantPackageNodes = @($PackageNodes | Where-Object {
        $_.Package -ne 'Bundle' -and (
          -not $_.PackageType -or
          $_.PackageType -in @('Exe', 'Msi', 'Msp', 'Msu')
        )
      })

    $Supported = [System.Collections.Generic.List[string]]::new()
    foreach ($Architecture in @('x86', 'x64', 'arm64')) {
      if (-not $RelevantPackageNodes) {
        # If the package manifest is unavailable, fall back to the bundle PE
        # machine. This is weaker than package conditions but still useful for
        # native x64/arm64 bootstrapper stubs.
        $BundleArchitecture = Convert-BurnMachineTypeToArchitecture -MachineType $BurnInfo.MachineType
        if ($BundleArchitecture -eq 'x86' -or $Architecture -eq $BundleArchitecture -or ($BundleArchitecture -eq 'x64' -and $Architecture -eq 'arm64')) {
          $Supported.Add($Architecture)
        }
        continue
      }

      foreach ($Package in $RelevantPackageNodes) {
        if (Test-BurnArchitectureCondition -Condition $Package.InstallCondition -Architecture $Architecture) {
          if (-not $Supported.Contains($Architecture)) { $Supported.Add($Architecture) }
          break
        }
      }
    }

    if ($Supported.Count -eq 3) {
      $Manifest = Get-BurnManifest -Path $Path
      $ManifestText = $Manifest.OuterXml
      $HasX64Marker = $ManifestText -match '(?i)(ProgramFiles64Folder|System64Folder|\bx64\b|_x64\b|x64Setup|SetupX64|amd64)'
      $HasX86Marker = $ManifestText -match '(?i)(ProgramFilesFolder(?!64)|FilePath="[^"]*(\bx86\b|_x86\b|x86Setup|SetupX86)[^"]*")'
      $HasArm64Marker = $ManifestText -match '(?i)(\barm64\b|_arm64\b|arm64Setup|SetupArm64)'

      if ($HasX64Marker -and -not $HasX86Marker -and -not $HasArm64Marker) {
        $Supported = [System.Collections.Generic.List[string]]::new()
        $Supported.Add('x64')
        $Supported.Add('arm64')
      } elseif ($HasArm64Marker -and -not $HasX64Marker -and -not $HasX86Marker) {
        $Supported = [System.Collections.Generic.List[string]]::new()
        $Supported.Add('arm64')
      }
    }

    $SupportedArchitectures = @('x86', 'x64', 'arm64') | Where-Object { $Supported.Contains($_) }
    [PSCustomObject]@{
      BundleArchitecture       = Convert-BurnMachineTypeToArchitecture -MachineType $BurnInfo.MachineType
      SupportedArchitectures   = $SupportedArchitectures
      UnsupportedArchitectures = @('x86', 'x64', 'arm64') | Where-Object { $_ -notin $SupportedArchitectures }
      Packages                 = $RelevantPackageNodes
    }
  }
}

function Convert-BurnPerMachineToScope {
  <#
  .SYNOPSIS
    Convert Burn PerMachine metadata to a WinGet scope
  .PARAMETER PerMachine
    The Burn PerMachine value
  #>
  [OutputType([string])]
  param (
    [AllowNull()]
    [string]$PerMachine
  )

  switch -Regex ($PerMachine) {
    '^(?i)(yes|1|true)$' { return 'machine' }
    '^(?i)(no|0|false)$' { return 'user' }
    default { return $null }
  }
}

function Get-BurnScopeInfo {
  <#
  .SYNOPSIS
    Read static install scope metadata from a WiX Burn bundle
  .PARAMETER Path
    The path to the WiX bundle file
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the WiX bundle file')]
    [string]$Path
  )

  process {
    $BootstrapperApplicationData = $null
    try {
      $BootstrapperApplicationData = Get-BurnBootstrapperApplicationData -Path $Path
    } catch {
      $BootstrapperApplicationData = $null
    }
    $Manifest = Get-BurnManifest -Path $Path

    $BundlePerMachine = $null
    if ($BootstrapperApplicationData) {
      $BundleProperties = @($BootstrapperApplicationData.GetElementsByTagName('WixBundleProperties') | Select-Object -First 1)
      if ($BundleProperties) { $BundlePerMachine = $BundleProperties[0].GetAttribute('PerMachine') }
    }
    if ([string]::IsNullOrWhiteSpace($BundlePerMachine)) {
      $Registration = @($Manifest.GetElementsByTagName('Registration') | Select-Object -First 1)
      if ($Registration) { $BundlePerMachine = $Registration[0].GetAttribute('PerMachine') }
    }

    $DefaultScope = Convert-BurnPerMachineToScope -PerMachine $BundlePerMachine
    $PackageScopes = @(
      $Manifest.GetElementsByTagName('*') |
        Where-Object { $_.Name -match 'Package$' -and $_.GetAttribute('Permanent') -ne 'yes' -and $_.HasAttribute('PerMachine') } |
        ForEach-Object { Convert-BurnPerMachineToScope -PerMachine $_.GetAttribute('PerMachine') } |
        Where-Object { $_ } |
        Select-Object -Unique
    )

    $OverridableVariables = @()
    if ($BootstrapperApplicationData) {
      $OverridableVariables = @($BootstrapperApplicationData.GetElementsByTagName('WixStdbaOverridableVariable') | ForEach-Object { $_.GetAttribute('Name') } | Where-Object { $_ })
    }
    $VariableNames = @($Manifest.GetElementsByTagName('Variable') | ForEach-Object { $_.GetAttribute('Id') } | Where-Object { $_ })
    $PackageIds = @($Manifest.GetElementsByTagName('*') | Where-Object { $_.Name -match 'Package$' } | ForEach-Object { $_.GetAttribute('Id') } | Where-Object { $_ })

    # Python-style Burn bundles expose both all-users and just-for-me package
    # groups, and make InstallAllUsers overridable from the command line.
    $HasAllUsersPackage = [bool]($PackageIds | Where-Object { $_ -match '(?i)(^|_)AllUsers($|_)' })
    $HasJustForMePackage = [bool]($PackageIds | Where-Object { $_ -match '(?i)(^|_)JustForMe($|_)' })
    $HasInstallAllUsersVariable = $VariableNames -contains 'InstallAllUsers'
    $HasInstallAllUsersOverride = $OverridableVariables -contains 'InstallAllUsers'
    $SupportsDualScope = $HasAllUsersPackage -and $HasJustForMePackage -and $HasInstallAllUsersVariable -and $HasInstallAllUsersOverride

    $SupportedScopes = if ($SupportsDualScope) {
      @('user', 'machine')
    } elseif ($DefaultScope) {
      @($DefaultScope)
    } else {
      @()
    }

    [PSCustomObject]@{
      DefaultScope                  = $DefaultScope
      SupportedScopes               = $SupportedScopes
      SupportsDualScope             = $SupportsDualScope
      BundlePerMachine              = $BundlePerMachine
      PackageScopes                 = $PackageScopes
      ScopeVariables                = @($VariableNames | Where-Object { $_ -match '(?i)(InstallAllUsers|InstallPerMachine|PerMachine|AllUsers)' })
      OverridableScopeVariables     = @($OverridableVariables | Where-Object { $_ -match '(?i)(InstallAllUsers|InstallPerMachine|PerMachine|AllUsers)' })
    }
  }
}

function Read-ScopeFromBurn {
  <#
  .SYNOPSIS
    Read the default install scope from a WiX Burn bundle
  .PARAMETER Path
    The path to the WiX bundle file
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the WiX bundle file')]
    [string]$Path
  )

  process {
    (Get-BurnScopeInfo -Path $Path).DefaultScope
  }
}

function Read-SupportedScopesFromBurn {
  <#
  .SYNOPSIS
    Read install scopes supported by a WiX Burn bundle
  .PARAMETER Path
    The path to the WiX bundle file
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the WiX bundle file')]
    [string]$Path
  )

  process {
    (Get-BurnScopeInfo -Path $Path).SupportedScopes
  }
}

function Test-BurnDualScope {
  <#
  .SYNOPSIS
    Test whether a WiX Burn bundle statically exposes both user and machine scope
  .PARAMETER Path
    The path to the WiX bundle file
  #>
  [OutputType([bool])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the WiX bundle file')]
    [string]$Path
  )

  process {
    (Get-BurnScopeInfo -Path $Path).SupportsDualScope
  }
}

function Read-UnsupportedArchitecturesFromBurn {
  <#
  .SYNOPSIS
    Read Windows architectures that the Burn installer does not support
  .PARAMETER Path
    The path to the WiX bundle file
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the WiX bundle file')]
    [string]$Path
  )

  process {
    (Get-BurnPackageArchitectureInfo -Path $Path).UnsupportedArchitectures
  }
}

function Test-BurnUnsupportedArchitecture {
  <#
  .SYNOPSIS
    Test whether the Burn installer does not support a Windows architecture
  .PARAMETER Path
    The path to the WiX bundle file
  .PARAMETER Architecture
    The Windows architecture to test
  #>
  [OutputType([bool])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the WiX bundle file')]
    [string]$Path,

    [Parameter(Mandatory, HelpMessage = 'The Windows architecture to test')]
    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture
  )

  process {
    (Get-BurnPackageArchitectureInfo -Path $Path).UnsupportedArchitectures -contains $Architecture
  }
}

function Read-ProductCodeFromBurn {
  <#
  .SYNOPSIS
    Read the ProductCode property of the WiX bundle file
  .PARAMETER Path
    The path to the WiX bundle file
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the WiX bundle file')]
    [string]$Path
  )

  process {
    try {
      $BootstrapperApplicationData = Get-BurnBootstrapperApplicationData -Path $Path
      Write-Output -InputObject $BootstrapperApplicationData.BootstrapperApplicationData.WixBundleProperties.Id
    } catch {
      Write-Host -Object 'Failed to read the BootstrapperApplicationData file. Fallbacking to the manifest file'
      $Manifest = Get-BurnManifest -Path $Path
      if ($Manifest.BurnManifest.Registration.HasAttribute('Code')) {
        # WiX v6+
        Write-Output -InputObject $Manifest.BurnManifest.Registration.Code
      } else {
        Write-Output -InputObject $Manifest.BurnManifest.Registration.Id
      }
    }
  }
}

function Read-UpgradeCodeFromBurn {
  <#
  .SYNOPSIS
    Read the UpgradeCode property of the WiX bundle file
  .PARAMETER Path
    The path to the WiX bundle file
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the WiX bundle file')]
    [string]$Path
  )

  process {
    try {
      $BootstrapperApplicationData = Get-BurnBootstrapperApplicationData -Path $Path
      Write-Output -InputObject $BootstrapperApplicationData.BootstrapperApplicationData.WixBundleProperties.UpgradeCode
    } catch {
      Write-Host -Object 'Failed to read the BootstrapperApplicationData file. Fallbacking to the manifest file'
      $Manifest = Get-BurnManifest -Path $Path
      if ($Manifest.BurnManifest.RelatedBundle.HasAttribute('Code')) {
        # WiX v6+
        Write-Output -InputObject $Manifest.BurnManifest.RelatedBundle.Code
      } else {
        Write-Output -InputObject $Manifest.BurnManifest.RelatedBundle.Id
      }
    }
  }
}

function Read-ProductNameFromBurn {
  <#
  .SYNOPSIS
    Read the ProductName property of the WiX bundle file
  .PARAMETER Path
    The path to the WiX bundle file
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the WiX bundle file')]
    [string]$Path
  )

  process {
    try {
      $BootstrapperApplicationData = Get-BurnBootstrapperApplicationData -Path $Path
      Write-Output -InputObject $BootstrapperApplicationData.BootstrapperApplicationData.WixBundleProperties.DisplayName
    } catch {
      Write-Host -Object 'Failed to read the BootstrapperApplicationData file. Fallbacking to the manifest file'
      $Manifest = Get-BurnManifest -Path $Path
      Write-Output -InputObject $Manifest.BurnManifest.Registration.Arp.DisplayName
    }
  }
}

Export-ModuleMember -Function Get-BurnInfo, Get-BurnStub, Get-BurnManifest, Get-BurnUXPayload, Get-BurnBootstrapperApplicationData, Get-BurnPackageArchitectureInfo, Get-BurnScopeInfo, Read-ScopeFromBurn, Read-SupportedScopesFromBurn, Test-BurnDualScope, Read-UnsupportedArchitecturesFromBurn, Test-BurnUnsupportedArchitecture, Read-ProductCodeFromBurn, Read-UpgradeCodeFromBurn, Read-ProductNameFromBurn
