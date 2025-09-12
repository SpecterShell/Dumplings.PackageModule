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
    $CabPath = New-TempFile
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
      $ManifestReader.ReadToEnd() | ConvertFrom-Xml
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
      $Reader.ReadToEnd() | ConvertFrom-Xml
    } catch {
      $Reader.Close()
    }
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
    return "{$((Get-BurnInfo -Path $Path).BundleCode)}"
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

Export-ModuleMember -Function Get-BurnInfo, Get-BurnStub, Get-BurnManifest, Get-BurnUXPayload, Get-BurnBootstrapperApplicationData, Read-ProductCodeFromBurn, Read-UpgradeCodeFromBurn, Read-ProductNameFromBurn
