BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  $Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
  $Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Infrastructure' 'Runtime.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Infrastructure' 'Binary.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Infrastructure' 'Archive.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Infrastructure' 'PE.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Infrastructure' 'InstallerEvidence.psm1') -Force
  . (Resolve-DumplingsTestModulePath 'Tests\Support\Import-DataInfrastructure.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Infrastructure' 'InstallerBridge.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Installers' 'MSI.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Installers' 'NSIS.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Installers' 'Inno.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Installers' 'AdvancedInstaller.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Installers' 'QtInstallerFramework.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Installers' 'SetupFactory.psm1') -Force

  $Script:FixtureDirectory = $TestDrive

  function Get-InstallerFixture {
    param(
      [Parameter(Mandatory)]
      [string]$Name,

      [Parameter(Mandatory)]
      [string]$Url,

      [string]$Sha256,

      [switch]$UseSourceForgeMetaRefresh
    )

    $Arguments = @{
      RelativePath              = Resolve-DumplingsTestFixtureCatalogPath -Name $Name
      Uri                       = $Url
      UseSourceForgeMetaRefresh = $UseSourceForgeMetaRefresh
    }
    if ($Sha256) { $Arguments.Sha256 = $Sha256 }
    Get-DumplingsTestFixture @Arguments
  }

  function Add-TestInt64LE {
    param([System.Collections.Generic.List[byte]]$Bytes, [int64]$Value)

    $Bytes.AddRange([System.BitConverter]::GetBytes($Value))
  }

  function Add-TestQtByteArray {
    param(
      [System.Collections.Generic.List[byte]]$Bytes,
      [string]$Value
    )

    $Data = [Text.Encoding]::UTF8.GetBytes($Value)
    Add-TestInt64LE -Bytes $Bytes -Value $Data.Length
    $Bytes.AddRange($Data)
  }

  function New-TestQtInstallerFrameworkFixture {
    param(
      [string]$Name,
      [string]$InstallerXml,
      [string]$ScriptText,
      [object[]]$Operation = @()
    )

    $FixturePath = Join-Path $Script:FixtureDirectory $Name
    $Bytes = [System.Collections.Generic.List[byte]]::new()
    $Bytes.AddRange([byte[]](0x4d, 0x5a))
    $Bytes.AddRange([System.Text.Encoding]::ASCII.GetBytes("IFW Version: 4.11.0, built with Qt 6.8.0.`0"))
    $Bytes.AddRange([System.Text.Encoding]::ASCII.GetBytes("accept-licenses`0default-answer`0confirm-command`0check-updates`0create-offline`0clear-cache`0"))
    while ($Bytes.Count -lt 512) { $Bytes.Add(0) }

    $EndOfExecutable = $Bytes.Count
    $MetaStart = $Bytes.Count
    $MetaBytes = [System.Text.Encoding]::UTF8.GetBytes($InstallerXml)
    $Bytes.AddRange($MetaBytes)
    $MetaSegments = [System.Collections.Generic.List[object]]::new()
    $MetaSegments.Add([pscustomobject]@{ Start = $MetaStart; Length = $MetaBytes.Length })
    if ($PSBoundParameters.ContainsKey('ScriptText')) {
      $ScriptStart = $Bytes.Count
      $ScriptBytes = [System.Text.Encoding]::UTF8.GetBytes($ScriptText)
      $Bytes.AddRange($ScriptBytes)
      $MetaSegments.Add([pscustomobject]@{ Start = $ScriptStart; Length = $ScriptBytes.Length })
    }

    $OperationsStart = $Bytes.Count
    Add-TestInt64LE -Bytes $Bytes -Value $Operation.Count
    foreach ($OperationItem in $Operation) {
      Add-TestQtByteArray -Bytes $Bytes -Value $OperationItem.Name
      Add-TestQtByteArray -Bytes $Bytes -Value $OperationItem.Data
    }
    Add-TestInt64LE -Bytes $Bytes -Value $Operation.Count
    $OperationsLength = $Bytes.Count - $OperationsStart

    Add-TestInt64LE -Bytes $Bytes -Value 0
    $CollectionIndexStart = $Bytes.Count
    Add-TestInt64LE -Bytes $Bytes -Value 0
    Add-TestInt64LE -Bytes $Bytes -Value 0
    $CollectionIndexLength = $Bytes.Count - $CollectionIndexStart

    Add-TestInt64LE -Bytes $Bytes -Value ($CollectionIndexStart - $EndOfExecutable)
    Add-TestInt64LE -Bytes $Bytes -Value $CollectionIndexLength
    foreach ($MetaSegment in $MetaSegments) {
      Add-TestInt64LE -Bytes $Bytes -Value ($MetaSegment.Start - $EndOfExecutable)
      Add-TestInt64LE -Bytes $Bytes -Value $MetaSegment.Length
    }
    Add-TestInt64LE -Bytes $Bytes -Value ($OperationsStart - $EndOfExecutable)
    Add-TestInt64LE -Bytes $Bytes -Value $OperationsLength
    Add-TestInt64LE -Bytes $Bytes -Value $MetaSegments.Count

    $BinaryContentSize = ($Bytes.Count + 24) - $EndOfExecutable
    Add-TestInt64LE -Bytes $Bytes -Value $BinaryContentSize
    Add-TestInt64LE -Bytes $Bytes -Value 0x12023233
    $Bytes.AddRange([byte[]](0xf8, 0x68, 0xd6, 0x99, 0x1c, 0x0a, 0x63, 0xc2))

    [System.IO.File]::WriteAllBytes($FixturePath, $Bytes.ToArray())
    return $FixturePath
  }
}
