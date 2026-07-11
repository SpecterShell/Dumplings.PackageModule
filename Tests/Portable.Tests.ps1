BeforeAll {
  . (Join-Path $PSScriptRoot 'TestFixture.ps1')
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Runtime.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\Binary.psm1') -Force
  . (Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath 'Index.ps1')

  $Script:PortableFixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'PackageModule\Portable'
  if (Test-Path -LiteralPath $Script:PortableFixtureDirectory) {
    Remove-Item -LiteralPath $Script:PortableFixtureDirectory -Recurse -Force
  }
  $null = New-Item -Path $Script:PortableFixtureDirectory -ItemType Directory -Force

  function Get-PortableTestPEFixture {
    param(
      [Parameter(Mandatory)]
      [string]$Name,

      [Parameter(Mandatory)]
      [uint16]$Machine,

      [switch]$PE32Plus,

      [switch]$Dll,

      [uint16]$Subsystem = 3,

      [uint32]$ClrFlags = 0,

      [string]$TargetFramework,

      [string[]]$Imports = @(),

      [string[]]$DelayImports = @(),

      [string]$AppHostBinding,

      [string]$BundleRuntimeConfigJson
    )

    $Path = Join-Path $Script:PortableFixtureDirectory $Name
    $Bytes = [byte[]]::new(0x3000)

    function Write-TestUInt16 {
      param([int]$Offset, [uint16]$Value)
      [System.BitConverter]::GetBytes($Value).CopyTo($Bytes, $Offset)
    }

    function Write-TestUInt32 {
      param([int]$Offset, [uint32]$Value)
      [System.BitConverter]::GetBytes($Value).CopyTo($Bytes, $Offset)
    }

    function Write-TestUInt64 {
      param([int]$Offset, [uint64]$Value)
      [System.BitConverter]::GetBytes($Value).CopyTo($Bytes, $Offset)
    }

    function Write-TestAscii {
      param([int]$Offset, [string]$Value)
      $StringBytes = [System.Text.Encoding]::ASCII.GetBytes($Value)
      [Array]::Copy($StringBytes, 0, $Bytes, $Offset, $StringBytes.Length)
      $Bytes[$Offset + $StringBytes.Length] = 0
    }

    function Write-TestBytes {
      param([int]$Offset, [byte[]]$Value)
      [Array]::Copy($Value, 0, $Bytes, $Offset, $Value.Length)
    }

    function Convert-TestRvaToOffset {
      param([uint32]$Rva)
      [int](0x200 + ($Rva - 0x1000))
    }

    $PeOffset = 0x80
    $OptionalHeaderOffset = $PeOffset + 24
    $OptionalHeaderSize = $PE32Plus ? 0xF0 : 0xE0
    $DataDirectoryOffset = $PE32Plus ? ($OptionalHeaderOffset + 112) : ($OptionalHeaderOffset + 96)
    $NumberOfRvaAndSizesOffset = $PE32Plus ? ($OptionalHeaderOffset + 108) : ($OptionalHeaderOffset + 92)
    $SectionOffset = $OptionalHeaderOffset + $OptionalHeaderSize

    Write-TestUInt16 -Offset 0 -Value 0x5A4D
    Write-TestUInt32 -Offset 0x3C -Value $PeOffset
    Write-TestUInt32 -Offset $PeOffset -Value 0x00004550
    Write-TestUInt16 -Offset ($PeOffset + 4) -Value $Machine
    Write-TestUInt16 -Offset ($PeOffset + 6) -Value 1
    Write-TestUInt16 -Offset ($PeOffset + 20) -Value $OptionalHeaderSize
    $Characteristics = if ($Dll) { [uint16]0x2102 } else { [uint16]0x0102 }
    Write-TestUInt16 -Offset ($PeOffset + 22) -Value $Characteristics

    Write-TestUInt16 -Offset $OptionalHeaderOffset -Value ($PE32Plus ? 0x020B : 0x010B)
    if ($PE32Plus) {
      Write-TestUInt64 -Offset ($OptionalHeaderOffset + 24) -Value 0x0000000140000000
    } else {
      Write-TestUInt32 -Offset ($OptionalHeaderOffset + 28) -Value 0x00400000
    }
    Write-TestUInt32 -Offset ($OptionalHeaderOffset + 60) -Value 0x200
    Write-TestUInt16 -Offset ($OptionalHeaderOffset + 68) -Value $Subsystem
    Write-TestUInt32 -Offset $NumberOfRvaAndSizesOffset -Value 16

    $SectionNameBytes = [System.Text.Encoding]::ASCII.GetBytes('.rdata')
    [Array]::Copy($SectionNameBytes, 0, $Bytes, $SectionOffset, $SectionNameBytes.Length)
    Write-TestUInt32 -Offset ($SectionOffset + 8) -Value 0x2000
    Write-TestUInt32 -Offset ($SectionOffset + 12) -Value 0x1000
    Write-TestUInt32 -Offset ($SectionOffset + 16) -Value 0x2000
    Write-TestUInt32 -Offset ($SectionOffset + 20) -Value 0x200

    function Write-TestDataDirectory {
      param([int]$Index, [uint32]$Rva, [uint32]$Size)
      $DirectoryOffset = $DataDirectoryOffset + ($Index * 8)
      Write-TestUInt32 -Offset $DirectoryOffset -Value $Rva
      Write-TestUInt32 -Offset ($DirectoryOffset + 4) -Value $Size
    }

    if ($Imports.Count -gt 0) {
      $ImportDescriptorRva = 0x1100
      Write-TestDataDirectory -Index 1 -Rva $ImportDescriptorRva -Size ([uint32](($Imports.Count + 1) * 20))
      for ($Index = 0; $Index -lt $Imports.Count; $Index++) {
        $DescriptorOffset = (Convert-TestRvaToOffset -Rva $ImportDescriptorRva) + ($Index * 20)
        $NameRva = [uint32](0x1300 + ($Index * 0x40))
        Write-TestUInt32 -Offset ($DescriptorOffset + 12) -Value $NameRva
        Write-TestUInt32 -Offset ($DescriptorOffset + 16) -Value ([uint32](0x1500 + ($Index * 0x10)))
        Write-TestAscii -Offset (Convert-TestRvaToOffset -Rva $NameRva) -Value $Imports[$Index]
      }
    }

    if ($DelayImports.Count -gt 0) {
      $DelayDescriptorRva = 0x1160
      Write-TestDataDirectory -Index 13 -Rva $DelayDescriptorRva -Size ([uint32](($DelayImports.Count + 1) * 32))
      for ($Index = 0; $Index -lt $DelayImports.Count; $Index++) {
        $DescriptorOffset = (Convert-TestRvaToOffset -Rva $DelayDescriptorRva) + ($Index * 32)
        $NameRva = [uint32](0x1800 + ($Index * 0x40))
        Write-TestUInt32 -Offset $DescriptorOffset -Value 1
        Write-TestUInt32 -Offset ($DescriptorOffset + 4) -Value $NameRva
        Write-TestUInt32 -Offset ($DescriptorOffset + 12) -Value ([uint32](0x1A00 + ($Index * 0x10)))
        Write-TestUInt32 -Offset ($DescriptorOffset + 16) -Value ([uint32](0x1B00 + ($Index * 0x10)))
        Write-TestAscii -Offset (Convert-TestRvaToOffset -Rva $NameRva) -Value $DelayImports[$Index]
      }
    }

    if ($ClrFlags -ne 0 -or $TargetFramework) {
      $ClrRva = 0x11C0
      $ClrOffset = Convert-TestRvaToOffset -Rva $ClrRva
      Write-TestDataDirectory -Index 14 -Rva $ClrRva -Size 0x48
      Write-TestUInt32 -Offset $ClrOffset -Value 0x48
      Write-TestUInt16 -Offset ($ClrOffset + 4) -Value 2
      Write-TestUInt16 -Offset ($ClrOffset + 6) -Value 5
      $MetaDataRva = $TargetFramework ? 0x1C00 : 0x1250
      $MetaDataSize = $TargetFramework ? 0x100 : 0x20
      Write-TestUInt32 -Offset ($ClrOffset + 8) -Value $MetaDataRva
      Write-TestUInt32 -Offset ($ClrOffset + 12) -Value $MetaDataSize
      Write-TestUInt32 -Offset ($ClrOffset + 16) -Value $ClrFlags
      Write-TestUInt32 -Offset ($ClrOffset + 20) -Value 0x06000001
      if ($TargetFramework) {
        Write-TestAscii -Offset (Convert-TestRvaToOffset -Rva 0x1C00) -Value $TargetFramework
      }
    }

    if ($AppHostBinding) {
      Write-TestAscii -Offset 0x1F00 -Value $AppHostBinding
    }

    if ($BundleRuntimeConfigJson) {
      $RuntimeConfigBytes = [System.Text.Encoding]::UTF8.GetBytes($BundleRuntimeConfigJson)
      $RuntimeConfigOffset = 0x2000
      $HeaderOffset = 0x2400
      $MarkerOffset = 0x1E00
      $BundleId = 'FakeBundleID'
      $BundleIdBytes = [System.Text.Encoding]::UTF8.GetBytes($BundleId)
      $BundleSignature = [byte[]](
        0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38,
        0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
        0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18,
        0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae
      )

      Write-TestBytes -Offset $RuntimeConfigOffset -Value $RuntimeConfigBytes
      Write-TestBytes -Offset $MarkerOffset -Value ([System.BitConverter]::GetBytes([int64]$HeaderOffset))
      Write-TestBytes -Offset ($MarkerOffset + 8) -Value $BundleSignature

      Write-TestUInt32 -Offset $HeaderOffset -Value 6
      Write-TestUInt32 -Offset ($HeaderOffset + 4) -Value 0
      Write-TestUInt32 -Offset ($HeaderOffset + 8) -Value 1
      $Bytes[$HeaderOffset + 12] = [byte]$BundleIdBytes.Length
      Write-TestBytes -Offset ($HeaderOffset + 13) -Value $BundleIdBytes
      $HeaderV2Offset = $HeaderOffset + 13 + $BundleIdBytes.Length
      Write-TestBytes -Offset $HeaderV2Offset -Value ([System.BitConverter]::GetBytes([int64]0))
      Write-TestBytes -Offset ($HeaderV2Offset + 8) -Value ([System.BitConverter]::GetBytes([int64]0))
      Write-TestBytes -Offset ($HeaderV2Offset + 16) -Value ([System.BitConverter]::GetBytes([int64]$RuntimeConfigOffset))
      Write-TestBytes -Offset ($HeaderV2Offset + 24) -Value ([System.BitConverter]::GetBytes([int64]$RuntimeConfigBytes.Length))
      Write-TestBytes -Offset ($HeaderV2Offset + 32) -Value ([System.BitConverter]::GetBytes([uint64]0))
    }

    $ParentDirectory = Split-Path -Path $Path -Parent
    if (-not (Test-Path -LiteralPath $ParentDirectory)) {
      $null = New-Item -Path $ParentDirectory -ItemType Directory -Force
    }
    [System.IO.File]::WriteAllBytes($Path, $Bytes)
    return $Path
  }

  function New-PortableTestRuntimeConfig {
    param(
      [Parameter(Mandatory)]
      [string]$Path,

      [Parameter(Mandatory)]
      [string]$Json
    )

    Set-Content -LiteralPath $Path -Value $Json -Encoding UTF8
    return $Path
  }

  function New-PortableTestBundledRuntimeMarker {
    param(
      [Parameter(Mandatory)]
      [string]$Path
    )

    [System.IO.File]::WriteAllBytes($Path, [byte[]](1, 2, 3, 4))
    return $Path
  }
}

Describe 'PE architecture helpers' {
  It 'Should identify Windows GUI and console PE subsystems' {
    $Gui = Get-PortableTestPEFixture -Name 'windows-gui.exe' -Machine 0x8664 -PE32Plus -Subsystem 2
    $Console = Get-PortableTestPEFixture -Name 'windows-console.exe' -Machine 0x8664 -PE32Plus -Subsystem 3

    $GuiInfo = Get-PESubsystemInfo -Path $Gui
    $GuiInfo.Name | Should -Be 'WindowsGui'
    $GuiInfo.IsGui | Should -BeTrue
    $GuiInfo.IsConsole | Should -BeFalse

    $ConsoleInfo = Get-PESubsystemInfo -Path $Console
    $ConsoleInfo.Name | Should -Be 'WindowsCui'
    $ConsoleInfo.IsGui | Should -BeFalse
    $ConsoleInfo.IsConsole | Should -BeTrue
  }

  It 'Should map native PE machine values to concrete WinGet architectures' {
    (Get-PEArchitectureInfo -Path (Get-PortableTestPEFixture -Name 'native-x86.exe' -Machine 0x014C)).RecommendedWinGetArchitecture | Should -Be 'x86'
    (Get-PEArchitectureInfo -Path (Get-PortableTestPEFixture -Name 'native-x64.exe' -Machine 0x8664 -PE32Plus)).RecommendedWinGetArchitecture | Should -Be 'x64'
    (Get-PEArchitectureInfo -Path (Get-PortableTestPEFixture -Name 'native-arm64.exe' -Machine 0xAA64 -PE32Plus)).RecommendedWinGetArchitecture | Should -Be 'arm64'
  }

  It 'Should classify DLL PE files and map their architecture' {
    $X86Dll = Get-PortableTestPEFixture -Name 'native-x86.dll' -Machine 0x014C -Dll
    $X64Dll = Get-PortableTestPEFixture -Name 'native-x64.dll' -Machine 0x8664 -PE32Plus -Dll
    $Arm64Dll = Get-PortableTestPEFixture -Name 'native-arm64.dll' -Machine 0xAA64 -PE32Plus -Dll

    (Get-PEArchitectureInfo -Path $X86Dll).FileKind | Should -Be 'Dll'
    (Get-PEArchitectureInfo -Path $X86Dll).RecommendedWinGetArchitecture | Should -Be 'x86'
    (Get-PEArchitectureInfo -Path $X64Dll).RecommendedWinGetArchitecture | Should -Be 'x64'
    (Get-PEArchitectureInfo -Path $Arm64Dll).RecommendedWinGetArchitecture | Should -Be 'arm64'
  }

  It 'Should exclude ARM32 from recommendations' {
    $Info = Get-PEArchitectureInfo -Path (Get-PortableTestPEFixture -Name 'native-arm.dll' -Machine 0x01C4 -Dll)

    $Info.RecommendedWinGetArchitectures | Should -BeNullOrEmpty
    $Info.Warnings[0] | Should -BeLike '*ARM32*excluded*'
  }

  It 'Should report .NET Framework AnyCPU below 4.8.1 as x86 and x64 only' {
    $Info = Get-PEArchitectureInfo -Path (Get-PortableTestPEFixture -Name 'anycpu-net472.exe' -Machine 0x014C -ClrFlags 0x00000001 -TargetFramework '.NETFramework,Version=v4.7.2')

    $Info.IsAnyCpu | Should -BeTrue
    $Info.RecommendedWinGetArchitecture | Should -BeNullOrEmpty
    $Info.RecommendedWinGetArchitectures | Should -Contain 'x86'
    $Info.RecommendedWinGetArchitectures | Should -Contain 'x64'
    $Info.RecommendedWinGetArchitectures | Should -Not -Contain 'arm64'
    $Info.RecommendedWinGetArchitectures | Should -Not -Contain 'neutral'
  }

  It 'Should report AnyCPU with missing target framework as x86 and x64 with a warning' {
    $Info = Get-PEArchitectureInfo -Path (Get-PortableTestPEFixture -Name 'anycpu-unknown.exe' -Machine 0x014C -ClrFlags 0x00000001)

    $Info.RecommendedWinGetArchitectures | Should -Contain 'x86'
    $Info.RecommendedWinGetArchitectures | Should -Contain 'x64'
    $Info.RecommendedWinGetArchitectures | Should -Not -Contain 'arm64'
    $Info.Warnings | Should -Contain 'Managed AnyCPU target framework metadata was not found; reporting x86 and x64 only and requiring manual review before adding arm64.'
  }

  It 'Should map 32BitRequired managed executables to x86' {
    $Info = Get-PEArchitectureInfo -Path (Get-PortableTestPEFixture -Name 'managed-x86.exe' -Machine 0x014C -ClrFlags 0x00000003 -TargetFramework '.NETFramework,Version=v4.8')

    $Info.RecommendedWinGetArchitecture | Should -Be 'x86'
    $Info.ClrFlags.Requires32Bit | Should -BeTrue
  }

  It 'Should keep x64 support for 32BitPreferred AnyCPU executables' {
    $Info = Get-PEArchitectureInfo -Path (Get-PortableTestPEFixture -Name 'anycpu-prefer-x86.exe' -Machine 0x014C -ClrFlags 0x00020001 -TargetFramework '.NETFramework,Version=v4.7.2')

    $Info.PreferredArchitecture | Should -Be 'x86'
    $Info.RecommendedWinGetArchitectures | Should -Contain 'x86'
    $Info.RecommendedWinGetArchitectures | Should -Contain 'x64'
  }

  It 'Should narrow managed AnyCPU when related native DLLs provide one architecture' {
    $Main = Get-PortableTestPEFixture -Name 'anycpu-net6.exe' -Machine 0x014C -ClrFlags 0x00000001 -TargetFramework '.NETCoreApp,Version=v6.0'
    $NativeDll = Get-PortableTestPEFixture -Name 'native-related-x64.dll' -Machine 0x8664 -PE32Plus

    $Info = Get-PEArchitectureInfo -Path $Main -RelatedFile $NativeDll

    $Info.RecommendedWinGetArchitecture | Should -Be 'x64'
    $Info.Warnings | Should -Contain 'Related PE files narrow this portable executable to x64.'
  }

  It 'Should warn when related native DLLs contain multiple architectures' {
    $Main = Get-PortableTestPEFixture -Name 'anycpu-net6-mixed.exe' -Machine 0x014C -ClrFlags 0x00000001 -TargetFramework '.NETCoreApp,Version=v6.0'
    $X86Dll = Get-PortableTestPEFixture -Name 'native-related-x86.dll' -Machine 0x014C
    $X64Dll = Get-PortableTestPEFixture -Name 'native-related-x64-mixed.dll' -Machine 0x8664 -PE32Plus

    $Info = Get-PEArchitectureInfo -Path $Main -RelatedFile @($X86Dll, $X64Dll)

    $Info.Warnings | Should -Contain 'Related PE files contain multiple concrete architectures: x64, x86. Inspect package layout manually before authoring WinGet installers.'
  }

  It 'Should keep compatibility wrapper names available' {
    $Path = Get-PortableTestPEFixture -Name 'wrapper-native-x64.exe' -Machine 0x8664 -PE32Plus

    (Get-PortableExecutableArchitectureInfo -Path $Path).RecommendedWinGetArchitecture | Should -Be 'x64'
    Read-ArchitectureFromPortableExecutable -Path $Path | Should -Be 'x64'
    Test-PortableExecutableArchitecture -Path $Path -Architecture x64 | Should -BeTrue
  }
}

Describe 'PE dependency helpers' {
  It 'Should map imported VC runtime DLLs to WinGet VCRedist package identifiers' {
    $Path = Get-PortableTestPEFixture -Name 'vcredist-x64.exe' -Machine 0x8664 -PE32Plus -Imports @(
      'msvcr80.dll',
      'msvcp90.dll',
      'mfc100u.dll',
      'vcomp110.dll',
      'msvcr120.dll',
      'vcruntime140.dll'
    )

    $Info = Get-PEDependencyInfo -Path $Path

    $Info.RecommendedPackageDependencyIds | Should -Contain 'Microsoft.VCRedist.2005.x64'
    $Info.RecommendedPackageDependencyIds | Should -Contain 'Microsoft.VCRedist.2008.x64'
    $Info.RecommendedPackageDependencyIds | Should -Contain 'Microsoft.VCRedist.2010.x64'
    $Info.RecommendedPackageDependencyIds | Should -Contain 'Microsoft.VCRedist.2012.x64'
    $Info.RecommendedPackageDependencyIds | Should -Contain 'Microsoft.VCRedist.2013.x64'
    $Info.RecommendedPackageDependencyIds | Should -Contain 'Microsoft.VCRedist.2015+.x64'
  }

  It 'Should map delay-imported VC runtime DLLs' {
    $Path = Get-PortableTestPEFixture -Name 'vcredist-delay-x86.exe' -Machine 0x014C -DelayImports @('msvcp140.dll')

    $Info = Get-PEDependencyInfo -Path $Path

    $Info.RecommendedPackageDependencyIds | Should -Contain 'Microsoft.VCRedist.2015+.x86'
    $Info.VCRedistImports.Directory | Should -Contain 'DelayImport'
  }

  It 'Should map VC++ 2015+ arm64 imports' {
    $Path = Get-PortableTestPEFixture -Name 'vcredist-arm64.exe' -Machine 0xAA64 -PE32Plus -Imports @('vcruntime140_1.dll')

    $Info = Get-PEDependencyInfo -Path $Path

    $Info.RecommendedPackageDependencyIds | Should -Contain 'Microsoft.VCRedist.2015+.arm64'
  }

  It 'Should report UCRT imports separately from VCRedist package dependencies' {
    $Path = Get-PortableTestPEFixture -Name 'ucrt-x64.exe' -Machine 0x8664 -PE32Plus -Imports @('ucrtbase.dll', 'api-ms-win-crt-runtime-l1-1-0.dll')

    $Info = Get-PEDependencyInfo -Path $Path

    $Info.DependsOnUcrt | Should -BeTrue
    $Info.DependsOnVCRedist | Should -BeFalse
    $Info.RecommendedPackageDependencyIds | Should -BeNullOrEmpty
  }

  It 'Should not infer VCRedist from OS or managed framework imports' {
    $Path = Get-PortableTestPEFixture -Name 'no-vcredist.exe' -Machine 0x014C -Imports @('kernel32.dll', 'mscoree.dll')

    $Info = Get-PEDependencyInfo -Path $Path

    $Info.DependsOnVCRedist | Should -BeFalse
    $Info.RecommendedPackageDependencyIds | Should -BeNullOrEmpty
  }

  It 'Should inspect VC runtime imports from primary DLL files' {
    $Path = Get-PortableTestPEFixture -Name 'vcredist-x64.dll' -Machine 0x8664 -PE32Plus -Dll -Imports @('vcruntime140.dll')

    $Info = Get-PEDependencyInfo -Path $Path

    $Info.RecommendedPackageDependencyIds | Should -Contain 'Microsoft.VCRedist.2015+.x64'
    $Info.CheckedPEFiles | Should -Contain (Get-Item -LiteralPath $Path -Force).FullName
  }

  It 'Should inspect VC runtime imports from related DLL files' {
    $Path = Get-PortableTestPEFixture -Name 'main-no-import.exe' -Machine 0x8664 -PE32Plus
    $RelatedDll = Get-PortableTestPEFixture -Name 'related-vcredist-x64.dll' -Machine 0x8664 -PE32Plus -Dll -Imports @('msvcp120.dll')

    $Info = Get-PEDependencyInfo -Path $Path -RelatedFile $RelatedDll

    $Info.RecommendedPackageDependencyIds | Should -Contain 'Microsoft.VCRedist.2013.x64'
  }

  It 'Should map Tbox-like ASP.NET Core apphost runtimeconfig to a DotNet package dependency' {
    $Exe = Get-PortableTestPEFixture -Name 'TboxWebdav.Server.AspNetCore.exe' -Machine 0x8664 -PE32Plus
    $Dll = Get-PortableTestPEFixture -Name 'TboxWebdav.Server.AspNetCore.dll' -Machine 0x014C -Dll -ClrFlags 0x00000001 -TargetFramework '.NETCoreApp,Version=v8.0'
    $RuntimeConfig = New-PortableTestRuntimeConfig -Path (Join-Path $Script:PortableFixtureDirectory 'TboxWebdav.Server.AspNetCore.runtimeconfig.json') -Json @'
{
  "runtimeOptions": {
    "tfm": "net8.0",
    "frameworks": [
      { "name": "Microsoft.NETCore.App", "version": "8.0.0" },
      { "name": "Microsoft.AspNetCore.App", "version": "8.0.0" }
    ]
  }
}
'@

    $Info = Get-PEDependencyInfo -Path $Exe -RelatedFile @($Dll, $RuntimeConfig)

    $Info.DependsOnDotNetRuntime | Should -BeTrue
    $Info.DotNetInfo.IsDotNetAppHost | Should -BeTrue
    $Info.RecommendedPackageDependencyIds | Should -Contain 'Microsoft.DotNet.AspNetCore.8'
    $Info.RecommendedPackageDependencyIds | Should -Not -Contain 'Microsoft.DotNet.Runtime.8'
    ($Info.RecommendedPackageDependencies | Where-Object PackageIdentifier -EQ 'Microsoft.DotNet.AspNetCore.8').MinimumVersion | Should -Be '8.0.0'
  }

  It 'Should resolve runtimeconfig from the apphost-bound managed DLL path' {
    $Exe = Get-PortableTestPEFixture -Name 'BoundLauncher.exe' -Machine 0x8664 -PE32Plus -AppHostBinding 'app/RealProduct.dll'
    $Dll = Get-PortableTestPEFixture -Name 'app\RealProduct.dll' -Machine 0x014C -Dll -ClrFlags 0x00000001 -TargetFramework '.NETCoreApp,Version=v6.0'
    $RuntimeConfig = New-PortableTestRuntimeConfig -Path (Join-Path $Script:PortableFixtureDirectory 'app\RealProduct.runtimeconfig.json') -Json @'
{
  "runtimeOptions": {
    "framework": { "name": "Microsoft.NETCore.App", "version": "6.0.0" }
  }
}
'@

    $Info = Get-PEDependencyInfo -Path $Exe -RelatedFile @($Dll, $RuntimeConfig)

    $Info.DotNetInfo.AppHostInfo.IsBound | Should -BeTrue
    $Info.DotNetInfo.BoundAssemblyRelativePath | Should -Be 'app/RealProduct.dll'
    $Info.DotNetInfo.RuntimeConfigPath | Should -Be (Get-Item -LiteralPath $RuntimeConfig).FullName
    $Info.RecommendedPackageDependencyIds | Should -Contain 'Microsoft.DotNet.Runtime.6'
  }

  It 'Should parse embedded runtimeconfig from a single-file bundle header' {
    $RuntimeConfigJson = @'
{
  "runtimeOptions": {
    "frameworks": [
      { "name": "Microsoft.NETCore.App", "version": "8.0.0" },
      { "name": "Microsoft.WindowsDesktop.App", "version": "8.0.0" }
    ]
  }
}
'@
    $Exe = Get-PortableTestPEFixture -Name 'SingleFileBundle.exe' -Machine 0x8664 -PE32Plus -BundleRuntimeConfigJson $RuntimeConfigJson

    $Info = Get-PEDependencyInfo -Path $Exe

    $Info.DotNetInfo.IsDotNetAppHost | Should -BeTrue
    $Info.DotNetInfo.AppHostInfo.BundleInfo.RuntimeConfigJson | Should -Not -BeNullOrEmpty
    $Info.DotNetInfo.RuntimeConfigPath | Should -BeLike 'bundle:*'
    $Info.RecommendedPackageDependencyIds | Should -Contain 'Microsoft.DotNet.DesktopRuntime.8'
    $Info.RecommendedPackageDependencyIds | Should -Not -Contain 'Microsoft.DotNet.Runtime.8'
  }

  It 'Should map Windows Desktop runtimeconfig and suppress same-major NETCore runtime' {
    $Dll = Get-PortableTestPEFixture -Name 'DesktopApp.dll' -Machine 0x014C -Dll -ClrFlags 0x00000001 -TargetFramework '.NETCoreApp,Version=v7.0'
    $RuntimeConfig = New-PortableTestRuntimeConfig -Path (Join-Path $Script:PortableFixtureDirectory 'DesktopApp.runtimeconfig.json') -Json @'
{
  "runtimeOptions": {
    "frameworks": [
      { "name": "Microsoft.NETCore.App", "version": "7.0.0" },
      { "name": "Microsoft.WindowsDesktop.App", "version": "7.0.0" }
    ]
  }
}
'@

    $Info = Get-PEDependencyInfo -Path $Dll -RelatedFile $RuntimeConfig

    $Info.RecommendedPackageDependencyIds | Should -Contain 'Microsoft.DotNet.DesktopRuntime.7'
    $Info.RecommendedPackageDependencyIds | Should -Not -Contain 'Microsoft.DotNet.Runtime.7'
  }

  It 'Should recommend both Desktop and ASP.NET Core when both specific frameworks are present' {
    $Dll = Get-PortableTestPEFixture -Name 'HybridApp.dll' -Machine 0x014C -Dll -ClrFlags 0x00000001 -TargetFramework '.NETCoreApp,Version=v9.0'
    $RuntimeConfig = New-PortableTestRuntimeConfig -Path (Join-Path $Script:PortableFixtureDirectory 'HybridApp.runtimeconfig.json') -Json @'
{
  "runtimeOptions": {
    "frameworks": [
      { "name": "Microsoft.NETCore.App", "version": "9.0.0" },
      { "name": "Microsoft.WindowsDesktop.App", "version": "9.0.0" },
      { "name": "Microsoft.AspNetCore.App", "version": "9.0.0" }
    ]
  }
}
'@

    $Info = Get-PEDependencyInfo -Path $Dll -RelatedFile $RuntimeConfig

    $Info.RecommendedPackageDependencyIds | Should -Contain 'Microsoft.DotNet.DesktopRuntime.9'
    $Info.RecommendedPackageDependencyIds | Should -Contain 'Microsoft.DotNet.AspNetCore.9'
    $Info.RecommendedPackageDependencyIds | Should -Not -Contain 'Microsoft.DotNet.Runtime.9'
  }

  It 'Should not recommend DotNet dependencies for bundled runtime evidence' {
    $BundledDirectory = Join-Path $Script:PortableFixtureDirectory 'BundledRuntime'
    $null = New-Item -Path $BundledDirectory -ItemType Directory -Force
    $Dll = Get-PortableTestPEFixture -Name 'BundledRuntime\SelfContained.dll' -Machine 0x014C -Dll -ClrFlags 0x00000001 -TargetFramework '.NETCoreApp,Version=v8.0'
    $RuntimeConfig = New-PortableTestRuntimeConfig -Path (Join-Path $BundledDirectory 'SelfContained.runtimeconfig.json') -Json @'
{
  "runtimeOptions": {
    "includedFrameworks": [
      { "name": "Microsoft.NETCore.App", "version": "8.0.17" },
      { "name": "Microsoft.AspNetCore.App", "version": "8.0.17" }
    ]
  }
}
'@
    $HostFxr = New-PortableTestBundledRuntimeMarker -Path (Join-Path $BundledDirectory 'hostfxr.dll')

    $Info = Get-PEDependencyInfo -Path $Dll -RelatedFile @($RuntimeConfig, $HostFxr)

    $Info.DependsOnDotNetRuntime | Should -BeFalse
    $Info.DotNetInfo.IsRuntimeBundled | Should -BeTrue
    $Info.RecommendedPackageDependencyIds | Should -BeNullOrEmpty
  }

  It 'Should warn for unknown DotNet frameworks and unsupported dependency majors' {
    $Dll = Get-PortableTestPEFixture -Name 'UnsupportedDotNet.dll' -Machine 0x014C -Dll -ClrFlags 0x00000001 -TargetFramework '.NETCoreApp,Version=v11.0'
    $RuntimeConfig = New-PortableTestRuntimeConfig -Path (Join-Path $Script:PortableFixtureDirectory 'UnsupportedDotNet.runtimeconfig.json') -Json @'
{
  "runtimeOptions": {
    "frameworks": [
      { "name": "Contoso.Runtime", "version": "1.0.0" },
      { "name": "Microsoft.NETCore.App", "version": "11.0.0" }
    ]
  }
}
'@

    $Info = Get-PEDependencyInfo -Path $Dll -RelatedFile $RuntimeConfig

    $Info.RecommendedPackageDependencyIds | Should -BeNullOrEmpty
    $Info.Warnings | Should -Contain "Unknown .NET runtimeconfig framework 'Contoso.Runtime' was found; dependency mapping requires manual review."
    $Info.Warnings | Should -Contain "Runtimeconfig framework 'Microsoft.NETCore.App' version '11.0.0' is outside the supported Microsoft.DotNet dependency majors 5-10."
  }

  It 'Should warn when a managed .NET 5+ DLL has no runtimeconfig sidecar' {
    $Dll = Get-PortableTestPEFixture -Name 'NoRuntimeConfig.dll' -Machine 0x014C -Dll -ClrFlags 0x00000001 -TargetFramework '.NETCoreApp,Version=v6.0'

    $Info = Get-PEDependencyInfo -Path $Dll

    $Info.Warnings[0] | Should -BeLike '*has no runtimeconfig sidecar*'
  }

  It 'Should keep compatibility VCRedist wrapper names available' {
    $Path = Get-PortableTestPEFixture -Name 'wrapper-vcredist.exe' -Machine 0x014C -Imports @('msvcp100.dll')

    (Get-PortableExecutableVCRedistInfo -Path $Path).RecommendedPackageDependencyIds | Should -Contain 'Microsoft.VCRedist.2010.x86'
    Test-PortableExecutableVCRedistDependency -Path $Path | Should -BeTrue
  }
}

Describe 'Portable evidence in the WinGet installer analyzer' {
  It 'Should include portable evidence for loose PE files' {
    $Path = Get-PortableTestPEFixture -Name 'portable-analyzer.exe' -Machine 0x8664 -PE32Plus -Imports @('vcruntime140.dll')

    $Analysis = Get-WinGetInstallerAnalysis -Path $Path

    $Analysis.DetectedFileType.Type | Should -Be 'PE'
    $Analysis.PortableEvidence.RecommendedWinGetArchitecture | Should -Be 'x64'
    $Analysis.PortableEvidence.RecommendedPackageDependencyIds | Should -Contain 'Microsoft.VCRedist.2015+.x64'
    $Analysis.PortableEvidence.DependencyInfo.DependsOnVCRedist | Should -BeTrue
  }

  It 'Should include portable evidence for loose DLL files' {
    $Path = Get-PortableTestPEFixture -Name 'portable-analyzer.dll' -Machine 0x8664 -PE32Plus -Dll -Imports @('vcruntime140.dll')

    $Analysis = Get-WinGetInstallerAnalysis -Path $Path

    $Analysis.DetectedFileType.Type | Should -Be 'PE'
    $Analysis.PortableEvidence.ArchitectureInfo.FileKind | Should -Be 'Dll'
    $Analysis.PortableEvidence.RecommendedWinGetArchitecture | Should -Be 'x64'
    $Analysis.PortableEvidence.RecommendedPackageDependencyIds | Should -Contain 'Microsoft.VCRedist.2015+.x64'
  }

  It 'Should include portable evidence for ZIP portable candidates' {
    $SourceDirectory = Join-Path $Script:PortableFixtureDirectory 'ZipSource'
    $null = New-Item -Path $SourceDirectory -ItemType Directory -Force
    $PortablePath = Get-PortableTestPEFixture -Name 'Product.exe' -Machine 0x014C -Imports @('msvcr120.dll')
    Copy-Item -LiteralPath $PortablePath -Destination (Join-Path $SourceDirectory 'Product.exe') -Force
    $ZipPath = Join-Path $Script:PortableFixtureDirectory 'Product.zip'
    Compress-Archive -Path (Join-Path $SourceDirectory '*') -DestinationPath $ZipPath -Force

    $Analysis = Get-WinGetInstallerAnalysis -Path $ZipPath
    $ZipResult = $Analysis.ParserResults[0]

    $Analysis.DetectedFileType.Type | Should -Be 'ZipArchive'
    $ZipResult.PortableCandidateEvidence[0].RelativeFilePath | Should -Be 'Product.exe'
    $ZipResult.PortableCandidateEvidence[0].Evidence.RecommendedWinGetArchitecture | Should -Be 'x86'
    $ZipResult.PortableCandidateEvidence[0].Evidence.RecommendedPackageDependencyIds | Should -Contain 'Microsoft.VCRedist.2013.x86'
  }

  It 'Should include runtimeconfig sidecars for ZIP portable candidates' {
    $SourceDirectory = Join-Path $Script:PortableFixtureDirectory 'ZipDotNetSource'
    $null = New-Item -Path $SourceDirectory -ItemType Directory -Force
    $Exe = Get-PortableTestPEFixture -Name 'ZipDotNet.exe' -Machine 0x8664 -PE32Plus
    $Dll = Get-PortableTestPEFixture -Name 'ZipDotNet.dll' -Machine 0x014C -Dll -ClrFlags 0x00000001 -TargetFramework '.NETCoreApp,Version=v8.0'
    Copy-Item -LiteralPath $Exe -Destination (Join-Path $SourceDirectory 'ZipDotNet.exe') -Force
    Copy-Item -LiteralPath $Dll -Destination (Join-Path $SourceDirectory 'ZipDotNet.dll') -Force
    New-PortableTestRuntimeConfig -Path (Join-Path $SourceDirectory 'ZipDotNet.runtimeconfig.json') -Json @'
{
  "runtimeOptions": {
    "framework": { "name": "Microsoft.NETCore.App", "version": "8.0.0" }
  }
}
'@ | Out-Null
    $ZipPath = Join-Path $Script:PortableFixtureDirectory 'ZipDotNet.zip'
    Compress-Archive -Path (Join-Path $SourceDirectory '*') -DestinationPath $ZipPath -Force

    $Analysis = Get-WinGetInstallerAnalysis -Path $ZipPath
    $ZipResult = $Analysis.ParserResults[0]

    $ZipResult.PortableCandidateEvidence[0].RelativeFilePath | Should -Be 'ZipDotNet.exe'
    $ZipResult.PortableCandidateEvidence[0].RelatedFilePaths.Count | Should -BeGreaterThan 0
    $ZipResult.PortableCandidateEvidence[0].Evidence.RecommendedPackageDependencyIds | Should -Contain 'Microsoft.DotNet.Runtime.8'
  }

  It 'Should prefer apphost candidates over bundled runtime helper executables in ZIP archives' {
    $SourceDirectory = Join-Path $Script:PortableFixtureDirectory 'ZipWithRuntimeSource'
    $null = New-Item -Path $SourceDirectory -ItemType Directory -Force
    $Createdump = Get-PortableTestPEFixture -Name 'createdump.exe' -Machine 0x8664 -PE32Plus
    $Exe = Get-PortableTestPEFixture -Name 'ZipWithRuntime.exe' -Machine 0x8664 -PE32Plus -AppHostBinding 'ZipWithRuntime.dll'
    $Dll = Get-PortableTestPEFixture -Name 'ZipWithRuntime.dll' -Machine 0x014C -Dll -ClrFlags 0x00000001 -TargetFramework '.NETCoreApp,Version=v8.0'
    Copy-Item -LiteralPath $Createdump -Destination (Join-Path $SourceDirectory 'createdump.exe') -Force
    Copy-Item -LiteralPath $Exe -Destination (Join-Path $SourceDirectory 'ZipWithRuntime.exe') -Force
    Copy-Item -LiteralPath $Dll -Destination (Join-Path $SourceDirectory 'ZipWithRuntime.dll') -Force
    New-PortableTestRuntimeConfig -Path (Join-Path $SourceDirectory 'ZipWithRuntime.runtimeconfig.json') -Json @'
{
  "runtimeOptions": {
    "includedFrameworks": [
      { "name": "Microsoft.NETCore.App", "version": "8.0.17" },
      { "name": "Microsoft.AspNetCore.App", "version": "8.0.17" }
    ]
  }
}
'@ | Out-Null
    foreach ($MarkerName in @('hostfxr.dll', 'hostpolicy.dll', 'coreclr.dll', 'System.Private.CoreLib.dll')) {
      New-PortableTestBundledRuntimeMarker -Path (Join-Path $SourceDirectory $MarkerName) | Out-Null
    }
    1..80 | ForEach-Object -Process {
      New-PortableTestBundledRuntimeMarker -Path (Join-Path $SourceDirectory "Library$_.dll") | Out-Null
    }
    $ZipPath = Join-Path $Script:PortableFixtureDirectory 'ZipWithRuntime.zip'
    Compress-Archive -Path (Join-Path $SourceDirectory '*') -DestinationPath $ZipPath -Force

    $Analysis = Get-WinGetInstallerAnalysis -Path $ZipPath
    $ZipResult = $Analysis.ParserResults[0]

    $ZipResult.PortableCandidateEvidence.RelativeFilePath | Should -Contain 'ZipWithRuntime.exe'
    $ZipResult.PortableCandidateEvidence.RelativeFilePath | Should -Not -Contain 'createdump.exe'
    $ZipResult.PortableCandidateEvidence[0].Evidence.DependencyInfo.DotNetInfo.IsRuntimeBundled | Should -BeTrue
    $ZipResult.PortableCandidateEvidence[0].Evidence.DependencyInfo.DotNetInfo.BundledRuntimeFiles.Count | Should -Be 4
    $ZipResult.PortableCandidateEvidence[0].Evidence.RecommendedPackageDependencyIds | Should -BeNullOrEmpty
  }

  It 'Should include DLL portable candidates only when runtimeconfig sidecar exists' {
    $SourceDirectory = Join-Path $Script:PortableFixtureDirectory 'ZipDllSource'
    $null = New-Item -Path $SourceDirectory -ItemType Directory -Force
    $AppDll = Get-PortableTestPEFixture -Name 'DllApp.dll' -Machine 0x014C -Dll -ClrFlags 0x00000001 -TargetFramework '.NETCoreApp,Version=v8.0'
    $LibraryDll = Get-PortableTestPEFixture -Name 'LibraryOnly.dll' -Machine 0x8664 -PE32Plus -Dll
    Copy-Item -LiteralPath $AppDll -Destination (Join-Path $SourceDirectory 'DllApp.dll') -Force
    Copy-Item -LiteralPath $LibraryDll -Destination (Join-Path $SourceDirectory 'LibraryOnly.dll') -Force
    New-PortableTestRuntimeConfig -Path (Join-Path $SourceDirectory 'DllApp.runtimeconfig.json') -Json @'
{
  "runtimeOptions": {
    "framework": { "name": "Microsoft.NETCore.App", "version": "8.0.0" }
  }
}
'@ | Out-Null
    $ZipPath = Join-Path $Script:PortableFixtureDirectory 'ZipDll.zip'
    Compress-Archive -Path (Join-Path $SourceDirectory '*') -DestinationPath $ZipPath -Force

    $Analysis = Get-WinGetInstallerAnalysis -Path $ZipPath
    $ZipResult = $Analysis.ParserResults[0]

    $ZipResult.PortableCandidateEvidence.RelativeFilePath | Should -Contain 'DllApp.dll'
    $ZipResult.PortableCandidateEvidence.RelativeFilePath | Should -Not -Contain 'LibraryOnly.dll'
  }
}
