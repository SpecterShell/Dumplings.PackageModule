# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Force stop on error
$ErrorActionPreference = 'Stop'

function Read-MsiProperty {
  <#
  .SYNOPSIS
    Query a value from the MSI file using SQL-like query
  .PARAMETER Path
    The path to the MSI file
  .PARAMETER PatchFile
    Indicate the file is a patch file
  .PARAMETER TransformPath
    The path to the transform files to be applied
  .PARAMETER Query
    The SQL-like query
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSI file')]
    [string]$Path,

    [Parameter(HelpMessage = 'Indicate the file is a patch file')]
    [switch]$PatchFile,

    [Parameter(HelpMessage = 'The path to the transform file to be applied')]
    [AllowNull()]
    [string]$TransformPath,

    [Parameter(Mandatory, HelpMessage = 'The SQL-like query')]
    [string]$Query
  )

  begin {
    $WindowsInstaller = New-Object -ComObject 'WindowsInstaller.Installer'
  }

  process {
    # Obtain the absolute path of the file
    $Path = (Get-Item -Path $Path -Force).FullName
    $OpenMode = $PatchFile ? 32 : 0
    $Database = $WindowsInstaller.OpenDatabase($Path, $OpenMode)

    # Apply the transform if specified
    if ($TransformPath) {
      $TransformPath = (Get-Item -Path $TransformPath -Force).FullName
      Write-Host $Path $TransformPath
      $Database.ApplyTransform($TransformPath, 0)
    }

    $View = $Database.OpenView($Query)
    $View.Execute() | Out-Null
    $Record = $View.Fetch()
    Write-Output -InputObject ($Record.GetType().InvokeMember('StringData', 'GetProperty', $null, $Record, 1))

    [System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($View) | Out-Null
    [System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($Database) | Out-Null
  }

  end {
    [System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($WindowsInstaller) | Out-Null
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
  }
}

function Read-ProductVersionFromMsi {
  <#
  .SYNOPSIS
    Read the ProductVersion property value from the MSI file
  .PARAMETER Path
    The path to the MSI file
  .PARAMETER TransformPath
    The path to the transform file to be applied
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSI file')]
    [string]$Path,

    [Parameter(HelpMessage = 'The path to the transform file to be applied')]
    [string]$TransformPath
  )

  process {
    Read-MsiProperty @PSBoundParameters -Query "SELECT Value FROM Property WHERE Property='ProductVersion'"
  }
}

function Read-ProductCodeFromMsi {
  <#
  .SYNOPSIS
    Read the ProductCode property value from the MSI file
  .PARAMETER Path
    The path to the MSI file
  .PARAMETER TransformPath
    The path to the transform files to be applied
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSI file')]
    [string]$Path,

    [Parameter(HelpMessage = 'The path to the transform file to be applied')]
    [string]$TransformPath
  )

  process {
    Read-MsiProperty @PSBoundParameters -Query "SELECT Value FROM Property WHERE Property='ProductCode'"
  }
}

function Read-UpgradeCodeFromMsi {
  <#
  .SYNOPSIS
    Read the UpgradeCode property value from the MSI file
  .PARAMETER Path
    The path to the MSI file
  .PARAMETER TransformPath
    The path to the transform files to be applied
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSI file')]
    [string]$Path,

    [Parameter(HelpMessage = 'The path to the transform file to be applied')]
    [string]$TransformPath
  )

  process {
    Read-MsiProperty @PSBoundParameters -Query "SELECT Value FROM Property WHERE Property='UpgradeCode'"
  }
}

function Read-ProductNameFromMsi {
  <#
  .SYNOPSIS
    Read the ProductName property value from the MSI file
  .PARAMETER Path
    The path to the MSI file
  .PARAMETER TransformPath
    The path to the transform files to be applied
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the MSI file')]
    [string]$Path,

    [Parameter(HelpMessage = 'The path to the transform file to be applied')]
    [string]$TransformPath
  )

  process {
    Read-MsiProperty @PSBoundParameters -Query "SELECT Value FROM Property WHERE Property='ProductName'"
  }
}

function Read-MsiSummaryValue {
  <#
  .SYNOPSIS
    Read a specified property value from the summary table of the MSI file
  .PARAMETER Path
    The MSI file path
  .PARAMETER Name
    The property name
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The MSI file path')]
    [string]$Path,

    [Parameter(Mandatory, HelpMessage = 'The property name')]
    [ValidateSet('Codepage', 'Title', 'Subject', 'Author', 'Keywords', 'Comments', 'Template', 'LastAuthor', 'RevNumber', 'EditTime', 'LastPrinted', 'CreateDtm', 'LastSaveDtm', 'PageCount', 'WordCount', 'CharCount', 'AppName', 'Security')]
    [string]$Name
  )

  begin {
    $WindowsInstaller = New-Object -ComObject 'WindowsInstaller.Installer'
    $Index = switch ($Name) {
      'Codepage' { 1 }
      'Title' { 2 }
      'Subject' { 3 }
      'Author' { 4 }
      'Keywords' { 5 }
      'Comments' { 6 }
      'Template' { 7 }
      'LastAuthor' { 8 }
      'RevNumber' { 9 }
      'EditTime' { 10 }
      'LastPrinted' { 11 }
      'CreateDtm' { 12 }
      'LastSaveDtm' { 13 }
      'PageCount' { 14 }
      'WordCount' { 15 }
      'CharCount' { 16 }
      'AppName' { 18 }
      'Security' { 19 }
      default { throw 'No such property or property not supported' }
    }
  }

  process {
    # Obtain the absolute path of the file
    $Path = (Get-Item -Path $Path -Force).FullName

    $Database = $WindowsInstaller.OpenDatabase($Path, 0)
    $SummaryInfo = $Database.GetType().InvokeMember('SummaryInformation', 'GetProperty', $null , $Database, $null)
    Write-Output -InputObject ($SummaryInfo.GetType().InvokeMember('Property', 'GetProperty', $Null, $SummaryInfo, $Index))

    [System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($SummaryInfo) | Out-Null
    [System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($Database) | Out-Null
  }

  end {
    [System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($WindowsInstaller) | Out-Null
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
  }
}
