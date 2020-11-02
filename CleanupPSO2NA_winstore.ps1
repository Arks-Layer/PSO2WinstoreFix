# Script failed to start in Windows PowerShell ISE, run this to disable the block policy
#
#	Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy ByPass -Confirm:$false
#
# and if that fails,try this comamand:
#
#	Set-ExecutionPolicy -Scope Process -ExecutionPolicy ByPass -Confirm:$false
#

Param(
	[Bool]$ForceReinstall = $true,
	[Bool]$TweakerMode = $false,
	[Bool]$PauseOnFail = $true,
	[Bool]$SkipRobomove = $false,
	[Bool]$ForceLocalInstall = $false,
	[Bool]$SkipStorageCheck = $false,
	[Bool]$SkipOneDrive = $false,
	[Bool]$ForceReHash = $false
)

$VersionScript = "Version 2020_08_29_1331" # Error codes: 41

<#
.SYNOPSIS
Register custom PSO2NA installation into APPX to allow XBOX login
.DESCRIPTION
This script tries to fix anything what would break XBOX and APPX registation
.PARAMETER ForceReinstall
Allow one to force to register the APPX package
.PARAMETER TweakerMode
Allow PSO2 Tweaker to run the script without any user interaction
.PARAMETER PauseOnFail
Pause the script if it get to a handled fail path
.PARAMETER SkipRobomove
Skip over moving the PSO2NA data files from MS Store folders
.PARAMETER ForceLocalInstall
Force to use APPX files from an outside source, not the MS Store
.PARAMETER SkipStorageCheck
Skip checking the volumes, in case of a broken disk management system
.PARAMETER SkipOneDrive
Skip checking OneDrive folders
.PARAMETER ForceReHash
Force remaking PSO2 Tweaker's client_na.json
.INPUTS
None. You cannot pipe objects to pso2_winstore_fix.ps1.
.OUTPUTS
None. pso2_winstore_fix.ps1 does not generate any output for systems, only humans
.EXAMPLE
PS> .\pso2_winstore_fix.ps1
.EXAMPLE
PS> .\pso2_winstore_fix.ps1 -SkipStorageCheck $true
.EXAMPLE
PS> .\pso2_winstore_fix.ps1 -TweakerMode $true -ForceReHash $true
#>

Function PauseAndFail {
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory=$true)]
		[Int]
		$ErrorLevel,
		[Parameter(Mandatory=$true, ValueFromPipeline=$true)]
		[String]
		$ErrorMessage
	)
	PROCESS
	{
		$ErrorMessage
		If ($PauseOnFail -eq $true)
		{
			[System.Windows.MessageBox]::Show($ErrorMessage) | Out-Null
		}
	}
	END
	{
		Stop-Transcript
		SetConsoleQuickEdit -Mode $true
		If ($PauseOnFail -eq $false)
		{
			exit $ErrorLevel
		}
		ElseIf ((Test-Path variable:global:psISE) -eq $true -or $true)
		{
			#[System.Windows.MessageBox]::Show($ErrorMessage)
			exit $ErrorLevel
		}
		Else
		{
			Write-Host -Object ""
			Write-Host -Object "Press any key to exit."
			$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
			exit $ErrorLevel
		}
	}
}

#All the fun helper functinons
#region helper_functinons
#Crash hander
Function Failure
{
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory=$true, ValueFromPipeline=$true)]
		[ValidateNotNullOrEmpty()]
		$Error
	)
	PROCESS
	{
try {
		$script:result = $Error.Exception.Response.GetResponseStream()
		$script:reader = New-Object System.IO.StreamReader($script:result)
		$script:responseBody = $script:reader.ReadToEnd();
		Write-Host -Object "Status: A system exception was caught."
		Write-Host -Object $script:responsebody
} catch {$_}
	}
	END
	{
		Stop-Transcript
		$null = $global:Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	}
	#exit 254
}

#Downloader
Function DownloadMe
{
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]
		$URI,
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]
		$OutFile,
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[Int]
		$ErrorLevel,
		[bool]
		$Overwrite = $false,
		[String]
		$SHA512 = $null
	)
	If (Test-Path -LiteralPath $OutFile -PathType Leaf)
	{
		$FileHash = Get-FileHash -LiteralPath $OutFile -Algorithm SHA512 -Verbose
		If ($FileHash.Hash -ne $SHA512)
		{
			$OverWrite = $true
		}
	}
	If ($OverWrite)
	{
		Remove-Item -Path $OutFile -ErrorAction SilentlyContinue
	}
	Try
	{
		If (-Not (Test-Path -LiteralPath $OutFile -PathType Leaf))
		{
			Invoke-WebRequest -Uri $URI -OutFile $OutFile -UserAgent "Arks-Layer pso2_winstore_fix" -Verbose
		}
		If (Test-Path -LiteralPath $OutFile -PathType Leaf)
		{
			$FileHash = Get-FileHash -LiteralPath $OutFile -Algorithm SHA512 -Verbose
			If ($null -ne $SHA512 -and $FileHash.Hash -ne $SHA512)
			{
				Write-Host -Object ""
				Write-Host -Object "Error: Failed to download file! The File had been does not match the checksum"
				Write-Host -Object ""
				Write-Host -Object $URI
				Write-Host -Object ""
				"Download Failed" | PauseAndFail -ErrorLevel $ErrorLevel
			}
		}
		Else
		{
			Write-Host -Object ""
			Write-Host -Object "Error: Failed to download file! You can manually download it by using the link below and saving it to the same place this script is:"
			Write-Host -Object ""
			Write-Host -Object $URI
			Write-Host -Object ""
			"Download Failed" | PauseAndFail -ErrorLevel $ErrorLevel
		}
		Return Resolve-Path -LiteralPath $OutFile
	}
	Catch
	{
		$_ | Failure
		"BAD CRASH" | PauseAndFail -ErrorLevel $ErrorLevel
	}
}

Function Get-OnlineAppxVolumes {
	[CmdletBinding()]

	$OnlineAppxVolumes = @()
	try {
		$OnlineAppxVolumes += Get-AppxVolume -Online -Verbose
	} catch {$_}
	Return $OnlineAppxVolumes
}

#Package version check
Function PackageVersion
{
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory=$true, ValueFromPipeline=$true)]
		[AllowNull()]
		[Object[]]
		$Packages,
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[Version]
		$Version,
		[String]
		$Architecture = "X64"
	)
	PROCESS
	{
		Write-Verbose -Message $Version
		Return $Packages | Where-Object -Property Architecture -EQ $Architecture | Where-Object -FilterScript {[Version]$_.Version -ge $Version}
	}
}

# Find MutableBackup
# Function FindMutableBackup
<#
.SYNOPSIS
Find MutableBackup of an app
.PARAMETER AppxPackageName
Name parameter of the Appx package manifest
#>
Function Find-AppxMutableBackups {
	[CmdletBinding()]
	Param
	(
		[String]
		$AppxPackageName = "100B7A24.oxyna"
	)
	PROCESS
	{
		Write-Verbose -Message $AppxPackageName
		$Mutable = @()
		$Mutable += Get-OnlineAppxVolumes | ForEach-Object -Process {
			$Test = Join-Path $_.PackageStorePath -ChildPath "MutableBackup"
			If (Test-Path -LiteralPath $Test -PathType Container)
			{
				Return Resolve-Path -LiteralPath $Test -Verbose
			}
		}
		$Backups = @()
		$Backups += $Mutable | ForEach-Object -Process {
			Return Get-ChildItem -LiteralPath $_.ProviderPath -Filter "$($AppxPackageName)*"
		} | Sort-Object -Descending LastWriteTime
		If ($Backups.Count -gt 0)
		{
			$Backups.FullName
		}
	}
}

function RobomoveByFolder {
	[CmdletBinding()]
	Param
	(
		[String]
		$source = ".",
		[String]
		$destination = ".",
		[String]
		$file = "*.*",
		[Bool]
		$Details = $false,
		[Bool]
		$SkipRemove = $false,
		[String]
		$logfile = "robocopy.log"

	)
	If ($SkipRobomove -eq $true)
	{
		return
	}
	If (-Not (Test-Path -LiteralPath $source -PathType Container))
	{
		Write-Host -Object "ERROR: $($source) is not a folder"
		return
	}
	If (-Not (Test-Path -LiteralPath $destination -PathType Container))
	{
		New-Item -Path $destination -ItemType Directory -Verbose -ErrorAction Continue | Out-Null
		If (-Not (Test-Path -LiteralPath $destination -PathType Container))
		{
			return
		}
	}
	If (-Not (Test-Path -LiteralPath $logfile -PathType Leaf))
	{
		New-Item -Path $logfile -ItemType File #-WhatIf
	}
	$logpath = Resolve-Path -LiteralPath $logfile
	If ($file -eq "*.*" -or $file -eq "0*.*" -and $SkipRemove -eq $false)
	{
		Write-Host -Object "Deleting broken patch files..."
		Get-ChildItem -LiteralPath $source -Force -File -ErrorAction Continue | Where-Object Extension -eq ".pat" | Remove-Item -Force -ErrorAction Continue
		Write-Host -Object "Deleting empty files in the source folder..."
		Get-ChildItem -LiteralPath $source -Force -File -ErrorAction Continue | Where-Object Length -eq 0 | Remove-Item -Force -ErrorAction Continue
	}
	If ($SkipRemove -eq $false)
	{
		Write-Host -Object "Deleting empty files in the dest folder..."
		$EmptyFiles = @() + (Get-ChildItem -LiteralPath $destination -Force -File -ErrorAction Continue | Where-Object Length -eq 0)
		If ($EmptyFiles.Count -gt 0)
		{
			$JSONObj.PSO2NARemoteVersion = 0
			$JSONObj | ConvertTo-Json | Out-File -FilePath $JSONPath -Encoding UTF8
			$EmptyFiles | Remove-Item -Force -ErrorAction Continue
			If (Test-Path -Path "client_na.json" -PathType Leaf)
			{
				Remove-Item -Path "client_na.json" -Force -Verbose
			}
		}
	}
	Write-Host -Object "Starting robocopy job..."
	$Cmdlist = "/C","Robocopy.exe", ('"{0}"' -f $source),('"{0}"' -f $destination),('"{0}"' -f $file),"/XF","*.pat","/TEE","/DCOPY:DA","/COPY:DAT","/MOV","/ZB","/ETA","/XO","/R:0","/W:1",('/LOG+:"{0}"' -f $logpath.Path)
	If ($Details -eq $true)
	{
		$Cmdlist += "/V"
	}
	Start-Process -FilePath $env:ComSpec -ArgumentList $Cmdlist -WorkingDirectory $env:SystemRoot -WindowStyle Minimized -Wait -Verbose
	If ($SkipRemove -eq $false)
	{
		Write-Host -Object "Deleting source files..."
		Get-ChildItem -LiteralPath $source -Filter $file -Depth 0 -Force -File -ErrorAction Continue | Remove-Item -Force -ErrorAction Continue
	}
	$Subs = @()
	$Subs += Get-ChildItem -Directory -Depth 0 -LiteralPath $source -ErrorAction Continue | Where-Object Name -ne "script" | Where-Object Name -Ne "backup"
	If ($Subs.Count -gt 0)
	{
		$Subs | ForEach-Object -Process {
			$NewSub = $_.Name
			$FilesCount = @()
			$DirsCount = @()
			If ($NewSub -notlike "win32*")
			{
				Write-Host -Object "Counting Files..."
				$FilesCount += Get-ChildItem -LiteralPath $_.FullName -Force -File -ErrorAction Continue | Where-Object BaseName -NotLike "*.pat"
				Write-Host -Object "Counting Folders..."
				$DirsCount += Get-ChildItem -LiteralPath $_.FullName -Force -Directory -ErrorAction Continue
				Write-Host -Object "Digging into $($_.FullName) Folder"
				Write-Host -Object "	$($FilesCount.Count) Files"
				Write-Host -Object "	$($DirsCount.Count) Directories"
			}
			If ($NewSub -Like "win32*")
			{
				(0..0xf | ForEach-Object -Process { $_.ToString("X1") }) | ForEach-Object -Process {
					Write-Host -Object ""
					Write-Host -Object "WARNING: a folder that MAY have a large number of files detected, only moving files starting with $($_) of (0123456789ABCDEF)"
					Write-Host -Object ""
					RobomoveByFolder -source (Join-Path $source -ChildPath $NewSub) -destination (Join-Path $destination -ChildPath $NewSub) -file ('{0}*.*' -f $_) -Details $true -SkipRemove $SkipRemove -logfile $logpath.Path
				}
			}
			ElseIf ($FilesCount.Count -gt 100)
			{
				Write-Host -Object ""
				Write-Host -Object ""
				Write-Host -Object ""
				Write-Host -Object ""
				Write-Host -Object ""
				Write-Host -Object "WARNING: large number of files detected - this may take a while, maybe even A LONG TIME! Please wait!"
				Write-Host -Object "WARNING: large number of files detected - this may take a while, maybe even A LONG TIME! Please wait!"
				Write-Host -Object "WARNING: large number of files detected - this may take a while, maybe even A LONG TIME! Please wait!"
				Write-Host -Object "WARNING: large number of files detected - this may take a while, maybe even A LONG TIME! Please wait!"
				Write-Host -Object "WARNING: large number of files detected - this may take a while, maybe even A LONG TIME! Please wait!"
				Write-Host -Object ""
				RobomoveByFolder -source (Join-Path $source -ChildPath $NewSub) -destination (Join-Path $destination -ChildPath $NewSub) -Details $true -SkipRemove $SkipRemove -logfile $logpath.Path
			}
			else
			{
				RobomoveByFolder -source (Join-Path $source -ChildPath $NewSub) -destination (Join-Path $destination -ChildPath $NewSub) -Details $false -SkipRemove $SkipRemove -logfile $logpath.Path
			}
		}
	}
}

function Takeownship {
	[CmdletBinding()]
	Param
	(
		[String]
		$path = "."

	)
	$takeownEXE = "$($Env:SystemRoot)\System32\takeown.exe"
	If (Test-Path -LiteralPath $takeownEXE)
	{
		Write-Host -Object "Reseting ACL of $($path)"
		Start-Process -FilePath $takeownEXE -ArgumentList "/R","/A","/F",('"{0}"' -f $path) -WorkingDirectory $env:SystemRoot -WindowStyle Normal -Wait -Verbose
		#we can not use"/D Y" only work on English, we need to ask the user in a non-Powershell window
	}
	Else
	{
		Write-Host -Object "WARNING: Takeown.exe is missing from your system32 folder!"
	}
}

Function PauseOnly {
	[CmdletBinding()]
	Param
	(
		[Parameter(ValueFromPipeline=$true)]
		[String]
		$PauseMessage = "Click OK to keep going."
	)
	PROCESS
	{
		$PauseMessage
	}
	END
	{
		If ((Test-Path variable:global:psISE) -eq $true -or $true)
		{
			[System.Windows.MessageBox]::Show($PauseMessage) | Out-Null
		}
		Else
		{
			Write-Host -Object ""
			Write-Host -Object "Press any key to continue."
			$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
		}
	}
}

Function Window10Version
{
	Param
	(

		[Parameter(Mandatory=$true)]
		[Int]
		$Build
	)
	Switch ($Build)
	{
		10240 {Return "1507"}
		10586 {Return "1511"}
		14393 {Return "1607"}
		15063 {Return "1703"}
		16299 {Return "1709"}
		17134 {Return "1803"}
		17763 {Return "1809"}
		18362 {Return "1903"}
		18363 {Return "1909"}
		19041 {Return "2004"}
	}
	Return "Unknown"
}

# Function FindMutable_Appx
<#
.SYNOPSIS
Find MutablePackageDirectory or, better known by the implementation name, ModifiableWindowsApps folders of an app
.PARAMETER MutablePackageDirectory
desktop6:MutablePackageDirectory parameter of the Appx package manifest
#>
Function Find-AppxModifiableWindowsApps
{
	Param
	(
		[String]
		$MutablePackageDirectory = "pso2_bin"
	)
	$CandidateAppxVolumes = @()
	$OAV = Get-OnlineAppxVolumes
	$OAV | Where-Object -Property IsSystemVolume -eq $true | ForEach-Object -Verbose -Process {
		$ModifiableFolder = Join-Path -Path $_.PackageStorePath -ChildPath "..\ModifiableWindowsApps" -Verbose
		If (Test-Path -LiteralPath $ModifiableFolder -PathType Container -Verbose)
		{
			$CandidateAppxVolumes += $_
		}
	}
	$OAV | Where-Object -Property IsSystemVolume -eq $false | ForEach-Object -Verbose -Process {
		$ModifiableFolder = Join-Path -Path $_.PackageStorePath -ChildPath "..\Program Files\ModifiableWindowsApps" -Verbose
		If (Test-Path -LiteralPath $ModifiableFolder -PathType Container -Verbose)
		{
			$CandidateAppxVolumes += $_
		}
	}

	$FiltratePaths = @{}
	If ($CandidateAppxVolumes.Count -gt 0)
	{
		$CandidateAppxVolumes | Where-Object -Property IsSystemVolume -eq $true | ForEach-Object -Verbose -Process {
			$MutableFolder = Join-Path -Path $_.PackageStorePath -ChildPath "..\ModifiableWindowsApps\$($MutablePackageDirectory)" -Verbose
			If (Test-Path -LiteralPath $MutableFolder -PathType Container -Verbose)
			{
				$CurrentAppxVolume = Resolve-Path -LiteralPath $MutableFolder -Verbose
				$FiltratePaths[$CurrentAppxVolume] = $true
			}
		}
		$CandidateAppxVolumes | Where-Object -Property IsSystemVolume -eq $false | ForEach-Object -Verbose -Process {
			$MutableFolder = Join-Path -Path $_.PackageStorePath -ChildPath "..\Program Files\ModifiableWindowsApps\$($MutablePackageDirectory)" -Verbose
			If (Test-Path -LiteralPath $MutableFolder -PathType Container -Verbose)
			{
				$CurrentAppxVolume = Resolve-Path -LiteralPath $MutableFolder -Verbose
				$FiltratePaths[$CurrentAppxVolume] = $true
			}
		}
	}

	$SystemDrivePath = "$($env:SystemDrive)\Program Files\ModifiableWindowsApps\$($MutablePackageDirectory)"
	If (Test-Path -LiteralPath $SystemDrivePath -PathType Container -Verbose)
	{
		$CurrentAppxVolume = Resolve-Path -LiteralPath $SystemDrivePath -Verbose
		$FiltratePaths[$CurrentAppxVolume] = $true
	}
	$ProgramFilesPath = "$($env:ProgramFiles)\ModifiableWindowsApps\$($MutablePackageDirectory)"
	If (Test-Path -LiteralPath $ProgramFilesPath -PathType Container -Verbose)
	{
		$CurrentAppxVolume = Resolve-Path -LiteralPath $ProgramFilesPath -Verbose
		$FiltratePaths[$CurrentAppxVolume] = $true
	}
	Return $FiltratePaths.Keys | Select-Object -ExpandProperty ProviderPath
}

Function SetConsoleQuickEdit
{
	Param
	(
		[Parameter(Mandatory=$true)]
		[Bool]
		$Mode
	)
	$RegistryKeyPath = "HKCU:\Console\%SystemRoot%_System32_WindowsPowerShell_v1.0_powershell.exe"
	If (-Not (Test-Path -LiteralPath $RegistryKeyPath -PathType Container))
	{
		Return
	}
	$OldMode = $null
	$OldMode = GetConsoleQuickEdit
	Set-ItemProperty -LiteralPath $RegistryKeyPath -Name "QuickEdit" -Value $Mode -Type DWord -ErrorAction SilentlyContinue
	Return $oldMode
}

Function GetConsoleQuickEdit
{
	$RegistryKeyPath = "HKCU:\Console\%SystemRoot%_System32_WindowsPowerShell_v1.0_powershell.exe"
	If (-Not (Test-Path -LiteralPath $RegistryKeyPath -PathType Container))
	{
		Return $null
	}
	$RegData = $null
	$RegData = Get-ItemProperty -LiteralPath $RegistryKeyPath -Name "QuickEdit" -ErrorAction SilentlyContinue
	If ($null -ne $RegData)
	{
		Return $RegData.QuickEdit
	}
}

Function Join-Paths
{
	Param
	(
		[Parameter(Mandatory=$true)]
		[String[]]
		$Path,
		[Parameter(Mandatory=$true,ValueFromPipeline=$true)]
		[String]
		$ChildPath
	)
	PROCESS
	{
		Return Join-Path -Path $Path -ChildPath $ChildPath
	}
}

Function HashOrDelete()
{
	Param
	(
		[Parameter(Mandatory=$true)]
		[String]
		$Path,
		[Parameter(Mandatory=$true)]
		[String]
		$Folder,
		[Parameter(Mandatory=$true,ValueFromPipeline=$true)]
		[String]
		$Filename,
		[Parameter(Mandatory=$true)]
		[Int32]
		$Hash_Count
	)
	BEGIN
	{
		If ($Folder -eq ".")
		{
			$BaseDir = $Path
			$FolderName = "Core"
		}
		Else
		{
			$BaseDir = Join-Path -Path $Path -ChildPath $Folder
			$FolderName = $Folder
		}
		Write-Progress -Activity "Making MD5 hashs for files in the $($FolderName) folder" -Status "Ready" -Id 0 -PercentComplete 0
		$Hash_Counter = 0
	}
	PROCESS
	{
		Write-Progress -Activity "Making MD5 hashs for files in the $($FolderName) folder" -Status "File $($Hash_Counter + 1) of $($Hash_Count): $($Filename)" -Id 0 -PercentComplete (($Hash_Counter * 100) /$Hash_Count)
		$Hash_Counter += 1
		$FilePath =  Join-Path -Path $BaseDir -ChildPath $Filename
		$MD5Hash = $null
try {
		$MD5Hash = (Get-FileHash -LiteralPath $FilePath -Algorithm MD5 -Verbose).Hash
} catch {Write-Verbose $_}
		If ($null -eq $MD5Hash)
		{
			$MD5HashS = "D41D8CD98f00B204E9800998ECF8427E"
		}
		else
		{
			$MD5HashS = ([string]$MD5Hash).ToUpper()
		}
		If ($Folder -eq ".")
		{
			$HashName_unix = $Filename
		}
		Else
		{
			$HashName_dos = (Join-Path -Path $Folder -ChildPath $FileName)
			$HashName_unix = $HashName_dos.Replace('\','/')
		}
		Return @{$HashName_unix = $MD5HashS}
	}
	END
	{
		Write-Progress -Activity "Making MD5 hashs for files in the $($FolderName) folder" -Status "Done" -Id 0 -Completed
		If ($Folder -eq ".")
		{
			Write-Verbose -Message "Done processing $($Hash_Counter) files in Core Folder"
		}
		Else
		{
			Write-Verbose -Message "Done processing $($Hash_Counter) files in the $($Folder) Folder"
		}
	}
}

Function RemakeClientHashs()
{
	Param
	(
		[Parameter(Mandatory=$true)]
		[String]
		$Path
	)
	Write-Host -Object "Double checking data files for read acess issues..."
	$core_files = @()
	$data_license_files = @()
	$data_win32na_files = @()
	$data_win32jp_files = @()
	$data_win32jp_script_files = @()
	$core_files += Get-ChildItem -LiteralPath $Path -File -Filter "*.dll" -Name
	$core_files += Get-ChildItem -LiteralPath $Path -File -Filter "*.exe" -Name
	$core_files += Get-ChildItem -LiteralPath $Path -File -Filter "*.rtf" -Name
	$core_files += Get-ChildItem -LiteralPath $Path -File -Filter "*.txt" -Name
	$core_files += Get-ChildItem -LiteralPath $Path -File -Filter "*.ver" -Name
	$core_files += Get-ChildItem -LiteralPath $Path -File -Filter "*.ini" -Name
	$core_files += Get-ChildItem -LiteralPath $Path -File -Filter "*.des" -Name
	$core_files += Get-ChildItem -LiteralPath $Path -File -Filter "*.png" -Name
	$data_folder = Join-Path -Path $Path -ChildPath "data"
	If (Test-Path -LiteralPath $data_folder -PathType Container)
	{
		$data_license_folder = Join-Path -Path $data_folder -ChildPath "license"
		If (Test-Path -LiteralPath $data_license_folder -PathType Container)
		{
			$data_license_files += Get-ChildItem -LiteralPath $data_license_folder -File -Name
		}
		$data_win32na_folder = Join-Path -Path $data_folder -ChildPath "win32_na"
		If (Test-Path -LiteralPath $data_win32na_folder -PathType Container)
		{
			$data_win32na_files += Get-ChildItem -LiteralPath $data_win32na_folder -File -Name
		}
		$data_win32jp_folder = Join-Path -Path $data_folder -ChildPath "win32"
		If (Test-Path -LiteralPath $data_win32jp_folder -PathType Container)
		{
			$data_win32jp_files += Get-ChildItem -LiteralPath $data_win32jp_folder -File -Name
			$data_win32jp_script_folder = Join-Path -Path $data_win32jp_folder -ChildPath "script"
			If (Test-Path -LiteralPath $data_win32jp_script_folder -PathType Container)
			{
				$data_win32jp_script_files += Get-ChildItem -LiteralPath $data_win32jp_script_folder -File -Name
			}
		}
	}
	$all_file_count = $core_files.Count + $data_license_files.Count + $data_win32na_files.Count + $data_win32jp_files.Count
	Write-Host -Object "Going to hash $($all_file_count) files, this may take a while"
	$core_hashs = @()
	$data_win32jp_script_hashs = @()
	$data_license_hashs = @()
	$data_win32na_hashs = @()
	$data_win32jp_hashs = @()
	If ($core_files.Count -gt 0)
	{
		Write-Verbose -Message "Found $($core_files.Count) core files..."
		$core_hashs += $core_files | HashOrDelete -Path $Path -Folder "." -Hash_Count $core_files.Count
	}
	If ($data_win32jp_script_files.Count -gt 0)
	{
		Write-Verbose -Message "Found $($data_win32jp_script_files.Count) script files..."
		$data_win32jp_script_hashs += $data_win32jp_script_files | HashOrDelete -Path $Path -Folder "data/win32/script" -Hash_Count $data_win32jp_script_files.Count
	}
	If ($data_license_files.Count -gt 0)
	{
		Write-Verbose -Message "Found $($data_license_files.Count) license files..."
		$data_license_hashs += $data_license_files | HashOrDelete -Path $Path -Folder "data/license" -Hash_Count $data_license_files.Count
	}
	If ($data_win32na_files.Count -gt 0)
	{
		Write-Verbose -Message "Found $($data_win32na_files.Count) NA data files.."
		$data_win32na_hashs += $data_win32na_files | HashOrDelete -Path $Path -Folder "data/win32_na" -Hash_Count $data_win32na_files.Count
	}
	If ($data_win32jp_files.Count -gt 0)
	{
		Write-Verbose -Message "Found $($data_win32jp_files.Count) JP data files.."
		$data_win32jp_hashs += $data_win32jp_files | HashOrDelete -Path $Path -Folder "data/win32" -Hash_Count $data_win32jp_files.Count
	}
	$i = @()
	If($core_hashs.Count -gt 0)
	{
		$i += $core_hashs
	}
	If($data_win32jp_script_hashs.Count -gt 0)
	{
		$i += $data_win32jp_script_hashs
	}
	If($data_license_hashs.Count -gt 0)
	{
		$i += $data_license_hashs
	}
	If($data_win32na_hashs.Count -gt 0)
	{
		$i += $data_win32na_hashs
	}
	If($data_win32jp_hashs.Count -gt 0)
	{
		$i += $data_win32jp_hashs
	}
	$r = @{}
	Write-Verbose -Message "Converting $($i.Count) MD5SUM list to hashtable..."
	$i | Where-Object -FilterScript {$null -ne $_} | ForEach-Object -Process {
		$k = $_.Keys[0] -join ""
		$v = $_.Values[0] -join ""
		If ($null -ne $v -and "D41D8CD98f00B204E9800998ECF8427E" -ne $v)
		{
			$r.Add($k, $v)
		}
	}
	Write-Verbose -Message "Saving $($r.Count) hashtable to file"
	Return $r
}

Function CheckPath()
{
	Param
	(
		[Parameter(Mandatory=$true)]
		[String]
		$Path,
		[Parameter(Mandatory=$true)]
		[String[]]
		$BadFolders
	)
	If ($Path -in $BadFolders)
	{
		Return $true
	}
	$Parent = $Path | Split-Path -Parent
	If ($Parent -eq "")
	{
		Return $false
	}
	Return CheckPath -Path $Parent -BadFolders $BadFolders
}

Function RegQUERY()
{
	Param
	(
		[Parameter(Mandatory=$true)]
		[String]
		$KeyName,
		[Parameter(Mandatory=$true)]
		[String]
		$RegKey,
		[Object]
		$Default = $null
	)
	if (Test-Path -LiteralPath $KeyName)
	{
		$RegPath = Get-ItemProperty -LiteralPath $KeyName
		if ($null -ne $RegPath -and $null -ne ($RegPath | Get-Member -Name $RegKey) )
		{
			Return Get-ItemPropertyValue -LiteralPath $KeyName -Name $RegKey
		}
	}
	Return $Default
}

#endregion  helper_functinons

#----------------------------------------------------------------------------------------------------------------------------------

$OldBackups = @()
"Looking for old PSO2NA MutableBackup folders..."
$OldBackups += Find-AppxMutableBackups
$MWA = @()
$MWA += Find-AppxModifiableWindowsApps
$OldPackages = @()
$OldPackages += Get-AppxPackage -Name "100B7A24.oxyna" -AllUsers | Where-Object -Property SignatureKind -EQ "Store"

If ($OldBackups.Count -gt 0)
{
	"Found $($OldBackups.Count) MS Store backup copies of PSO2NA, this may take a while" | PauseOnly
}
If ($MWA.Count -gt 0)
{
	"Found MS Store patch folder of PSO2NA, this may take a while" | PauseOnly
}
ElseIf ($OldPackages.Count -gt 0)
{
	"Found MS Store copy of PSO2NA, this may take a while" | PauseOnly
}

If ($OldPackages.Count -gt 0)
{
	$OldPackages | Where-Object InstallLocation -ne $null | ForEach-Object -Process {
		$OldBin = $_.InstallLocation
		Write-Host -Object "Found the old MS STORE's pso2_bin core's data folder!"
		Takeownship -path $OldBin
		#Write-Host -Object "Removing $($NAFiles.Count) unneeded files..."
		#$NAFiles | Join-Paths -Path $OldBin | Remove-Item -Force -ErrorAction SilentlyContinue
		#Write-Host -Object "Deleting old MS STORE's pso2_bin core's data folder..."
try {
		#Write-Host -Object "Deleting files in $($OldBin) Folder..."
		#Get-ChildItem -LiteralPath $OldBin -ErrorAction Continue -File -Recurse | Remove-Item -Force -Confirm:$false -ErrorAction SilentlyContinue
} Catch {$_}
try {
		#Write-Host -Object "Deleting subfolders in $($OldBin) Folder..."
		#Get-ChildItem -LiteralPath $OldBin -ErrorAction Continue -Directory | Remove-Item -Recurse -Force -Confirm:$false -Verbose -ErrorAction SilentlyContinue
} Catch {$_}
try {
		#Write-Host -Object "Deleting $($OldBin) Folder..."
		#Remove-Item -LiteralPath $OldBin -Recurse -Force -Confirm:$false -Verbose -ErrorAction SilentlyContinue
} Catch {$_}
	}
}

If ($OldBackups.Count -gt 0)
{
	Write-Host -Object "Found some MutableBackup folders!"
	$OldBackups | Format-List
	$OldBackups | ForEach-Object -Process {
		$OldBin = $_
		Takeownship -path $OldBin
		Write-Host -Object "Removing $($NAFiles.Count) unneeded files..."
		$NAFiles | Join-Paths -Path $OldBin | Remove-Item -Force -ErrorAction SilentlyContinue
		Write-Host -Object "Deleting old $($OldBin) folder..."
try {
		Write-Host -Object "Deleting files in $($OldBin) Folder..."
		Get-ChildItem -LiteralPath $OldBin -ErrorAction Continue -File -Recurse | Remove-Item -Force -Confirm:$false -ErrorAction SilentlyContinue
} Catch {$_}
try {
		Write-Host -Object "Deleting subfolders in $($OldBin) Folder..."
		Get-ChildItem -LiteralPath $OldBin -ErrorAction Continue -Directory | Remove-Item -Recurse -Force -Confirm:$false -Verbose -ErrorAction SilentlyContinue
} Catch {$_}
try {
		Write-Host -Object "Deleting $($OldBin) Folder..."
		Remove-Item -LiteralPath $OldBin -Recurse -Force -Confirm:$false -Verbose -ErrorAction SilentlyContinue
} Catch {$_}
	}
}

If ($MWA.Count -gt 0)
{
	$MWA | ForEach-Object -Process {
		If ([string]::IsNullOrEmpty($_)) {
			Write-Host -Object "Found Garbage ModifiableWindowsApps and ignoring it: $($_)"
			Continue
		}
		$OldBin = $_
		Write-Host -Object "Found the old MS STORE's pso2_bin patch folder!"
		Takeownship -path $OldBin
		Write-Host -Object "Removing $($NAFiles.Count) unneeded files..."
		$NAFiles | Join-Paths -Path $OldBin | Remove-Item -Force -ErrorAction SilentlyContinue
		Write-Host -Object "Deleting old MS STORE's pso2_bin patch folder..."
		try {
			Write-Host -Object "Deleting files in $($OldBin) Folder..."
			Get-ChildItem -LiteralPath $OldBin -ErrorAction Continue -File -Recurse | Remove-Item -Force -Confirm:$false -ErrorAction SilentlyContinue
		} Catch {$_}
		try {
			Write-Host -Object "Deleting subfolders in $($OldBin) Folder..."
			Get-ChildItem -LiteralPath $OldBin -ErrorAction Continue -Directory | Remove-Item -Recurse -Force -Confirm:$false -Verbose -ErrorAction SilentlyContinue
		} Catch {$_}
		try {
			Write-Host -Object "Deleting $($OldBin) Folder..."
			Remove-Item -LiteralPath $OldBin -Recurse -Force -Confirm:$false -Verbose -ErrorAction SilentlyContinue
		} Catch {$_}
	}
}

If ($OldPackages.Count -gt 0)
{
	Write-Host -Object "If this takes more then 30 minutes, you may have to reboot."
	Write-Host -Object "Unregistering the old PSO2 from the Windows Store... (This may take a while, don't panic!)"
	$OldPackages | Remove-AppxPackage -AllUsers -Verbose -ErrorAction Continue
}
Else
{
	Write-Host -Object "No Windows Store PSO2NA installations found. Awesome!"
}
$Shell = New-Object -ComObject "WScript.Shell"
$Button = $Shell.Popup("Script complete! All detected PSO2NA Windows Store installations have been removed.", 0, "Done!", 0)