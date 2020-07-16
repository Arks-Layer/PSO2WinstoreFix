# Script failed to start in Windows PowerShell ISE, run this to disable the block policy
#
#	Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy ByPass -Confirm:$false
#
# and if that fails,try this comamand:
#
#	Set-ExecutionPolicy -Scope Process -ExecutionPolicy ByPass -Confirm:$false
#

Param(
	[Bool]$ForceReinstall = $false,
	[Bool]$TweakerMode = $false,
	[Bool]$PauseOnFail = $true,
	[Bool]$SkipRobomove = $false,
	[Bool]$ForceLocalInstall = $false,
	[Bool]$SkipStorageCheck = $false,
	[Bool]$SkipOneDrive = $false,
	[Bool]$ForceReHash = $false
)

$VersionScript = "Version 2020_07_16_1226" # Error codes: 39

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
FOrce to use APPX files from an outside source, not the MS Store

.PARAMETER SkipStorageCheck
Skip checking the volumes, in case of a broken disk management system

.PAREMETER SkipOneDrive
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
			[System.Windows.MessageBox]::Show($ErrorMessage)
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

#Find MutableBackup
Function FindMutableBackup {
	[CmdletBinding()]
	Param
	(
		[String]
		$Package = "100B7A24.oxyna"
	)
	PROCESS
	{
		Write-Verbose -Message $Package
		$AppxVols = @()
		$AppxVols += Get-AppxVolume -Online -Verbose
		$Mutable = @()
		$Mutable += $AppxVols | ForEach-Object -Process {
			$Test = Join-Path $_.PackageStorePath -ChildPath "MutableBackup"
			If (Test-Path -LiteralPath $Test -PathType Container)
			{
				Return Resolve-Path -LiteralPath $Test -Verbose
			}
		}
		$Backups = @()
		$Backups += $Mutable | ForEach-Object -Process {
			Return Get-ChildItem -LiteralPath $_.ProviderPath -Filter "$($Package)*"
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
			Remove-Item -Path "client_na.json" -Force -Verbose
		}
	}
	Write-Host -Object "Starting robocopy job..."
	$Cmdlist = "/C","Robocopy.exe", ('"{0}"' -f $source),('"{0}"' -f $destination),('"{0}"' -f $file),"/XF","*.pat","/TEE","/DCOPY:DA","/COPY:DAT","/MOV","/ZB","/ETA","/XO","/R:0","/W:1",('/LOG+:"{0}"' -f $logpath.Path)
	If ($Details -eq $true)
	{
		$Cmdlist += "/V"
	}
	Start-Process -Wait -FilePath $env:ComSpec -ArgumentList $Cmdlist -WindowStyle Minimized
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
			If ($NewSub -like "win32*")
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
		Start-Process -Wait -FilePath $takeownEXE -ArgumentList "/R","/A","/F",('"{0}"' -f $path) -ErrorAction Continue -WindowStyle Normal
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
			[System.Windows.MessageBox]::Show($PauseMessage)
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

Function FindMutable_Appx
{
	Param
	(
		[String]
		$Folder = "pso2_bin"
	)
	$OnlineVolumes = @()
	$MutableVolumes = @()
	$PackageFolders = @()
try {
	$OnlineVolumes += Get-AppxVolume -Online -Verbose
} catch {$_}
	If ($OnlineVolumes.Count -gt 0)
	{
		$MutableVolumes += $OnlineVolumes | ForEach-Object -Process {
			$ModifiableFolder = Join-Path -Path $_.PackageStorePath -ChildPath "..\WindowsModifiableApps"
			If (Test-Path -LiteralPath $ModifiableFolder -PathType Container)
			{
				$_
			}
		}
	}
	If ($MutableVolumes.Count -gt 0)
	{
		$PackageFolders += $MutableVolumes | ForEach-Object -Process {
			$MutableFolder = Join-Path -Path $_.PackageStorePath -ChildPath "..\WindowsModifiableApps\$($Folder)"
			If (Test-Path -LiteralPath $MutableFolder -PathType Container)
			{
				Return Resolve-Path -LiteralPath $MutableFolder
			}
		}
	}
	If (Test-Path -LiteralPath "$($Env:SystemDrive)\Program Files\WindowsModifiableApps\$($Folder)" -PathType Container)
	{
		$PackageFolders += Resolve-Path -LiteralPath "$($Env:SystemDrive)\Program Files\WindowsModifiableApps\$($Folder)"
	}
	If ($PackageFolders.Count -gt 0)
	{
		Return $PackageFolders.ProvidePath
	}
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
		[Parameter(Mandatory=$true,ValueFromPipeline)]
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
} catch {$_}
		If ($null -eq $MD5Hash)
		{
			Remove-Item -LiteralPath $_.PSPath -Force -Verbose -ErrorAction Continue -WhatIf
			Return
		}
		$MD5HashS = ([string]$MD5Hash).ToUpper()
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
	$core_files = Get-ChildItem -LiteralPath $Path -File -Filter "*.dll" -Name
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
		$r.Add($_.Keys[0] -join "", $_.Values[0] -join "")
	}
	Write-Verbose -Message "Saving $($i.Count) hashtable to file"
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

#----------------------------------------------------------------------------------------------------------------------------------

#if there an unhandled error, just stop
If ($host.name -ne 'Windows Powershell ISE Host' -and $false)
{
	$ErrorActionPreference = "Continue"
}
Else
{
	$ErrorActionPreference = "Stop"
}
#Kill all logging
Try
{
	Do
	{
		Stop-Transcript -ErrorAction Stop
	} While ($true)
}
Catch {
	"Testing if we can write t our own log file"
}
#Find the script's folder and add "PSO2NA_PSLOG.log" to end of it
If ($PSScriptRoot -ne $null -and -not (Test-Path -Path "PSO2 Tweaker.exe" -PathType Leaf))
{
	$ScriptLog = Join-Path -Path $PSScriptRoot -ChildPath "PSO2NA_PSLOG.log"
	Set-Location -LiteralPath $PSScriptRoot
}
Else
{
	$ScriptLog = Join-Path -Path "." -ChildPath "PSO2NA_PSLOG.log"
}

Add-Type -AssemblyName PresentationCore,PresentationFramework
#Start logging
try {
Start-Transcript -LiteralPath $ScriptLog
} catch {
$_
"I am betting that the folder is read-only OR....",
".....PLEASE FUCKING REMOVING THE TWEAKER AND PSO2 FOLDERS OUT OF of Settings App -> Virus & threat protection -? Randsomware protection -> Protected folders" | PauseAndFail -ErrorLevel 255
}
#Version number
$VersionScript

If (-Not (Test-Path -Path "PSO2 Tweaker.exe" -PathType Leaf))
{
	"The Powershell Script NOW need to be placed in the same folder as PSO2 Tweaker, please move me" | PauseAndFail -ErrorLevel 31
}

SetConsoleQuickEdit -Mode $false | Out-Null

If ($MyInvocation.MyCommand.Name -eq "pso2_winstore_fix_freshinstall.ps1")
{
	$SkipRobomove = $true
}

If ($TweakerMode -eq $true)
{
	$PauseOnFail = $false
	$SkipRobomove = $true
	$ForceLocalInstall = $true
}

If (-Not (Test-Path -Path "client_na.json" -PathType Leaf))
{
	$ForceReHash = $true
}

#Start-Service -Name "Winmgmt" -ErrorAction Stop

Write-Host -Object "Checking Windows version..."
$WinVer = [System.Environment]::OSVersion.Version
if ($WinVer.Major -lt 10)
{
	""
	"Reported Windows Major version $($WinVer.Major)"
	"ERROR: PSO2NA is only supported on Windows 10." | PauseAndFail -ErrorLevel 1
}
Elseif ($WinVer.Minor -gt 0) {}
ElseIf ($WinVer.Build -lt 18362)
{
	Write-Host -Object ""
	Write-Host -Object "Reported Windows Build $($WinVer.Build), Verion $(Window10Version -Build $WinVer.Build)"
	Write-Host -Object "ERROR: PSO2NA is only supported on Windows 10 Version 1903 or higher. You need to upgrade Windows to a newer build/version." |	PauseAndFail -ErrorLevel 2
}
Elseif ([System.Environment]::Is64BitOperatingSystem -eq $false)
{
	Write-Host -Object ""
	"PSO2NA is only supported on 64-bit OS. You need to reinstall your Windows OS if your CPU is 64-bit." | PauseAndFail -ErrorLevel 21
}
Write-Host -Object "[OK]"
Write-Host -Object "Report Windows Verion"
$WinVer | Format-List
Write-Host -Object ""
Write-Host -Object ""
Write-Host -Object ""
Write-Host -Object ""

Import-Module -Name Appx -Force -Verbose
Import-Module -Name CimCmdlets -Force -Verbose
Import-Module -Name Microsoft.PowerShell.Archive -Force -Verbose
Import-Module -Name Microsoft.PowerShell.Diagnostics -Force -Verbose
Import-Module -Name Microsoft.PowerShell.Host -Force -Verbose
Import-Module -Name Microsoft.PowerShell.Management -Force -Verbose
Import-Module -Name Microsoft.PowerShell.Utility -Force -Verbose
Import-Module -Name NetAdapter -Force -Verbose
Import-Module -Name NetTCPIP -Force -Verbose
Import-Module -Name Storage -Force -Verbose

Write-Host -Object "Checking for Administrator Role..."
# Get the ID and security principal of the current user account
$myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal=New-Object System.Security.Principal.WindowsPrincipal($myWindowsID)
# Get the security principal for the Administrator role
$adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
if (-Not $myWindowsPrincipal.IsInRole($adminRole))
{
	Write-Host -Object ""
	Write-Host -Object "WARNING: You need to run this PowerShell script using an Administrator account (or with an admin powershell)."
	Stop-Transcript
	Start-Process -FilePath "powershell.exe" -ArgumentList "-NoLogo","-NoProfile","-ExecutionPolicy","ByPass","-File",('"{0}"' -f $MyInvocation.MyCommand.Path) -Verb RunAs -WindowStyle Maximized
	exit
	#PauseAndFail -ErrorLevel 3
}
Write-Host -Object "[OK]"
Write-Host -Object ""
Write-Host -Object ""
Write-Host -Object ""
Write-Host -Object ""

Write-Host -Object "Killing PSO2 processes"
try {
Get-Process | Where-Object ProcessName -in "PSO2 Tweaker","pso2","pso2download","pso2laucher","pso2predownload","pso2startup","pso2updater","GameGuard.des","GameMon.des","GameMon64.des" | Stop-Process -Force -ErrorAction Continue -Verbose
} catch {$_}


Write-Host -Object "Look for PSO2 log entries"
$WinAppLogs = @()
$WinAppLogs += Get-WinEvent -LogName Application -ErrorAction SilentlyContinue
$WinAppLogs | Where-Object Message -like "*pso2*" | Format-List
""

Write-Host -Object "Testing for broken IPv6 network setup"
$IPv6DR = @()
$IPv6DR += Get-NetRoute -AddressFamily IPv6 -Verbose | Where-Object DestinationPrefix -eq "::/0" |Where-Object NextHop -ne "::" | Sort-Object ifMetric
If ($IPv6DR.Count -gt 0)
{
	Write-Host -Object "Found IPv6 network setup"
	Write-Host -Object "Network Adapter with IPv6:"
	$IPv6DR | Sort-Object ifIndex -Unique | Get-NetAdapter
	Write-Host -Object "IPv6 Address Settings:"
	$IPv6DR | Sort-Object ifIndex -Unique | Get-NetIPAddress -AddressFamily IPv6 | Where-Object SuffixOrigin -NE "Random" | Where-Object SuffixOrigin -NE "Link" | Where-Object AddressState -NE "Deprecated" | Select-Object IPv6Address, PrefixLength, AddressState, InterfaceAlias, InterfaceIndex, PrefixOrigin, SkipAsSource, Store, SuffixOrigin, Type
	Write-Host -Object "Ipv6 DNS Settings:"
	$IPv6DR | Sort-Object ifIndex -Unique | Get-DnsClientServerAddress -AddressFamily IPv6 | Select-Object InterfaceAlias, InterfaceIndex, ServerAddresses
	Write-Host -Object "IPv6 Routes:"
	$IPv6DR
	$IPv6Test = $null
	Write-Host -Object "Testing if we can get an IPv6 only data..."
	try {
	$IPv6Test = Invoke-RestMethod -Uri "http://ipv6.alam.srb2.org/PSO2/BASICDev_proxy/config.json" -UserAgent "Arks-Layer pso2_winstore_fix" -TimeoutSec 10 -ErrorAction Stop -Verbose
	} catch {$_}
	If ($null -eq $IPv6Test)
	{
		Write-Host -Object "Failed IPv6 test, disabling IPv6"
		$IPv6DR | Disable-NetAdapterBinding -ComponentID ms_tcpip6 -Verbose
	}
	Else
	{
		Write-Host -Object "	[OK]"
	}
}
Else
{
	Write-Host -Object "There no IPv6 network setup to check if it is broken"
}


Write-Host -Object "Getting Windows Patch list"
$WinPatchs = @()
try {
	$WinPatchs += Get-Hotfix -Verbose -ErrorAction Continue
} catch {
	"Broken Windows Update system" | PauseOnly
}
If ($WinPatchs.Count -gt 0)
{
try {
	$WinPatchs | Where-Object InstalledOn -ne $null | Sort-Object InstalledOn
	$WinPatchs | Where-Object InstalledOn -eq $null
} catch {
	$WinPatchs
}
}
If ($WinPatchs.HotFixID -contains "KB4560960" -and (-Not ($WinPatchs.HotFixID -contains "KB4567512")))
{
	Write-Host -Object ""
	If ($WinVer.Build -eq 18362 -or $WinVer.Build -eq 18363) # 1903 and 1909 are the "same"
	{
		[Diagnostics.Process]::Start("https://www.catalog.update.microsoft.com/Search.aspx?q=KB4567512%2010%201909%20x64") | Out-Null
	}
	Else
	{
		[Diagnostics.Process]::Start("https://www.catalog.update.microsoft.com/Search.aspx?q=KB4567512") | Out-Null
	}
	"KB4560960 patch is installed, it been known to crash PSO2, please install KB4567512 update" | PauseOnly
}

Write-Host -Object "Getting Software list... (TimeOut set to 5 minutes)"
Write-Host -Object "Please note: if you have any broken MSI installations, you may get errors"
$MSIList = @()
$MSIList_Nahimic = @()
$MSIList_Bad = @()
try {
$MSIList += Get-CimInstance -ClassName Win32_Product -OperationTimeoutSec 300 -Shallow -ErrorAction Continue
} catch {$_}
If ($MSIList.Count -gt 0)
{
	Write-Host -Object "Exporting Installed programs for troubleshooting..."
	$MSIList | Export-Clixml -Path "Installed.xml"
}
Write-Host -Object "[OK]"
$BadMSIs = @()
$BadMSIs += "{FD585866-680F-4FE0-8082-731D715F90CE}","{FE05D491-4625-496D-A27A-FC318DE398B7}","{85D06868-AE2D-4B82-A4B1-913A757F0A32}"
$BadMSIs += "{D88C71FC-FB81-49E0-9661-41ADDC02E4FD}"."{893DFE4F-0810-4CC6-A0EB-2A4E8EAE36B4}","{0D3E2309-662A-4F32-9A29-278663BEF2E5}"
$BadMSIs += "{D65C6419-CA01-46F1-B492-18F1BCB71E5D}"
$MSIR = @()
$MSIList_Nahimic += $MSIList | Where-Object Vendor -EQ "Nahimic"
$MSIList_Nahimic += $MSIList | Where-Object IdentifyingNumber -In $BadMSIs
If ($MSIList_Nahimic.Count -gt 0)
{
	$MSILog = Join-Path -Path $PSScriptRoot -ChildPath "NahimicAll.log"
	Write-Host -Object "Ok, Going to Remove All Nahimic software to stop PSO2 from crashing"
	$MSIList_Nahimic | Select-Object -Property Name, Caption, Description, IdentifyingNumber, PackageName
	$MSIR += $MSIList_Nahimic | ForEach-Object -Process {
		Start-Process -Wait -Verbose -FilePath "MsiExec.exe" -ArgumentList "/x",$_.IdentifyingNumber,"/l*vx+",('"{0}"' -f $MSILog),"/qb"
	}
}

$MSIList_Bad += $MSIList | Where-Object Vendor -NE "Nahimic" | Where-Object Name -Like "Nahimic*"
If ($MSIList_Bad.Count -gt 0)
{
	Write-Host -Object "Found Bad software:"
	$MSIList_Bad | Select-Object -Property Vendor, Name, Caption, Version, Description, IdentifyingNumber, PackageName
	#PauseOnly
}

If (3010 -In $MSIR.ExitCode)
{
	"We need to reboot to be done removing the Nahimic software, BUT not right now" | PauseOnly
}

Write-Host -Object "Getting list of PNP devices..."
$PNPDevices = @()
$PNPDevices += Get-CimInstance -ClassName Win32_PNPEntity -ErrorAction Continue
If ($PNPDevices.Count -gt 0)
{
	Write-Host -Object "Export PNP Devices incause of troubleshooting.."
	$PNPDevices | Export-Clixml -Path "PNPDevices.xml"
}
Write-Host -Object "Getting list of Windows Drivers.."
$Drivers = @()
$Drivers += Get-WindowsDriver -Online -ErrorAction Continue
IF ($Drivers.Count -gt 0)
{
	Write-Host -Object "Export Windows Drivers incause of troubleshooting..."
	$Drivers | Export-Clixml -Path "DriversOFB.xml"
}
$PNPDevices_AVOL = @()
$PNPDevices_AVOL += $PNPDevices | Where-Object Manufacturer -eq "A-Volute"
If ($PNPDevices_AVOL.Count -gt 0)
{
	Write-Host -Object "WARNING: Found bad A-Volute software components drivers , We are going to remove them to stop PSO2 from crashing"
	Get-Service -ErrorAction SilentlyContinue -Name "NahimicService" | Stop-Service -ErrorAction Continue
}
$Drivers_AVOL = @()
$Drivers_AVOL += $Drivers | Where-Object ProviderName -eq "A-Volute"
If ($Drivers_AVOL.Count -gt 0)
{
	Write-Host -Object "Found bad A-Volute Drivers, uninstalling them"
	$Drivers_AVOL | Format-List
	$Drivers_AVOL | ForEach-Object -Process {
		Start-Process -Wait -FilePath "pnputil.exe" -ArgumentList "/delete-driver",$_.Driver,"/uninstall","/force"
	}
}
$Drivers_NV3D = @()
$Drivers_NV3D += $Drivers | Where-Object ClassName -eq "Display" | Where-Object ProviderName -eq "NVIDIA"
If ($Drivers_NV3d.Count -gt 0)
{
	Write-Host -Object "NVIDIA 3D Display Driver found"
	$BadVersion = [Version]"26.21.14.4587"
	$Drivers_NV3d_GOOD = @()
	$Drivers_NV3d_GOOD += $Drivers_NV3d | Where-Object -FilterScript {[Version]$_.Version -gt $BadVersion}
	If ($Drivers_NV3d_GOOD.Count -eq 0)
	{
		$Drivers_NV3D
		[Diagnostics.Process]::Start("https://www.nvidia.com/download/index.aspx")
		"Please Update your NVIDIA Driver" | PauseOnly
	}
	Else
	{
		Write-Host -Object "All Good?"
	}
}
$Drivers_AMD3D = @()
$Drivers_AMD3D += $Drivers | Where-Object ClassName -eq "Display" | Where-Object ProviderName -eq "Advanced Micro Devices, Inc."
If ($Drivers_AMD3D.Count -gt 0)
{
	Write-Host -Object "Found AMD 3D Drivers:"
	$Drivers_AMD3D
}
$Drivers_KILLER = @()
$Drivers_KILLER += $Drivers | Where-Object ProviderName -eq "Rivet Networks LLC"
If ($Drivers_KILLER.Count -gt 0)
{
	Write-Host -Object "Found Killer Gaming Drivers:"
	$Drivers_KILLER
}
$Drivers_SCP = @()
$Drivers_SCP += $Drivers | Where-Object CatalogFile -eq "ScpVBus.cat"
If ($Drivers_SCP.Count -gt 0)
{
	Write-Host -Object "Found Scp Drivers:"
	$Drivers_SCP
}

Write-Host -Object "Checking MS Store Setup"
try {
Set-Service -Name "wuauserv" -StartupType Manual -ErrorAction Continue
} catch {
"ERROR: Windows Service Manager is broken, try rebooting" | PauseAndFail -ErrorLevel 33
}
#Set-Service -Name "BITS" -StartupType AutomaticDelayedStart -ErrorAction Continue
Set-Service -Name "StorSvc" -StartupType Manual -ErrorAction Continue
Get-Service -Name "wuauserv","BITS","StorSvc","AppxSvc","ClipSvc" | Where-Object Statis -NE "Running" | Start-Service -ErrorAction Continue -Verbose

"Turn back on XBOX services..."
Get-Service -Name "XblGameSave","XblAuthManager","XboxNetApiSvc" | Where-Object StartType -EQ "Disabled" | Set-Service -StartupType Manual -PassThru -Verbose | Start-Service -Verbose
"Starting XBOX services..."
Get-Service -Name "XblGameSave","XblAuthManager","XboxNetApiSvc" | Where-Object Status -NE "Running" | Start-Service -Verbose
"Killing any XBOX process"
Get-Process -IncludeUserName | Where-Object UserName -eq ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) | Where-Object ProcessName -like "*xbox*" | Stop-Process -Force -ErrorAction Continue

$SystemVolume = Get-AppxVolume | Where-Object -Property IsSystemVolume -eq $true
$AddonVolumes = @()
$AddonVolumes += Get-AppxVolume -Online | Where-Object -Property IsSystemVolume -eq $false

Write-Host -Object "Checking for NET Framework 2.2 (2.2.27912.0+)"
$NETFramework = @()
$NETFramework_version = [Version]"2.2.27912.0"
$NETFramework += Get-AppxPackage -Name "Microsoft.NET.Native.Framework.2.2" -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" -PackageTypeFilter Framework | PackageVersion -Version $NETFramework_version
If ($NETFramework.Count -eq 0)
{
	$NetDownload = @()
	Write-Host -Object "Downloading NET 2.2 x86 Runtime Framework... (195 KB)"
	$URI = "https://github.com/Arks-Layer/PSO2WinstoreFix/raw/master/appx/Microsoft.NET.Native.Runtime.2.2_2.2.28604.0_x86__8wekyb3d8bbwe.appx"
	$FileD = "Microsoft.NET.Native.Runtime.2.2_2.2.28604.0_x86__8wekyb3d8bbwe.appx"
	$SHA512 = "2CA0D278729CDCE07899FF3791906F7B08BC1ED540B4A72CD72B928CF4F9BC2F58739270DC1978A82089F187898F9E333BBE07FF436E91733AB25C6898C9251C"
	$NetDownload += DownloadMe -URI $URI -OutFile $FileD -ErrorLevel 35 -SHA512 $SHA512

	Write-Host -Object "Downloading NET 2.2 x64 Runtime Framework... (239 KB)"
	$URI = "https://github.com/Arks-Layer/PSO2WinstoreFix/raw/master/appx/Microsoft.NET.Native.Runtime.2.2_2.2.28604.0_x64__8wekyb3d8bbwe.appx"
	$FileD = "Microsoft.NET.Native.Runtime.2.2_2.2.28604.0_x64__8wekyb3d8bbwe.appx"
	$SHA512 = "55647C44524ACFC25C1AA866D4ED8A73F35EFE6320B458303D5F72A57517760A3B50C03D6022628CBEC95E05E6F4520D89408F989E9C7A1E66E6BFF9B200595C"
	$NetDownload += DownloadMe -URI $URI -OutFile $FileD -ErrorLevel 35 -SHA512 $SHA512

	Write-Host -Object "Downloading NET 2.2 x86 Support Framework... (5 MB)"
	$URI = "https://github.com/Arks-Layer/PSO2WinstoreFix/raw/master/appx/Microsoft.NET.Native.Framework.2.2_2.2.27912.0_x86__8wekyb3d8bbwe.appx"
	$FileD = "Microsoft.NET.Native.Framework.2.2_2.2.27912.0_x86__8wekyb3d8bbwe.appx"
	$SHA512 = "D52BEC2FED3342E58587CF2D1ECA5EB3F68BC6C53D0D7AA8D544DF70F1670B231BFFAA826C6170D311C4241C2DD5103C8AC79611CBCAEAC36A91952EB2B49ADE"
	$NetDownload += DownloadMe -URI $URI -OutFile $FileD -ErrorLevel 35 -SHA512 $SHA512

	Write-Host -Object "Downloading NET 2.2 x64 Support Framework... (7 MB)"
	$URI = "https://github.com/Arks-Layer/PSO2WinstoreFix/raw/master/appx/Microsoft.NET.Native.Framework.2.2_2.2.27912.0_x64__8wekyb3d8bbwe.appx"
	$FileD = "Microsoft.NET.Native.Framework.2.2_2.2.27912.0_x64__8wekyb3d8bbwe.appx"
	$SHA512 = "83C85A05439B4608842DCDF828CCC7B5C6328AED1FC869247321D30E85D1AE1EA141B0D2A5154ECA4BE94E69DE4AB6659782C1C2333266F43A8B3EDE326EEE3E"
	$NetDownload += DownloadMe -URI $URI -OutFile $FileD -ErrorLevel 35 -SHA512 $SHA512

	Write-Host -Object "Installing NET 2.2 requirements... If you see an error about it not being installed becuase of a higher version, that's OK!"
	$NetDownload | Add-AppxPackage -Stage -Volume $SystemVolume -Verbose -ErrorAction Continue
	$NetDownload | Add-AppxPackage -Volume $SystemVolume -Verbose -ErrorAction Continue
	#$NewPackages | Remove-Item -Verbose
}
Else
{
	Write-Host -Object "	INSTALLED"
	$NETFramework
}
$XBOXIP_User = @()
$XBOXIP_Any = @()
$XBOXIP_All = @()
$XBOXIP_version = [Version]"12.64.28001.0"
$XBOXIP_User += Get-AppxPackage -Name "Microsoft.XboxIdentityProvider" -PackageTypeFilter Main -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" -Verbose | PackageVersion -Version $XBOXIP_version
$XBOXIP_Any += Get-AppxPackage -Name "Microsoft.XboxIdentityProvider" -PackageTypeFilter Main -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" -Verbose
$XBOXIP_All += Get-AppxPackage -Name "Microsoft.XboxIdentityProvider" -PackageTypeFilter Main -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" -AllUsers -Verbose | PackageVersion -Version $XBOXIP_version

If ($XBOXIP_All.Count -gt 0 -and $XBOXIP_User.Count -eq 0)
{
	Write-Host -Object "XBOX Identify Provider not installed to the user account, forcing install..."
	$XBOXIP_All | Where-Object InstallLocation -ne $null | ForEach-Object -Process {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -Verbose}
}
ElseIf ($XBOXIP_All.Count -eq 0 -and ($NETFramework.Count -gt 0 -or $true) -and $ForceLocalInstall -eq $true)
{
	Write-Host -Object "Downloading XBOX Identify Provider App... (13MB)"
	$URI = "https://github.com/Arks-Layer/PSO2WinstoreFix/raw/master/appx/Microsoft.XboxIdentityProvider_12.64.28001.0_neutral___8wekyb3d8bbwe.AppxBundle"
	$FileD = "Microsoft.XboxIdentityProvider_12.64.28001.0_neutral_~_8wekyb3d8bbwe.appxbundle"
	$Download = DownloadMe -URI $URI -OutFile $FileD -ErrorLevel 30 -SHA512 "FF1B99DB8EB30BD1CDF88EEAE310625726E1553B08D95F4001755711C7E32F6254A75C149458DFB8319F32A570B22CF5BD4C1F6D284859BB1FCCCF9132885A0F"

	Write-Host -Object "Installing XBOX Identify Provider app..."
	Try {
		$Download | Add-AppxPackage -Volume $SystemVolume -Verbose -ForceApplicationShutdown -ForceUpdateFromAnyVersion
	}
	Catch {$_}
}

$XBOXIP = Get-AppxPackage -Name "Microsoft.XboxIdentityProvider" -PackageTypeFilter Main -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" -Verbose

If ($null -ne $XBOXIP)
{
	Write-Host -Object "Looking for the XBOX Identify Provider folder to wipe..."
	$PackageF = Join-Path -Path $env:LOCALAPPDATA -ChildPath "Packages" -Verbose
	$XBOXIPFN = $XBOXIP.PackageFamilyName
	$XBOXIPF = Join-Path -Path $PackageF -ChildPath $XBOXIPFN -Verbose
	$XBOXTBF = Join-Path $XBOXIPF -ChildPath "AC\TokenBroker" -Verbose
	If (Test-Path -LiteralPath $XBOXTBF -PathType Container)
	{
		Takeownship -path $XBOXTBF
		Get-ChildItem -LiteralPath $XBOXTBF -Force | Remove-Item -Recurse -Force -Confirm:$false -ErrorAction Continue
	}
}
Else
{
	[Diagnostics.Process]::Start("ms-windows-store://pdp?productid=9wzdncrd1hkw")
	Write-Host -Object ""
	"ERROR: Look like XBOX Identify Provider has been uninstalled. Please use the Windows Store to get it back." | PauseAndFail -ErrorLevel 27
}

Write-Host -Object "Checking for needed Gaming Services App runtime..."
$GamingServices_User = @()
$GamingServices_Any = @()
$GamingServices_All = @()
$GamingServices_version = [Version]"2.42.5001.0"
$GamingServices_User += Get-AppxPackage -Name "Microsoft.GamingServices" -PackageTypeFilter Main -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" | PackageVersion -Version $GamingServices_version
$GamingServices_Any += Get-AppxPackage -Name "Microsoft.GamingServices" -PackageTypeFilter Main -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" -AllUsers
$GamingServices_All += $GamingServices_Any | PackageVersion -Version $GamingServices_version

$GamingServices_Any_Error = @()
$GamingServices_Any_Error += $GamingServices_Any.PackageUserInformation | Where-Object InstallState -NotIn "Installed","Staged"

$GamingSrv = @()
$GamingSrv += Get-Service -ErrorAction SilentlyContinue -Name "GamingServices"
$GamingSrv_STOP = @()
$GamingSrv_STOP += $GamingSrv | Where-Object Status -NE "Running"
$GamingSrv_DISABLED = @()
$GamingSrv_DISABLED += $GamingSrv | Where-Object StartType -EQ "Disabled"

$GamingNetSrv = @()
$GamingNetSrv += Get-Service -ErrorAction SilentlyContinue -Name "GamingServicesNet"
$GamingNetSrv_DISABLED += $GamingNetSrv | Where-Object StartType -EQ "Disabled"

If ($GamingNetSrv_DISABLED.Count -gt 0 -or $GamingSrv_DISABLED.Count -gt 0)
{
	"There a pending uninstall of the GamingServices App, please reboot your system" | PauseAndFail -ErrorLevel 36
}

$Drivers_XBOX = $Drivers | Where-Object ProviderName -eq "Xbox"

If ($GamingSrv_STOP.Count -gt 0)
{
	Write-Host -Object "GamingServices is not running, going to remove the XBOX drivers"
	If ($Drivers_XBOX.Count -gt 0)
	{
		$Drivers_XBOX | Format-List
		$Drivers_XBOX | ForEach-Object -Process {
			Start-Process -Wait -FilePath "pnputil.exe" -ArgumentList "/delete-driver",$_.Driver,"/uninstall","/force"
		}
	}
}

Try
{
	$ForceReinstallGS = $true
	Write-Host -Object "Checking if we can get the Gaming Services working..."
	$GamingNetSrv | Where-Object Status -NE "Running" | Restart-Service -ErrorAction Continue
	$GamingSrv | Where-Object Status -NE "Running" | Restart-Service
	Write-Host -Object "No errors found! :D"
	$ForceReinstallGS = $false
}
Catch
{
	Write-Host -Object "There was an issue checking the Gaming Services, we will try to reinstall the app..."
}

$GamingNetSrv = @()
$GamingNetSrv += Get-Service -ErrorAction SilentlyContinue -Name "GamingServicesNet"
$GamingNetSrv_START = @()
$GamingNetSrv_START += $GamingNetSrv | Where-Object Status -EQ "Running"
$GamingNetSrv_STOP = @()
$GamingNetSrv_STOP += $GamingNetSrv | Where-Object Status -NE "Running"
$GamingSrv = @()
$GamingSrv += Get-Service -ErrorAction SilentlyContinue -Name "GamingServices"
$GamingSrv_START = @()
$GamingSrv_START += $GamingSrv | Where-Object Status -EQ "Running"
$GamingSrv_STOP = @()
$GamingSrv_STOP += $GamingSrv | Where-Object Status -NE "Running"


If ($GamingNetSrv_STOP.Count -gt 0 -and $GamingSrv_START.Count -gt 0 -and $GamingServices_Any_Error.Count -eq 0)
{
	"Look like you broke the WindowsApp folder, ask for ONE on ONE support to fix this without reinstall Windows" | PauseAndFail -ErrorLevel 34
}
ElseIf ($GamingNetSrv_START.Count -gt 0 -and $GamingSrv_STOP.Count -gt 0)
{
	"Look like you have CheckPoint based software installed, Like ZoneAlarm, please uninstall it" | PauseAndFail -ErrorLevel 39
}

If ($GamingServices_Any_Error.Count -gt 0)
{
	#$ForceReinstallGS = $true
}

If ($GamingServices_All.Count -eq 0 -and $GamingServices_Any.Count -gt 0)
{
	Write-Host -Object ""
	Write-Host -Object "WARING: Old version of Gaming Services found!"
	Write-Host -Object ""
	[Diagnostics.Process]::Start("ms-windows-store://pdp?productid=9mwpm2cqnlhn")
	"	Please udpate Gaming Services from the MS Store." | PauseOnly
}
ElseIf ($ForceReinstallGS -eq $true -and $GamingServices_All.Count -gt 0)
{
	Write-Host -Object "Removing Gaming Services app..."
	Get-Service -Name "GamingServices","GamingServicesNet" -ErrorAction Continue | Stop-Service -ErrorAction Continue
	If ($Drivers_XBOXL.Count -gt 0)
	{
		$Drivers_XBOX | ForEach-Object -Process {
			Start-Process -Wait -FilePath "pnputil.exe" -ArgumentList "/delete-driver",$_.Driver,"/uninstall","/force"
		}
	}
	$GamingServices_Any | Remove-AppxPackage -Verbose -PreserveApplicationData:$false
	$GamingServices_Any | Remove-AppxPackage -AllUsers -Verbose
	Write-Host -Object ""
	"We going to restart the computer to get Gaming Services App uninstall, please run the script again after reboot" | PauseOnly
	Start-Sleep -Seconds 30
	Restart-Computer -Verbose
	"ERROR: Gaming Services has been removed, a reboot will be needed to reinstall it" | PauseAndFail -ErrorLevel 24
}
ElseIf ($GamingServices_Any.Count -gt 0 -and $GamingServices_User.Count -eq 0)
{
	Write-Host -Object "Installing Gaming Services to user account..."
	$GamingServices_All | Where-Object InstallLocation -ne $null | ForEach-Object -Process {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -Verbose -ForceApplicationShutdown}
}
ElseIf ($GamingServices_All.Count -eq 0 -or $ForceLocalInstall -eq $true)
{
	Write-Host -Object "Downloading Gaming Services App... (10MB)"
	$URI = "https://github.com/Arks-Layer/PSO2WinstoreFix/raw/master/appx/Microsoft.GamingServices_2.42.5001.0_neutral___8wekyb3d8bbwe.AppxBundle"
	$FileD = "Microsoft.GamingServices_2.42.5001.0_neutral_~_8wekyb3d8bbwe.appxbundle"
	$SHA512 = "F6BE8E57F1B50FD42FA827A842FDFC036039A78A5B773E15D50E7BCDC9074D819485424544B8E2958AEAEA7D635AD47399A31D2F6F91C42CE28991A242294FE3"
	$Download = DownloadMe -URI $URI -OutFile $FileD -ErrorLevel 18 -SHA512 $SHA512
	If ($Drivers_XBOX.Count -gt 0)
	{
		$Drivers_XBOX | ForEach-Object -Process {
			Start-Process -Wait -FilePath "pnputil.exe" -ArgumentList "/delete-driver",$_.Driver,"/uninstall","/force"
		}
	}
	Write-Host -Object "Removing Gaming Services app..."
	$GamingServices_Any | Remove-AppxPackage -PreserveApplicationData:$false -Verbose
	$GamingServices_Any | Remove-AppxPackage -AllUsers -Verbose

	Write-Host -Object "Installing Gaming Services app..."
	Try {
		$BadInstall = $true
		$Download | Add-AppxPackage -Volume $SystemVolume -Verbose -ForceApplicationShutdown -ForceUpdateFromAnyVersion
		$BadInstall = $false
		$ForceReinstallGS = $true
	}
	Catch {$_}
	$GamingServices_Any = @()
	$GamingServices_Any += Get-AppxPackage -Name "Microsoft.GamingServices" -PackageTypeFilter Main -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" -AllUsers | PackageVersion -Version $GamingServices_version
	If ($BadInstall -eq $false -and $GamingServices_Any.Count -gt 0)
	{
		Write-Host -Object ""
		"We going to restart the computer to get Gaming Services App install, please run the script again after reboot" | PauseOnly
		Start-Sleep -Seconds 30
		Restart-Computer -Verbose
		"ERROR: Gaming Services installed, please reboot." | PauseAndFail -ErrorLevel 25
		#Resolve-Path -LiteralPath $FileD | Remove-Item -Verbose
	}
}

If ($false) #($GamingServices_Any.Count -eq 0 -or $ForceReinstallGS -eq $true)
{
	Write-Host -Object ""
	Write-Host -Object "Starting MS Store App with the Gaming Service Listing..."
	[Diagnostics.Process]::Start("ms-windows-store://pdp?productid=9mwpm2cqnlhn")
	"ERROR: Please make sure to install the Gaming Services from the MS Store." | PauseAndFail -ErrorLevel 26
}
ElseIf ($GamingServices_Any.Count -eq 0 -and $ForceReinstallGS -eq $true)
{
	Write-Host -Object ""
	Write-Host -Object "Starting MS Store App with the XBox (Beta) Listing..."
	[Diagnostics.Process]::Start("ms-windows-store://pdp?productid=9mv0b5hzvk9z")
}

Write-Host -Object ""
Write-Host -Object "Status of GamingService App"
Get-AppxPackage -Name "Microsoft.GamingServices" -PackageTypeFilter Main -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" -AllUsers
Write-Host -Object "End of Status Report"

Write-Host -Object "Finding GameGuard Service..."
$npggsvc = @()
$npggsvc += Get-Service -ErrorAction SilentlyContinue -Name "npggsvc"
If ($npggsvc.Count -gt 0)
{
	Write-Host -Object "Found GameGuard Service..."
	Write-Host -Object "Trying to stop it..."
	Try
	{
		$BrokenGG = $true
		$npggsvc | Where-Object Statis -EQ "Running" | Stop-Service -ErrorAction Continue -PassThru | Set-Service -StartupType Manual
		$BrokenGG = $false
	}
	Catch {$_}
	$npggsvcK = "HKLM:SYSTEM\CurrentControlSet\Services\npggsvc"
	If (-Not (Test-Path -LiteralPath $npggsvcK))
	{
		$BrokenGG = $true
	}

	If ($BrokenGG)
	{
		#Delete-Service do not exist in Power-Shell 5.1
		Start-Process -Wait -FilePath $env:ComSpec -ArgumentList "/C","$($env:SystemRoot)\System32\sc.exe","delete","npggsvc" -WindowStyle Minimized
	}
}

$OneDrives = @()
$OneDrives += (Get-ChildItem -Path Env: | Where-Object Name -like "OneDrive*").Value | Sort-Object -Unique

Write-Host -Object "Looking at My Document folder"
If ($SkipOneDrive -ne $true)
{
	$PersonalFolder = [System.Environment]::GetFolderPath([Environment+SpecialFolder]::MyDocuments)
	Write-Host -Object "User Document folder is: $($PersonalFolder)"
	If ($PersonalFolder -eq "")
	{
		"Ahhh, Can not find your Document Folder" | PauseOnly
	}
	If (-Not (Test-Path -LiteralPath $PersonalFolder -PathType Container))
	{
		"ERROR: The Documents folder is missing: $($PersonalFolder)" | PauseAndFail -ErrorLevel 32
	}
	$OneDriveFolder = @()
	If ($OneDrives.Count -gt 0)
	{
		$OneDriveFolder += $OneDrives | ForEach-Object -Process {
			If (-Not (Test-Path -LiteralPath $_ -PathType Container))
			{
				Return
			}
			Elseif (-Not (CheckPath -Path $PersonalFolder -BadFolders $_))
			{
				Return
			}
			$_
		}
	}
	$SegaFolder = Join-Path $PersonalFolder -ChildPath "SEGA"
	If (-Not (Test-Path -LiteralPath $SegaFolder -PathType Container))
	{
		New-Item -Path $SegaFolder -ItemType Directory | Out-Null
	}
	Write-Host -Object "Removing READONLY attrib bit from SEGA folder..."
	Start-Process -FilePath "attrib.exe" -ArgumentList "-R",('"{0}"' -f $SegaFolder),"/S","/D" -Wait -Verbose -WindowStyle Minimized
	If ($OneDriveFolder.Count -gt 0)
	{
		Write-Host -Object "Found OneDrive usage, pinning SEGA folder to always on local computer.."
		Start-Process -FilePath "attrib.exe" -ArgumentList "-U","+P",('"{0}"' -f $SegaFolder),"/S","/D" -Wait -Verbose -WindowStyle Minimized
	}
}

Write-Host -Object "Checking PSO2 Tweaker settings..."
$JSONPath = $null
$JSONData = $null
$PSO2NABinFolder = $null
$PSO2NAFolder = $null
$JSONPath = [System.Environment]::ExpandEnvironmentVariables("%APPDATA%\PSO2 Tweaker\settings.json")

Write-Host -Object "Checking for existing PSO2NA package..."
$PSO2NABinFolder_FallBack = $null
$MSPackages = @()
$MSPackages += Get-AppxPackage -Name "100B7A24.oxyna" -AllUsers | Where-Object -Property SignatureKind -EQ "Store"
If ($MSPackages.Count -eq 1)
{
	$MSItem = Get-Item -LiteralPath $MSPackages.InstallLocation -ErrorAction Continue
	If ($MSItem.Target.Count -eq 1)
	{
		$MSItem = Get-Item -LiteralPath ($MSItem.Target -join "")
	}
	$PSO2NABinFolder_FallBack = Join-Path $MSItem.FullName -ChildPath "..\ModifiableWindowsApps\pso2_bin"
}
$UTPackages = @()
$UTPackages += Get-AppxPackage -Name "100B7A24.oxyna" -AllUsers | Where-Object -Property SignatureKind -EQ "None"
If ($UTPackages.Count -eq 1)
{
	$PSO2NABinFolder_FallBack = Join-Path $UTPackages.InstallLocation -ChildPath "pso2_bin"
}

If ($JSONPath)
{
	Write-Host -Object "Loading Tweaker Config from $($JSONPath)"
	$JSONData = Get-Content -LiteralPath $JSONPath -Encoding UTF8 -Verbose
}
Else
{
	Write-Host -Object ""
	"ERROR: Cannot find %APPDATA% folder - Is your Windows properly set up?" | PauseAndFail -ErrorLevel 5
}
If ($JSONData)
{
	$JSONObj = $JSONData | ConvertFrom-Json -Verbose
	Write-Host -Object "Tweaker Settings for logging:"
	$JSONObj
}
Else
{
	Write-Host -Object ""
	"ERROR: Cannot read Tweaker Setting JSON - Did you set up the Tweaker yet?" | PauseAndFail -ErrorLevel 6
}
If ($JSONObj)
{
	$PSO2NABinFolder = ""
	try {
		$PSO2NABinFolder = $JSONObj | Select-Object -ExpandProperty PSO2NABinFolder
	}
	catch {$_}

	If ($null -eq $PSO2NABinFolder -and $null -ne $PSO2NABinFolder_FallBack)
	{
		$PSO2NABinFolder = $PSO2NABinFolder_FallBack
	}
}
Else
{
	Write-Host -Object ""
	"ERROR: Can not convert JSON into PowerShell Object. This shouldn't happen!" | PauseAndFail -ErrorLevel 7
}
If ($PSO2NABinFolder -eq "")
{
	Write-Host -Object ""
	"ERROR: Old version of the Tweaker config file found, please update Tweaker."| PauseAndFail -ErrorLevel 20
}
ElseIF ($PSO2NABinFolder -contains "[" -or $PSO2NABinFolder -contains "]")
{
	Write-Host -Object ""
	"ERROR: The $($PSO2NABinFolder) folder have [ or ], PowerShell have issues with folder name." | PauseAndFail -ErrorLevel 28
}
ElseIf ($null -eq $PSO2NABinFolder)
{
	Write-Host -Object ""
	"ERROR: Tweaker NA Setup is not done, please tell me where to install PSO2NA." | PauseAndFail -ErrorLevel 20
}
ElseIf (-Not (Test-Path -LiteralPath "$($PSO2NABinFolder)" -PathType Container))
{
	Write-Host -Object ""
	"ERROR: The $($PSO2NABinFolder) folder does not exist. Please check your PSO2 Tweaker settings." | PauseAndFail -ErrorLevel 16
}
ElseIf ($PSO2NABinFolder)
{
	$PSO2NAFolder = $PSO2NABinFolder | Split-Path
}
Else
{
	Write-Host -Object ""
	"ERROR: Cannot find a PSO2NABinFolder setting - Did you set up PSO2NA through the Tweaker yet? If not, do it." | PauseAndFail -ErrorLevel 8
}
If (-Not (Test-Path -LiteralPath $PSO2NAFolder -PathType Container))
{
	Write-Host -Object ""
	"ERROR: The $($PSO2NAFolder) folder does not exist. Please check your PSO2 Tweaker settings." | PauseAndFail -ErrorLevel 17
}
ElseIf ($PSO2NAFolder -eq ($PSO2NAFolder | Split-Path -Leaf))
{
	"Sorry, but it seems you installed PSO2NA at the top of a drive, please move the pso2_bin folder into an another folder" | PauseANdFail -ErrorLevel 37
}
ElseIf ($PSO2NAFolder)
{
	$PSO2NABinFolder_PI = Get-Item -LiteralPath $PSO2NABinFolder
	If ($PSO2NABinFolder_PI.Target.Count -eq 1)
	{
		$PSO2NABinFolder_PI = Get-Item -LiteralPath ($PSO2NABinFolder_PI.Target -join "")
	}
	$PSO2NABinFolder_RP = Resolve-Path -LiteralPath $PSO2NABinFolder_PI.FullName
	$PSO2Drive = ("{0}:" -f $PSO2NABinFolder_RP.Drive.Name)
	$PSO2Drive_Root = $PSO2NABinFolder_RP.Drive.Root
	$LeafPath = $PSO2NAFolder | Split-Path -Leaf
	Write-Host -Object "Deleting broken patch files..."
	Get-ChildItem -LiteralPath $PSO2NABinFolder -Recurse -Force -File -ErrorAction Continue | Where-Object Extension -eq ".pat" | Remove-Item -Force -ErrorAction Continue
	If ($LeafPath -eq "ModifiableWindowsApps")
	{
		"Sorry, look like PSO2NA was installed via MS Store, we going to move the PSO2NA folder for you" | PauseOnly
		$PSO2NAFolder = Join-Path -Path $PSO2Drive_Root -ChildPath "PHANTASYSTARONLINE2_NA"
		New-Item -Path $PSO2NAFolder -ItemType Directory -Force -Confirm:$false -Verbose | Out-Null
		$PSO2NABinFolder = Join-Path -Path $PSO2NAFolder -ChildPath "pso2_bin"
		New-Item -Path $PSO2NABinFolder -ItemType Directory -Force -Confirm:$false -Verbose | Out-Null
		$JSONObj.PSO2NABinFolder = $PSO2NABinFolder
		$JSONObj | ConvertTo-Json | Out-File -FilePath $JSONPath -Encoding UTF8
		Remove-Item -Path "client_na.json" -Force -Verbose
		$SkipRobomove = $false
		$ForceReHash = $true
	}
	else
	{
		Write-Host -Object "Non MS Store copy installation detected"
 		$MAX_PATH = ("X:\".Length + 260) - ("\data\win32_na\0000000000000000000000000000000".Length)
		If ($PSO2NAFolder.Length -ge $MAX_PATH)
		{
			"pso2_bin folder is too long and will break old ANSI Win32 programs" | PauseOnly
		}
	}
}
Else
{
	Write-Host -Object ""
	"ERROR: Cannot get PSO2NA Folder - Did you follow the instructions?" | PauseAndFail -ErrorLevel 9
}

"Checking if PSO2 is installed in a blackhole folder"
$BadFolders = @()
$BadFolders_40 = [System.Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
$BadFolders_16 = [System.Environment]::GetFolderPath([Environment+SpecialFolder]::DesktopDirectory)
If ($null -ne $BadFolders_16 -and "" -ne $BadFolders_16)
{
	$BadFolders += $BadFolders_16
}
Else
{
	Write-Host -Object "No Desktop folder found"
	$BadFolders += Join-Path -Path $BadFolders_40 -ChildPath "Desktop"
}
$BadFolders_06 = [System.Environment]::GetFolderPath([Environment+SpecialFolder]::Favorites)
If ($null -ne $BadFolders_06 -and "" -ne $BadFolders_06)
{
	$BadFolders += $BadFolders_06
}
Else
{
	Write-Host -Object "No Favorites folder found"
	$BadFolders += Join-Path -Path $BadFolders_40 -ChildPath "Favorites"
}
$BadFolders_05 = [System.Environment]::GetFolderPath([Environment+SpecialFolder]::MyDocuments)
If ($null -ne $BadFolders_05 -and "" -ne $BadFolders_05)
{
	$BadFolders += $BadFolders_05
}
Else
{
	Write-Host -Object "No Documents folder found"
	$BadFolders += Join-Path -Path $BadFolders_40 -ChildPath "Documents"
}
$BadFolders_13 = [System.Environment]::GetFolderPath([Environment+SpecialFolder]::MyMusic)
If ($null -ne $BadFolders_13 -and "" -ne $BadFolders_13)
{
	$BadFolders += $BadFolders_13
}
Else
{
	Write-Host -Object "No Music folder found"
	$BadFolders += Join-Path -Path $BadFolders_40 -ChildPath "Music"
}
$BadFolders_39 = [System.Environment]::GetFolderPath([Environment+SpecialFolder]::MyPictures)
If ($null -ne $BadFolders_39 -and "" -ne $BadFolders_39)
{
	$BadFolders += $BadFolders_39
}
Else
{
	Write-Host -Object "No Pictures folder found"
	$BadFolders += Join-Path -Path $BadFolders_40 -ChildPath "Pictures"
}
$BadFolders_14 = [System.Environment]::GetFolderPath([Environment+SpecialFolder]::MyVideos)
If ($null -ne $BadFolders_14 -and "" -ne $BadFolders_14)
{
	$BadFolders += $BadFolders_14
}
Else
{
	Write-Host -Object "No Videos folder found"
	$BadFolders += Join-Path -Path $BadFolders_40 -ChildPath "Videos"
}
$BadFolders_38 = [System.Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
If ($null -ne $BadFolders_38 -and "" -ne $BadFolders_38)
{
	$BadFolders += $BadFolders_38
}
$BadFolders_42 = [System.Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86)
If ($null -ne $BadFolders_42 -and "" -ne $BadFolders_42)
{
	$BadFolders += $BadFolders_42
}

If ($OneDrives.Count -gt 0)
{
	$BadFolders += $OneDrives
}
If ( $AddonVolumes.Count -gt 0)
{
	$BadFolders += Join-Path -Path ($AddonVolumes.PackageStorePath|Split-Path -Parent) -ChildPath "Program Files"
}
"The following folders are noted as blackholes:"
$BadFolders
If (CheckPath -Path $PSO2NAFolder -BadFolders $BadFolders)
{
	"Sorry, look like PSO2NA was installed to a blackhole folder, we going to move the PSO2NA folder for you" | PauseOnly
	$NewPSO2Folder = Move-Item -LiteralPath $PSO2NAFolder -Destination $PSO2Drive_Root -Force -PassThru -Confirm:$false -Verbose
	$PSO2NAFolder = $NewPSO2Folder.FullName
	$PSO2NABinFolder = Join-Path -Path $PSO2NAFolder -ChildPath "pso2_bin"
	$JSONObj.PSO2NABinFolder = $PSO2NABinFolder
	$JSONObj | ConvertTo-Json | Out-File -FilePath $JSONPath -Encoding UTF8
	$ForceReHash = $true
}

"Report of Drive status"
$Volumes = @()
try{
$Volumes += Get-Volume -ErrorAction Continue
} catch {$_}
$Volumes | Where-Object DriveLetter -NE $null | Where-Object DriveType -NE "CD-ROM" | Select-Object -Property DriveLetter, DriveType, FileSystem, FileSystemLabel, HealthStatus, OperationalStatus, Path
"End of Report"
"Checking if Volume is formated as NTFS..."
$PSO2Vol = @()
Try
{
	$BrokenVolume = $true
	If ($SkipStorageCheck -ne $true -and $Volumes.Count -gt 0)
	{
		$PSO2Vol += Get-Volume -FilePath $PSO2NAFolder
	}
	$BrokenVolume = $false
}
Catch
{
	$_
	#PauseAndFail -ErrorLevel 19
}

$PSO2Vol_exFAT = @()
$PSO2Vol_FAT   = @()
$PSO2Vol_FAT32 = @()
$PSO2Vol_NTFS  = @()
$PSO2Vol_ReFS  = @()
$PSO2Vol_Unk   = @()
$PSO2Vol_exFAT += $PSO2Vol | Where-Object -Property FileSystemType -EQ exFAT
$PSO2Vol_FAT   += $PSO2Vol | Where-Object -Property FileSystemType -EQ FAT
$PSO2Vol_FAT32 += $PSO2Vol | Where-Object -Property FileSystemType -EQ FAT32
$PSO2Vol_NTFS  += $PSO2Vol | Where-Object -Property FileSystemType -EQ NTFS
$PSO2Vol_ReFS  += $PSO2Vol | Where-Object -Property FileSystemType -EQ ReFS
$PSO2Vol_UnK   += $PSO2Vol | Where-Object -Property FileSystemType -EQ Unknown

If ($BrokenVolume -eq $true)
{
	"WARNING: Your system's WMI database is broken, please repair it." | PauseOnly
}
ElseIf ($PSO2Vol_exFAT.Count -gt 0)
{
	"WARNING: Your PSO2NA installation on an exFAT formatted drive, please move the PSO2NA installation elsewhere." | PauseAndFail -ErrorLevel 15
}
ElseIf ($PSO2Vol_FAT.Count -gt 0)
{
	"WARNING: Your PSO2NA installation on an FAT formatted drive, please move the PSO2NA installation elsewhere." | PauseAndFail -ErrorLevel 15
}
ElseIf ($PSO2Vol_FAT32.Count -gt 0)
{
	"WARNING: Your PSO2NA installation on an FAT32 formatted drive, please move the PSO2NA installation elsewhere." | PauseAndFail -ErrorLevel 15
}
ElseIf ($PSO2Vol_NTFS.Count -gt 0)
{
	Write-Host -Object "Your PSO2NA installation is on a NTFS drive \o/"
}
ElseIf ($PSO2Vol_ReFS.Count -gt 0)
{
	"WARNING: Your PSO2NA installation on an ReFS formatted drive, please move the PSO2NA installation elsewhere." | PauseAndFail -ErrorLevel 15
}
ElseIf ($PSO2Vol_UnK.Count -gt 0)
{
	"WARNING: Your PSO2NA installation on an UNKNOWN formatted drive, please move the PSO2NA installation elsewhere." | PauseAndFail -ErrorLevel 15
}
ElseIF ($PSO2Vol.Count -gt 0)
{
	"WARNING: Your PSO2NA installation in on an unknown filesytem: $($PSO2Vol.FileSystem -join ",")?" | PauseOnly
}
Else
{
	Write-Host -Object "Unknown issue geting Storage data"
}

"Checking for broken link files"
Get-ChildItem -LiteralPath $PSO2NABinFolder -Recurse -File | Where-Object Mode -eq "-a---l" | Remove-Item -Force -Verbose

$MissingFiles = $false
"Checking for appxmanifest.xml..."
$Testing = Join-Path -Path $PSO2NAFolder -ChildPath "appxmanifest.xml"
If (-Not ($Testing | Test-Path -PathType Leaf))
{
	$MissingFiles = $true
	Write-Host -Object "	MISSING"
}
ElseIf ((Get-Item -LiteralPath $Testing).Length -eq 0)
{
	Write-Host -Object "	EMPTY"
	Remove-Item -LiteralPath $Testing -Force -Verbose
	$MissingFiles = $true
}
Else
{
	Write-Host -Object "	FOUND"
	[xml]$XMLContent = Get-Content -LiteralPath $Testing -Encoding UTF8 -Verbose
	If ($null -ne $XMLContent.Package.Extension -or $XMLContent.Package.Applications.Application.Executable -ne "pso2_bin/pso2.exe")
	{
		Write-Host -Object "	BUT it is the MS Store copy, not Custom one"
		Remove-Item -LiteralPath $Testing -Force -Verbose
		$MissingFiles = $true
	}
}
"Checking for MicrosoftGame.config..."
$Testing = Join-Path -Path $PSO2NAFolder -ChildPath "MicrosoftGame.config"
If (-Not ($Testing | Test-Path -PathType Leaf))
{
	$MissingFiles = $true
	Write-Host -Object "	MISSING"
}
ElseIf ((Get-Item -LiteralPath $Testing).Length -eq 0)
{
	Write-Host -Object "	EMPTY"
	Remove-Item -LiteralPath $Testing -Force -Verbose
	$MissingFiles = $true
}
Else
{
	Write-Host -Object "	FOUND"
}
"Checking for pso2_bin/pso2.exe file..."
$Testing = Join-Path -Path $PSO2NABinFolder -ChildPath "pso2.exe"
If (-Not ($Testing | Test-Path -PathType Leaf))
{
	$MissingFiles = $true
	Write-Host -Object "	MISSING"
}
ElseIf ($false) #((Get-Item -LiteralPath $Testing).Length -eq 0)
{
	Write-Host -Object "	EMPTY"
	Remove-Item -LiteralPath $Testing -Force -Verbose
	$MissingFiles = $true
}
Else
{
	Write-Host -Object "	FOUND"
}
"Checking for pso2_bin/Logo.png file..."
$Testing = Join-Path -Path $PSO2NABinFolder -ChildPath "Logo.png"
If (-Not ($Testing | Test-Path -PathType Leaf))
{
	$MissingFiles = $true
	Write-Host -Object "	MISSING"
}
ElseIf ((Get-Item -LiteralPath $Testing).Length -eq 0)
{
	Write-Host -Object "	EMPTY"
	Remove-Item -LiteralPath $Testing -Force
	$MissingFiles = $true
}
Else
{
	Write-Host -Object "	FOUND"
}
"Checking for pso2_bin/SmallLogo.png file..."
$Testing = Join-Path -Path $PSO2NABinFolder -ChildPath "SmallLogo.png"
If (-Not ($Testing | Test-Path -PathType Leaf))
{
	$MissingFiles = $true
	Write-Host -Object "	MISSING"
}
ElseIf ((Get-Item -LiteralPath $Testing).Length -eq 0)
{
	Write-Host -Object "	EMPTY"
	Remove-Item -LiteralPath $Testing -Force
	$MissingFiles = $true
}
Else
{
	Write-Host -Object "	FOUND"
}
"Checking for pso2_bin/SplashScreen.png file..."
$Testing = Join-Path -Path $PSO2NABinFolder -ChildPath "SplashScreen.png"
If (-Not ($Testing | Test-Path -PathType Leaf))
{
	$MissingFiles = $true
	Write-Host -Object "	MISSING"
}
ElseIf ((Get-Item -LiteralPath $Testing).Length -eq 0)
{
	Write-Host -Object "	EMPTY"
	Remove-Item -LiteralPath $Testing -Force
	$MissingFiles = $true
}
Else
{
	Write-Host -Object "	FOUND"
}

If ($MissingFiles -eq $true)
{
	Write-Host -Object "Downloading Starter files... (3 MB)"
	$URI = "https://github.com/Arks-Layer/PSO2WinstoreFix/raw/master/pso2_bin_na_starter.zip"
	$FileD = "pso2_bin_na_starter.zip"
	$MISSING = DownloadMe -URI $URI -OutFile $FileD -ErrorLevel 11 -SHA512 "50D8E90B66751EE4C238521E372D93A80D4767CBE007B74379D3BBD14FE94780C4D2D86A67D6C7E03F889FB777A0290DF08B5DA916CDCC50B294F0E4AA8160A5"
	$TMPFolder = New-Item -Path "UNPACK" -ItemType Directory -Verbose -Force
	$TMPBinFolder = New-Item -Path "UNPACK\pso2_bin" -ItemType Directory -Verbose -Force
	Expand-Archive -LiteralPath $MISSING -DestinationPath $TMPFolder -Force
	Get-ChildItem -LiteralPath $TMPFolder -File | ForEach-Object -Process {
		$OldFile = Join-Path -Path $PSO2NAFolder -ChildPath $_.Name
		If (-Not (Test-Path -LiteralPath $OldFile -PathType Leaf))
		{
			Copy-Item -LiteralPath $_.FullName -Destination $OldFile
		}
	}
	Get-ChildItem -LiteralPath $TMPBinFolder -File | ForEach-Object -Process {
		$OldFile = Join-Path -Path $PSO2NABinFolder -ChildPath $_.Name
		If (-Not (Test-Path -LiteralPath $OldFile -PathType Leaf))
		{
			Copy-Item -LiteralPath $_.FullName -Destination $OldFile
		}
	}
	Remove-Item -LiteralPath $TMPFolder -Recurse -Force -Confirm:$false
}

Write-Host -Object "Checking for Developer Mode..."
$DevMode = $false
$RegistryKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock"
if (Test-Path -LiteralPath $RegistryKeyPath)
{
	$AppModelUnlock = Get-ItemProperty -LiteralPath $RegistryKeyPath
	if ($null -ne $AppModelUnlock -and $null -ne ($AppModelUnlock | Get-Member -Name AllowDevelopmentWithoutDevLicense) )
	{
		$RegData = $AppModelUnlock | Select-Object -ExpandProperty AllowDevelopmentWithoutDevLicense
		If ($RegData -eq 1)
		{
			$DevMode = $true
		}
	}
}
If ($DevMode -EQ $false)
{
	Write-Host -Object ""
	Write-Host -Object "You need to enable Developer mode. Please see https://www.howtogeek.com/292914/what-is-developer-mode-in-windows-10/" -ForegroundColor Red
	"Developer mode is disabled" | PauseAndFail -ErrorLevel 4
}
"[OK]"

$NAFiles = @("version.ver")
If (Test-Path "client_na.json" -PathType Leaf)
{
	$NAState = @()
	Write-Host -Object "Reading Tweaker's UpdateEngine for PSO2NA"
	$NAFile = Get-Content -Path "client_na.json" -Encoding UTF8 -Force -Verbose
	Write-Host -Object "Loading $($NAFile.Length) bytes client JSON file"
	If ($NAFile.Length -gt 10)
	{
		$NAState += $NAFile | ConvertFrom-Json -Verbose
	}
	If ($NAState.Count -eq 1)
	{
		$NAFiles += (($NAState | Get-Member -MemberType NoteProperty) | Where-Object Name -ne $null | Where-Object Name -ne "").Name
	}
  	Write-Host -Object "Getting list of data files to exclude: $($NAFiles.Count)"
}

$OldBackups = @()
"Looking for old PSO2NA MutableBackup folders..."
$OldBackups += FindMutableBackup
$MWA = @()
$MWA += FindMutable_Appx
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
		Write-Host -Object "Going to move the MS STORE core's data files to your Tweaker copy of PSO2..."
		RobomoveByFolder -source $OldBin -destination $PSO2NABinFolder -SkipRemove $true
		#Write-Host -Object "Deleting old MS STORE's pso2_bin core's date folder..."
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
	$ForceReHash = $true
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
		Write-Host -Object "Going to move the old MS STORE backup files from $($OldBin) to your Tweaker copy of PSO2..."
		RobomoveByFolder -source $OldBin -destination $PSO2NABinFolder
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
	$ForceReHash = $true
}

If ($MWA.Count -gt 0)
{
	$MWA | ForEach-Object -Process {
		$OldBin = $_
		Write-Host -Object "Found the old MS STORE's pso2_bin patch folder!"
		Takeownship -path $OldBin
		Write-Host -Object "Removing $($NAFiles.Count) unneeded files..."
		$NAFiles | Join-Paths -Path $OldBin | Remove-Item -Force -ErrorAction SilentlyContinue
		Write-Host -Object "Going to move the MS STORE patch files to your Tweaker copy of PSO2..."
		RobomoveByFolder -source $OldBin -destination $PSO2NABinFolder
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
	$ForceReHash = $true
}

If ($OldPackages.Count -gt 0)
{
	Write-Host -Object "If this takes more then 30 minutes, you may have to reboot."
	Write-Host -Object "Unregistering the old PSO2 from the Windows Store... (This may take a while, don't panic!)"
	$OldPackages | Remove-AppxPackage -AllUsers -Verbose -ErrorAction Continue
}
Else
{
	Write-Host -Object "No Windows Store PSO2NA installation found. This is OK!"
}

"Checking if we need to install the requirements..."
$NewPackages = @()

$DirectXRuntime_All = @()
$DirectXRuntime_User = @()
$DirectXRuntime_version = [Version]"9.29.952.0"
$DirectXRuntime_All += Get-AppxPackage -Name "Microsoft.DirectXRuntime" -PackageTypeFilter Framework -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" -AllUsers | PackageVersion -Version $DirectXRuntime_version
$DirectXRuntime_User += Get-AppxPackage -Name "Microsoft.DirectXRuntime" -PackageTypeFilter Framework -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" | PackageVersion -Version $DirectXRuntime_version

$DirectXRuntime_User_Error = @()
$DirectXRuntime_User_Error += $DirectXRuntime_All.PackageUserInformation | Where-Object -FilterScript {$_.UserSecurityId.Sid -like $myWindowsID.User.Value} | Where-Object InstallState -NotIn "Installed","Staged"
$DirectXRuntime_All_Error = @()
$DirectXRuntime_All_Error += $DirectXRuntime_All.PackageUserInformation | Where-Object -FilterScript {$_.UserSecurityId.Sid -like "S-1-5-18"} | Where-Object InstallState -NotIn "Installed","Staged"

if ($DirectXRuntime_All.Count -gt 0 -and ($DirectXRuntime_User.Count -eq 0 -or $DirectXRuntime_User_Error.Count -gt 0) -and $DirectXRuntime_All_Error.Count -eq 0)
{
	Write-Host -Object "System already has a good copy of DirectX, trying to install the user profile..."
	$DirectXRuntime_All | Where-Object InstallLocation -ne $null | Sort-Object -Unique InstallLocation | ForEach-Object -Process {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -Verbose}
	$DirectXRuntime_User += Get-AppxPackage -Name "Microsoft.DirectXRuntime" -PackageTypeFilter Framework -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" | PackageVersion -Version $DirectXRuntime_version
}

If ($DirectXRuntime_User.Count -eq 0 -or $DirectXRuntime_All_Error.Count -gt 0)
{
	Write-Host -Object "Downloading DirectX Runtime requirement... (56MB)"
	$URI = "https://download.microsoft.com/download/c/c/2/cc291a37-2ebd-4ac2-ba5f-4c9124733bf1/UAPSignedBinary_Microsoft.DirectX.x64.appx"
	$FileD = "UAPSignedBinary_Microsoft.DirectX.x64.appx"
	$NewPackages += DownloadMe -URI $URI -OutFile $FileD -ErrorLevel 12 -SHA512 "7D6980446CCAB7F08C498CE28DFA3707876768CB0D54E6912D8689F8D92E639A54FDCD0F0730D3FCF9ED9E970F34DFA97816C85C779B63D003AB54324BCCB5FB"
}


$VCLibs_All = @()
$VCLibs_User = @()
$VCLibs_Version = [Version]"14.0.24217.0"
$VCLibs_All += Get-AppxPackage -Name "Microsoft.VCLibs.140.00.UWPDesktop" -PackageTypeFilter Framework -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" -AllUsers | PackageVersion -Version $VCLibs_Version
$VCLibs_User += Get-AppxPackage -Name "Microsoft.VCLibs.140.00.UWPDesktop" -PackageTypeFilter Framework -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" | PackageVersion -Version $VCLibs_Version

$VCLibs_User_Error = @()
$VCLibs_User_Error += $VCLibs_All.PackageUserInformation | Where-Object -FilterScript {$_.UserSecurityId.Sid -like $myWindowsID.User.Value} | Where-Object InstallState -NotIn "Installed","Staged"
$VCLibs_All_Error = @()
$VCLibs_All_Error += $VCLibs_All.PackageUserInformation | Where-Object -FilterScript {$_.UserSecurityId.Sid -like "S-1-5-18"} | Where-Object InstallState -NotIn "Installed","Staged"

If ($VCLibs_All.Count -gt 0 -And ($VCLibs_User.Count -eq 0 -or $VCLibs_User_Error.Count -gt 0) -and $VCLibs_All_Error.Count -eq 0)
{
	Write-Host -Object "System already has a good copy of VCLibs, trying to install the user profile"
	$VCLibsAll | Where-Object InstallLocation -ne $null | Sort-Object -Unique InstallLocation | ForEach-Object -Process {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -Verbose}
	$VCLibs_User += Get-AppxPackage -Name "Microsoft.VCLibs.140.00.UWPDesktop" -PackageTypeFilter Framework -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" | PackageVersion -Version $VCLibs_Version
}

if ($VCLibs_User.Count -eq 0 -or $VCLibs_All_Error.Count -gt 0)
{
	Write-Host -Object "Downloading VCLibs requirement... (7MB)"
	$URI = "https://github.com/Arks-Layer/PSO2WinstoreFix/blob/master/appx/Microsoft.VCLibs.x64.14.00.Desktop.appx?raw=true"
	$FileD = "Microsoft.VCLibs.x64.14.00.Desktop.appx"
	$NewPackages += DownloadMe -URI $URI -OutFile $FileD -ErrorLevel 13 -SHA512 "AF30593D82995AEF99DB86BF274407DC33D4EB51F3A79E7B636EA1C905F127E34310416EFB43BB9AC958992D175EB76806B27597E0B1AFE24D51D5D84C9ACF3A"
}

If ($NewPackages.Count -gt 0)
{
	Write-Host -Object "Installing requirements... If you see an error about it not being installed becuase of a higher version, that's OK!"
	$NewPackages | Add-AppxPackage -Stage -Volume $SystemVolume -Verbose -ErrorAction Continue
	$NewPackages | Add-AppxPackage -Volume $SystemVolume -Verbose -ErrorAction Continue
	#$NewPackages | Remove-Item -Verbose
}
Else
{
	Write-Host -Object "Requirements already installed"
}
""
"Status of DirectX framework"
Get-AppxPackage -Name "Microsoft.DirectXRuntime" -PackageTypeFilter Framework -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" -AllUsers
"Status of VCLIB framework"
Get-AppxPackage -Name "Microsoft.VCLibs.140.00.UWPDesktop" -PackageTypeFilter Framework -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" -AllUsers
"End of Framework status"


$PSO2Packages = @()
$PSO2Packages_User = @()
$PSO2Packages_Good = @()
$PSO2Packages_Bad = @()
$EmptyFiles = Get-ChildItem -LiteralPath $PSO2NABinFolder | Where-Object Name -ne "patchlist.txt" | Where-Object Name -NotLike "*.pat" | Where-Object Name -ne "PSO2NA_PSLOG.log" | Where-Object Name -NotLike "pso2.exe" | Where-Object Length -eq 0
$PSO2Packages +=  Get-AppxPackage -Name "100B7A24.oxyna" -AllUser | Where-Object -Property SignatureKind -EQ "None"
$PSO2Packages_User += Get-AppxPackage -Name "100B7A24.oxyna" | Where-Object -Property SignatureKind -EQ "None"
$PSO2Packages_Good += $PSO2Packages | Where-Object InstallLocation -eq $PSO2NAFolder | Where-Object Status -EQ "Ok"
$PSO2Packages_Bad += $PSO2Packages | Where-Object InstallLocation -ne $PSO2NAFolder
$PSO2Packages_Bad += $PSO2Packages | Where-Object Status -ne "Ok"
#$PSO2Packages_Bad += $PSO2Packages | PackageVersion -Version "1.0.7.0"

$XBOXURI = Test-Path -LiteralPath "Registry::HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\windows.protocol\ms-xbl-78a72674" -PathType Container
"Checking if XBOX protocol ms-xbl-78a72674 is registed"
If ($XBOXURI -eq $false)
{
	Write-Host -Object "	BAD"
	$ForceReinstall = $true
}
Else
{
	Write-Host -Object "	GOOD"
}

"Checking if an PSO2NA package is already installed on the system"
If ($PSO2Packages_User.Count -eq 0)
{
	Write-Host -Object "	YES"
	$ForceReinstall = $true
}
Else
{
	Write-Host -Object "	NO"
}

If ($ForceReinstall)
{
	Write-Host -Object "Bad install found, forcing a PSO2 reinstall..."
	Get-AppxPackage -Name "100B7A24.oxyna" -AllUsers | Remove-AppxPackage -Verbose -AllUsers
}
ElseIf ($PSO2Packages_Bad.Count -gt 0)
{
	Write-Host -Object "Found a old custom PSO2 install:"
	$PSO2Packages_Bad
	Write-Host -Object "removing it..."
	$PSO2Packages_Bad | Remove-AppxPackage -Verbose -AllUsers
}

"Making sure that the Appx volume is online..."
"REPORT: Current Appx volume setup"
""
Get-AppxVolume
""
"End of Appx volume report."
""
"Status of Appx volume that your custom PSO2 install is on:"
$AppxVols = @()
$PSO2Drive_Apps = @()
try {
$PSO2Drive_Apps += Get-AppxPackage -AllUsers -Volume $PSO2Drive -ErrorAction SilentlyContinue | Where-Object Name -NE "100B7A24.oxyna"
} catch {$_}
try {
Add-AppxVolume -Path $PSO2Drive -ErrorAction Continue
$AppxVols += Get-AppxVolume | Where-Object PackageStorePath -Like "$($PSO2Drive)*"
} catch {$_}
If ($AppxVols.Count -eq 0)
{
	Write-Host -Object "	TRAP"
}
ElseIf ($AppxVols.IsOffline -In $true)
{
	Write-Host -Object "	Custom PSO2 folder is on a drive with a broken Appx setup"
	$PSO2Packages | Remove-AppxPackage -Verbose -AllUsers
	If ($PSO2Drive_App.Count -eq 0)
	{
try {
		$AppxVols | Remove-AppxVolume -ErrorAction Continue
} catch {$_}
try {
		Add-AppxVolume -Path $PSO2Drive -ErrorAction Continue
} catch {$_}
	}
	Else
	{
try {
		Mount-AppxVolume -Volume $PSO2Drive -ErrorAction Continue
} catch {$_}
	}
	#PauseAndFail -ErrorLevel 29
}
else
{
	Write-Host -Object "	OK"
}
""

If ($PSO2Packages_Good.Count -eq 0 -or $ForceReinstall -eq $true) #Try
{
	$APPXXML = Join-Path -Path $PSO2NAFolder -ChildPath "appxmanifest.xml"
	Write-Host -Object "Registering our new shiny PSO2 with the Windows Store... (This may take a while, don't panic!)"
	If ($NewPackages.Count -gt 0 -and $false)
	{
		Add-AppxPackage -Register $APPXXML -Verbose -DependencyPath $PSO2NAFolder
	}
	Else
	{
		Add-AppxPackage -Register $APPXXML -Verbose
	}
	$EmptyFiles = @() + (Get-ChildItem -LiteralPath $PSO2NABinFolder -Force -File -ErrorAction Continue | Where-Object Length -eq 0)
	If ($EmptyFiles.Count -gt 0)
	{
		$ForceReHash = $true
	}
}
Else
{
	Write-Host -Object "There is already a custom PSO2 install?"
	$PSO2Packages_Good
}
If ($False) #Catch
{
	$_ | Failure
	#PauseAndFail -ErrorLevel 14
}
If ($NewPackages.Count -gt 0)
{
	#$NewPackages | Remove-Item -Verbose
}

If ($JSONObj.PSO2NARemoteVersion -eq 0)
{
	$ForceReHash = $true
}
ElseIf ($ForceReHash -eq $true)
{
	$JSONObj.PSO2NARemoteVersion = 0
	$JSONObj | ConvertTo-Json | Out-File -FilePath $JSONPath -Encoding UTF8
}

Write-Host -Object "Now double checking the custom PSO2 install..."
$CustomPSO2 = @()
$CustomPSO2 += Get-AppxPackage -Name "100B7A24.oxyna" | Where-Object IsDevelopmentMode -eq $true | Where-Object Status -EQ "Ok"

Write-Host -Object "Raw PSO2 install status:"
Get-AppxPackage -Name "100B7A24.oxyna"
Write-Host -Object ""
If ($CustomPSO2.Count -eq 0)
{
	 Write-Host -Object "Cannot find a custom PSO2 installation!" -ForegroundColor Red
}
ElseIf ($CustomPSO2.Count -eq 1)
{
	Write-Host -Object "Good, only found one custom PSO2 install."
	Get-ChildItem -Filter "*.txt" | Remove-Item -Force -Confirm:$false -ErrorAction Continue
	If ($ForceReHash -eq $true)
	{
		If (Test-Path -Path "client_na.json" -Verbose)
		{
			Remove-Item -Path "client_na.json" -Force -Verbose
		}
		RemakeClientHashs -Path $PSO2NABinFolder -Verbose | ConvertTo-Json | Out-File -FilePath "client_na.json" -Encoding UTF8
	}
	"We are going to start PSO2 Tweaker, please let it do an update check" | PauseOnly
	Start-Process -FilePath "PSO2 Tweaker.exe" -ArgumentList "-pso2na" -Verbose
}
Else
{
	Write-Host -Object "What? why are there $($CustomPSO2) custom PSO2 install?!"
}
""
Stop-Transcript -ErrorAction Continue
SetConsoleQuickEdit -Mode $true
Write-Host -Object 'Script complete! You can now close this window by pressing any key.'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
