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
	[Bool]$ForceLocalInstall = $true,
	[Bool]$SkipStorageCheck = $false
)
#f there an unhandled error, just stop
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
		Stop-Transcript
	} While ($true)
}
Catch {}
#Find the script's folder and add "PSO2NA_PSLOG.log" to end of it
If ($PSScriptRoot -ne $null)
{
	$ScriptLog = Join-Path -Path $PSScriptRoot -ChildPath "PSO2NA_PSLOG.log"
	Set-Location -LiteralPath $PSScriptRoot
}
Else
{
	$ScriptLog = Join-Path -Path "." -ChildPath "PSO2NA_PSLOG.log"
}

#Start logging
Start-Transcript -LiteralPath $ScriptLog
#Version number
"Version 2020_06_22_2049" # Error codes: 31
Import-Module Appx
Import-Module CimCmdlets
Import-Module Microsoft.PowerShell.Archive
Import-Module Microsoft.PowerShell.Host
Import-Module Microsoft.PowerShell.Management
Import-Module Microsoft.PowerShell.Utility
Import-Module Storage

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
try {
	$global:result = $Error.Exception.Response.GetResponseStream()
	$global:reader = New-Object System.IO.StreamReader($global:result)
	$global:responseBody = $global:reader.ReadToEnd();
	"Status: A system exception was caught."
	$global:responsebody
	Stop-Transcript
	$null = $global:Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
} catch {}
	#exit 254
}

#Downloader
Function DownloadMe
{
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory=$true, ValueFromPipeline=$true)]
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
		$ErrorLevel = 255,
		[Bool]
		$Overwrite = $true
	)
	If ($Overwrite -eq $true)
	{
		Remove-Item -Path $OutFile -ErrorAction SilentlyContinue
	}
	Try
	{
		If (-Not (Test-Path -LiteralPath $OutFile -PathType Leaf))
		{
			Invoke-WebRequest -Uri $URI -OutFile $OutFile -UserAgent "Arks-Layer pso2_winstore_fix" -Verbose
		}
		If (-Not (Test-Path -LiteralPath $OutFile -PathType Leaf))
		{
			""
			"Error: Failed to download file! You can manually download it by using the link below and saving it to the same place this script is:"
			""
			$URI
			""
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
		$AppxVols = @()
		$AppxVols += Get-AppxVolume -Online -Verbose
		$Mutable = @()
		$Mutable += $AppxVols | ForEach-Object {
			$Test = Join-Path $_.PackageStorePath -ChildPath "MutableBackup"
			If (Test-Path -LiteralPath $Test -PathType Container)
			{
				Return Resolve-Path -LiteralPath $Test -Verbose
			}
		}
		$Backups = @()
		$Backups += $Mutable | ForEach-Object {
			Return Get-ChildItem -LiteralPath $_.ProviderPath -Filter "$($Package)*" | Resolve-Path
		}
		If ($Backups.Count -gt 0)
		{
			$Backups.ProviderPath
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
		[String]
		$logfile = "robocopy.log"

	)
	If ($SkipRobomove -eq $true)
	{
		return
	}
	If (-Not (Test-Path -LiteralPath $source -PathType Container))
	{
		"ERROR: $($source) is not a folder"
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
	If ($file -eq "*.*" -or $file -eq "0*.*")
	{
		"Deleting empty files..."
		Get-ChildItem -LiteralPath $source -Force -File -ErrorAction Continue | Where-Object Length -eq 0 | Remove-Item -Force -ErrorAction Continue
		"Deleting broken patch files..."
		Get-ChildItem -LiteralPath $source -Force -File -ErrorAction Continue | Where-Object Extension -eq "pat" | Remove-Item -Force -ErrorAction Continue
	}
	"Starting robocopy job..."
	$Cmdlist = "/C","Robocopy.exe", ('"{0}"' -f $source),('"{0}"' -f $destination),('"{0}"' -f $file),"/XF","*.pat","/TEE","/DCOPY:DA","/COPY:DAT","/MOV","/ZB","/ETA","/XO","/R:0","/W:1",('/LOG+:"{0}"' -f $logpath.Path)
	If ($Details -eq $true)
	{
		$Cmdlist += "/V"
	}
	Start-Process -Wait -FilePath "C:\Windows\system32\cmd.exe" -ArgumentList $Cmdlist -WindowStyle Minimized
	Get-ChildItem -LiteralPath $source -Filter $file -Depth 0 -Force -File -ErrorAction Continue | Remove-Item -Force -ErrorAction Continue
	$Subs = @()
	$Subs += Get-ChildItem -Directory -Depth 0 -LiteralPath $source -ErrorAction Continue | Where-Object Name -ne "script" | Where-Object Name -Ne "backup"
	If ($Subs.Count -gt 0)
	{
		$Subs | ForEach-Object {
			$NewSub = $_.Name
			$FilesCount = @()
			$DirsCount = @()
			If ($NewSub -notlike "win32*")
			{
				"Counting Files..."
				$FilesCount += Get-ChildItem -LiteralPath $_.FullName -Force -File -ErrorAction Continue | Where-Object BaseName -NotLike "*.pat"
				"Counting Folders..."
				$DirsCount += Get-ChildItem -LiteralPath $_.FullName -Force -Directory -ErrorAction Continue
				"Digging into $($_.FullName) Folder"
				"	$($FilesCount.Count) Files"
				"	$($DirsCount.Count) Directories"
			}
			$Details = $false
			If ($NewSub -like "win32*")
			{
				(0..0xf|% ToString X1) | ForEach-Object {
					""
					"WARNING: a folder that MAY have a large number of files detected, only moving files starting with $($_) of (0123456789ABCDEF)"
					""
					RobomoveByFolder -source (Join-Path $source -ChildPath $NewSub) -destination (Join-Path $destination -ChildPath $NewSub) -file ('{0}*.*' -f $_)  -Details $true -logfile $logpath.Path
				}
			}
			ElseIf ($FilesCount.Count -gt 100)
			{
				""
				""
				""
				""
				""
				"WARNING: large number of files detected - this may take a while, maybe even A LONG TIME! Please wait!"
				"WARNING: large number of files detected - this may take a while, maybe even A LONG TIME! Please wait!"
				"WARNING: large number of files detected - this may take a while, maybe even A LONG TIME! Please wait!"
				"WARNING: large number of files detected - this may take a while, maybe even A LONG TIME! Please wait!"
				"WARNING: large number of files detected - this may take a while, maybe even A LONG TIME! Please wait!"
				""
				RobomoveByFolder -source (Join-Path $source -ChildPath $NewSub) -destination (Join-Path $destination -ChildPath $NewSub) -Details $true -logfile $logpath.Path
			}
			else
			{
				RobomoveByFolder -source (Join-Path $source -ChildPath $NewSub) -destination (Join-Path $destination -ChildPath $NewSub) -Details $false -logfile $logpath.Path
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
	$takeownEXE = "C:\Windows\system32\takeown.exe"
	If (Test-Path -LiteralPath $takeownEXE)
	{
		"Reseting ACL of $($path)"
		Start-Process -Wait -FilePath $takeownEXE -ArgumentList "/R","/A","/F",('"{0}"' -f $path) -ErrorAction Continue -WindowStyle Normal
		#we can not use"/D Y" only work on English, we need to ask the user in a non-Powershell window
	}
	Else
	{
		"WARNING: Takeown.exe is missing from your system32 folder!"
	}
}

Function PauseAndFail {
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory=$true)]
		[Int]
		$ErrorLevel = 255,
		[Parameter(Mandatory=$true, ValueFromPipeline=$true)]
		[String]
		$ErrorMessage = "Click OK to fail hard."
	)
	$ErrorMessage
	Stop-Transcript
	Set-ConsoleQuickEdit -Mode $true
	If ($PauseOnFail = $false)
	{
		exit $ErrorLevel
	}
	ElseIf (Test-Path variable:global:psISE -or $true)
	{
		$ObjShell = New-Object -ComObject "WScript.Shell"
		$Button = $ObjShell.Popup($ErrorMessage, 0, "Script failing", 0)
		exit $ErrorLevel
	}
	Else
	{
		""
		"Press any key to exit."
		$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
		exit $ErrorLevel
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
	$PauseMessage
	If ((Test-Path variable:global:psISE) -eq $true -or $true)
	{
		$ObjShell = New-Object -ComObject "WScript.Shell"
		$Button = $ObjShell.Popup($PauseMessage, 0, "Script pausing", 0)
	}
	Else
	{
		""
		"Press any key to continue."
		$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	}
}

Function Window10Version
{
	Param
	(
		
		[Parameter(Mandatory=$true)]
		[Int]
		$Build = 0
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
	$OnlineVolules += Get-AppxVolume -Online -Verbose
} catch {}
	If ($OnlineVolules.Count -gt 0)
	{
		$MutableVolumes += $OnlineVolules | ForEach-Object {
			$ModifiableFolder = Join-Path -Path $_.PackageStorePath -ChildPath "..\WindowsModifiableApps"
			If (Test-Path -LiteralPath $ModifiableFolder -PathType Container)
			{
				$_
			}
		}
	}
	If ($MutableVolumes.Count -gt 0)
	{
		$PackageFolders += $MutableVolumes | ForEach-Object {
			$MutableFolder = Join-Path -Path $_.PackageStorePath -ChildPath "..\WindowsModifiableApps\$($Folder)"
			If (Test-Path -LiteralPath $MutableFolder -PathType Container)
			{
				Return Resolve-Path -LiteralPath $MutableFolder
			}
		}
	}
	If (Test-Path -LiteralPath "C:\Program Files\WindowsModifiableApps\$($Folder)" -PathType Container)
	{
		$PackageFolders +=  Resolve-Path -LiteralPath "C:\Program Files\WindowsModifiableApps\$($Folder)"
	}
	If ($PackageFolders.Count -gt 0)
	{
		Return $PackageFolders.ProvidePath
	}
}

Function Set-ConsoleQuickEdit
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
	$OldMode = Get-ConsoleQuickEdit
	Set-ItemProperty -LiteralPath $RegistryKeyPath -Name "QuickEdit" -Value $Mode -Type DWord -ErrorAction SilentlyContinue
	Return $oldMode
}

Function Get-ConsoleQuickEdit
{
	$RegistryKeyPath = "HKCU:\Console\%SystemRoot%_System32_WindowsPowerShell_v1.0_powershell.exe"
	If (-Not (Test-Path -LiteralPath $RegistryKeyPath -PathType Container))
	{
		Return $null
	}
	$RegData = $null
	$RegData = Get-ItemProperty -LiteralPath $RegistryKeyPath -Name "QuickEdit" -ErrorAction SilentlyContinue
	If ($RegData -ne $Null)
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

If (-Not (Test-Path -Path "PSO2 Tweaker.exe" -PathType Leaf))
{
	"The PowerScript NOW need to be placed in the Tweaker folder to be able to read the UpdateEngine JSON files" | PauseAndFail -ErrorLevel 31
}

Set-ConsoleQuickEdit -Mode $false | Out-Null

If ($TweakerMode -eq $true)
{
	$PauseOnFail = $false
	$SkipRobomove = $true
	$ForceLocalInstall = $true
	$SkipStorageCheck = $trie
}

#Start-Service -Name "Winmgmt" -ErrorAction Stop

Write-Host -NoNewline "Checking Windows version..."
$WinVer = [Version](Get-CimInstance Win32_OperatingSystem).version
if ($WinVer.Major -lt 10)
{
	""
	"Reported Windows Major version $($WinVer.Major)"
	"ERROR: PSO2NA is only supported on Windows 10." | PauseAndFail -ErrorLevel 1
}
Elseif ($WinVer.Minor -gt 0) {}
ElseIf ($WinVer.Build -lt 18362)
{
	""
	"Reported Windows Build $($WinVer.Build), Verion $(Window10Version -Build $WinVer.Build)"
	"ERROR: PSO2NA is only supported on Windows 10 Version 1903 or higher. You need to upgrade Windows to a newer build/version." |	PauseAndFail -ErrorLevel 2
}
Elseif ([System.Environment]::Is64BitOperatingSystem -eq $false)
{
	""
	"PSO2NA is only supported on 64-bit OS. You need to reinstall your Windows OS if your CPU is 64-bit." | PauseAndFail -ErrorLevel 21
}
"[OK]"
""
""
""
""

Write-Host -NoNewline "Checking for Administrator Role..."
# Get the ID and security principal of the current user account
$myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal=New-Object System.Security.Principal.WindowsPrincipal($myWindowsID)
# Get the security principal for the Administrator role
$adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
if (-Not $myWindowsPrincipal.IsInRole($adminRole))
{
	""
	"WARNING: You need to run this PowerShell script using an Administrator account (or with an admin powershell)."
	Stop-Transcript
	Start-Process -FilePath "powershell.exe" -ArgumentList "-NoLogo","-NoProfile","-ExecutionPolicy","ByPass","-File",('"{0}"' -f $MyInvocation.MyCommand.Path) -Verb RunAs -WindowStyle Maximized
	exit
	#PauseAndFail -ErrorLevel 3
}
"[OK]"
""
""
""
""

"Report Windows Verion"
$WinVer | fl
"Getting Windows Patch list"
$WinPatchs = @()
$WinPatchs = Get-Hotfix -Verbose -ErrorAction Continue
$WinPatchs
If ($WinPatchs.HotFixID -contains "KB4560960" -and $false)
{
	""
	"KB4560960 patch is installed, it may cause issues with PSO2"
	"You may want to uninstall it"
	PauseOnly
}

"Getting Software list..."
"Please note: if you have any broken MSI installtions, you may get errors"
$MSIList = @()
$MSIList_Bad = @()
$MSIList += Get-CimInstance -ClassName Win32_Product
"[OK]"
$MSIList_Bad += $MSIList | Where-Object Name -Like "Nahimic*"
If ($MSIList_Bad.Count -gt 0)
{
	"Found Bad software:"
	$MSIList_Bad | select -Property Vendor, Name, Caption, Description, IdentifyingNumber, PackageName
	#PauseOnly
}

If ("{FD585866-680F-4FE0-8082-731D715F90CE}" -In $MSIList_Bad.IdentifyingNumber) #(Test-Path -LiteralPath "C:\Program Files\Nahimic\Nahimic2\UserInterface\x64\Nahimic2DevProps.dll" -PathType Leaf)
{
	"WARNING: Nahimic2 software detected, it is known to crash PSO2, We will uninstall it"
	$MSILog = Join-Path -Path $PSScriptRoot -ChildPath "Nahimic2.log"
	Start-Process -Wait -FilePath "MsiExec.exe" -ArgumentList "/x","{FD585866-680F-4FE0-8082-731D715F90CE}","/l*vx",('"{0}"' -f $MSILog),"/qf"
}

If ("{85D06868-AE2D-4B82-A4B1-913A757F0A32}" -In $MSIList_Bad.IdentifyingNumber) #(Test-Path -LiteralPath "C:\Program Files\Alienware\AWSoundCenter\UserInterface\x64\AWSoundCenterDevProps.dll" -PathType Leaf)
{
	"WARNING: AWSoundCenter software detected, it is known to crash PSO2, We will uninstall it"
	$MSILog = Join-Path -Path $PSScriptRoot -ChildPath "AWSoundCenter.log"
	Start-Process -Wait -FilePath "MsiExec.exe" -ArgumentList "/x","{85D06868-AE2D-4B82-A4B1-913A757F0A32}","/l*vx",('"{0}"' -f $MSILog),"/qf"
}

If ("{D88C71FC-FB81-49E0-9661-41ADDC02E4FD}" -In $MSIList_Bad.IdentifyingNumber)
{
	"WARNING: Nahimic Settings Configurator software detected, it is known to crash PSO2, We will uninstall it"
	$MSILog = Join-Path -Path $PSScriptRoot -ChildPath "Nahimic.log"
	Start-Process -Wait -FilePath "MsiExec.exe" -ArgumentList "/x","{D88C71FC-FB81-49E0-9661-41ADDC02E4FD}","/l*vx",('"{0}"' -f $MSILog),"/qf"
}

"Getting list of PNP devices"
$PNPDevices = @()
$PNPDevices += Get-WmiObject Win32_PNPEntity
"Getting list of Windows Drivers"
$Drivers = @()
$Drivers += Get-WindowsDriver -Online
$PNPDevices_AVOL = @()
$PNPDevices_AVOL += $PNPDevices | Where-Object HardwareID -Contains "SWC\VEN_AVOL&AID_0001"
$Drivers_AVOL = @()
$Drivers_AVOL += $Drivers | Where-Object ProviderName -eq "A-Volute"
If ($PNPDevices_AVOL.Count -gt 0)
{
	"WARNING: Found bad A-Volute software components drivers , We are going to remove them to stop PSO2 from crashing" | PauseOnly
	Get-Service | Where-Object Name -eq "NahimicService" | Stop-Service
	If ($Drivers_AVOL.Count -gt 0)
	{
		$Drivers_AVOL | ForEach-Object {
			Start-Process -Wait -FilePath "pnputil.exe" -ArgumentList  "/delete-driver",$_.Driver,"/uninstall","/force"
		}
	}
}

"Checking MS Store Setup"
Set-Service -Name "wuauserv" -StartupType Manual -ErrorAction Continue
#Set-Service -Name "BITS" -StartupType AutomaticDelayedStart -ErrorAction Continue
Set-Service -Name "StorSvc" -StartupType Manual -ErrorAction Continue
Get-Service -Name "wuauserv","BITS","StorSvc" | Where-Object Statis -NE "Running" | Start-Service -ErrorAction Continue -Verbose

"Restarting XBOX services..."
Get-Service -Name "XblGameSave","XblAuthManager","XboxNetApiSvc" | Restart-Service -Force -Verbose
"Killing any XBOX process"
Get-Process -IncludeUserName | Where-Object UserName -eq ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) | Where-Object Name -like "*xbox*" | Stop-Process -Force -ErrorAction Continue

$SystemVolume = Get-AppxVolume | Where-Object -Property IsSystemVolume -eq $true

"Checking for NET Framework 2.2 (2.2.27912.0+)"
$NETFramework = @()
$NETFramework_version = [Version]"2.2.27912.0"
$NETFramework += Get-AppxPackage -Name "Microsoft.NET.Native.Framework.2.2" -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" -PackageTypeFilter Framework | PackageVersion -Version $NETFramework_version
If ($NETFramework.Count -eq 0)
{
	"	NOT INSTALLED"
}
Else
{
	"	INSTALLED"
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
	"XBOX Identify Provider not installed to the user account, forcing install..."
	$XBOXIP_All | Where-Object InstallLocation -ne $null |  Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -Verbose}
}
ElseIf ($XBOXIP_All.Count -eq 0 -and ($NETFramework.Count -gt 0 -or $true) -and $ForceLocalInstall -eq $true)
{
	"Downloading XBOX Identify Provider App... (13MB)"
	$URI = "https://github.com/Arks-Layer/PSO2WinstoreFix/raw/master/appx/Microsoft.XboxIdentityProvider_12.64.28001.0_neutral___8wekyb3d8bbwe.AppxBundle"
	$FileD = "Microsoft.XboxIdentityProvider_12.64.28001.0_neutral_~_8wekyb3d8bbwe.appxbundle"
	$Download = $URI | DownloadMe -OutFile $FileD -ErrorLevel 30

	"Installing XBOX Identify Provider app..."
	Try {
		$Download | Add-AppxPackage -Volume $SystemVolume -Verbose -ForceApplicationShutdown -ForceUpdateFromAnyVersion
	}
	Catch {}
}

$XBOXIP = Get-AppxPackage -Name "Microsoft.XboxIdentityProvider" -PackageTypeFilter Main -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" -Verbose

If ($XBOXIP -ne $null)
{
	"Looking for the XBOX Identify Provider folder to wipe..."
	$PackageF = Join-Path -Path $env:LOCALAPPDATA -ChildPath "Packages" -Verbose
	$XBOXIPFN = $XBOXIP.PackageFamilyName
	$XBOXIPF = Join-Path -Path $PackageF -ChildPath $XBOXIPFN  -Verbose
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
	""
	"ERROR: Look like XBOX Identify Provider has been uninstalled. Please use the Windows Store to get it back." | PauseAndFail -ErrorLevel 27
}

"Checking for needed Gaming Services App runtime..."
$GamingServices_User = @()
$GamingServices_Any = @()
$GamingServices_All = @()
$GamingServices_version = [Version]"2.42.5001.0"
$GamingServices_User += Get-AppxPackage -Name "Microsoft.GamingServices" -PackageTypeFilter Main -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" | PackageVersion -Version $GamingServices_version
$GamingServices_Any += Get-AppxPackage -Name "Microsoft.GamingServices" -PackageTypeFilter Main -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" -AllUsers
$GamingServices_All += $GamingServices_Any | PackageVersion -Version $GamingServices_version

$GamingSrv = @()
$GamingSrv += Get-Service | Where-Object Name -In "GamingServices"
$GamingSrv_STOP = @()
$GamingSrv_STOP += $GamingSrv | Where-Object Status -NE "Running"
$GamingNetSrv = @()
$GamingNetSrv += Get-Service | Where-Object Name -In "GamingServicesNet"
$Drivers_XBOX = $Drivers | Where-Object ProviderName -eq "Xbox"

If ($GamingSrv_STOP.Count -gt 0)
{
	"GamingServices is not running, going to remove the XBOX drivers"
	If ($Drivers_XBOXL.Count -gt 0)
	{
		$Drivers_XBOX | ForEach-Object {
			Start-Process -Wait -FilePath "pnputil.exe" -ArgumentList  "/delete-driver",$_.Driver,"/uninstall","/force"
		}
	}
}

Try
{
	$ForceReinstallGS = $true
	"Checking if we can get the Gaming Services working..."
	$GamingNetSrv | Where-Object Status -NE "Running" | Restart-Service
	$GamingSrv | Where-Object Status -NE "Running" | Restart-Service
	"No errors found! :D"
	$ForceReinstallGS = $false
}
Catch
{
	"There was an issue checking the Gaming Services, we will try to reinstall the app..."
}

If ($GamingServices_All.Count -eq 0 -and $GamingServices_Any.Count -gt 0)
{
	""
	"WARING: Old version of Gaming Services found!"
	""
	[Diagnostics.Process]::Start("ms-windows-store://pdp?productid=9mwpm2cqnlhn")
	"	Please udpate Gaming Services from the MS Store." | PauseOnly
}
ElseIf ($ForceReinstallGS -eq $true -and $GamingServices_All.Count -gt 0)
{
	"Removing Gaming Services app..."
	Get-Service -Name "GamingServices","GamingServicesNet" -ErrorAction Continue | Stop-Service -ErrorAction Continue
	$GamingServices_Any | Remove-AppxPackage -Verbose -PreserveApplicationData:$false
	$GamingServices_Any | Remove-AppxPackage -AllUsers -Verbose
	""
	Start-Sleep -Seconds 30
	Restart-Computer -Verbose
	"ERROR: Gaming Services has been removed, a reboot will be needed to reinstall it" | PauseAndFail -ErrorLevel 24
}
ElseIf ($GamingServices_All.Count -gt 0 -and $GamingServices_User.Count -eq 0)
{
	"Installing Gaming Services to user account..."
	$GamingServices_All | Where-Object InstallLocation -ne $null |  Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -Verbose -ForceApplicationShutdown}
}
ElseIf ($GamingServices_All.Count -eq 0 -and ($NETFramework.Count -gt 0 -or $true) -and $ForceLocalInstall -eq $true)
{
	"Downloading Gaming Services App... (10MB)"
	$URI = "https://github.com/Arks-Layer/PSO2WinstoreFix/raw/master/appx/Microsoft.GamingServices_2.42.5001.0_neutral___8wekyb3d8bbwe.AppxBundle"
	$FileD = "Microsoft.GamingServices_2.42.5001.0_neutral_~_8wekyb3d8bbwe.appxbundle"
	$Download = $URI | DownloadMe -OutFile $FileD -ErrorLevel 18

	"Removing Gaming Services app..."
	$GamingServices_Any | Remove-AppxPackage -PreserveApplicationData:$false -Verbose
	$GamingServices_Any | Remove-AppxPackage -AllUsers -Verbose

	"Installing Gaming Services app..."
	Try {
		$BadInstall = $true
		$Download | Add-AppxPackage -Volume $SystemVolume -Verbose -ForceApplicationShutdown -ForceUpdateFromAnyVersion
		$BadInstall = $false
		$ForceReinstallGS = $true
	}
	Catch {}
	$GamingServices_Any = @()
	$GamingServices_Any += Get-AppxPackage -Name "Microsoft.GamingServices" -PackageTypeFilter Main -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" -AllUsers | PackageVersion -Version $GamingServices_version
	If ($BadInstall -eq $false -and $GamingServices_Any.Count -gt 0)
	{
		""
		Start-Sleep -Seconds 30
		Restart-Computer -Verbose
		"ERROR: Gaming Services installed, please reboot." | PauseAndFail -ErrorLevel 25
		#Resolve-Path -LiteralPath $FileD | Remove-Item -Verbose
	}
}

If ($GamingServices_Any.Count -eq 0 -or $ForceReinstallGS -eq $true)
{
	""
	"Starting MS Store App with the Gaming Service Listing..."
	[Diagnostics.Process]::Start("ms-windows-store://pdp?productid=9mwpm2cqnlhn")
	"ERROR: Please make sure to install the Gaming Services from the MS Store." | PauseAndFail -ErrorLevel 26
}

""
"Status of GamingService App"
Get-AppxPackage -Name "Microsoft.GamingServices" -PackageTypeFilter Main -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" -AllUsers
"End of Status Report"

"Finding GameGuard Service..."
$npggsvc = @()
$npggsvc += Get-Service | Where-Object Name -eq "npggsvc"
If ($npggsvc.Count -gt 0)
{
	"Found GameGuard Service..."
	"Trying to stop it..."
	Try
	{
		$BrokenGG = $true
		$npggsvc | Where-Object Statis -EQ "Running" | Stop-Service -ErrorAction Continue -PassThru | Set-Service -StartupType Manual
		$BrokenGG = $false
	}
	Catch {}
	$npggsvcK = "HKLM:SYSTEM\CurrentControlSet\Services\npggsvc"
	If (-Not (Test-Path -LiteralPath $npggsvcK))
	{
		$BrokenGG = $true
	}
	
	If ($BrokenGG)
	{
		#Delete-Service do not exist in Power-Shell 5.1
		Start-Process -Wait -FilePath "C:\Windows\system32\cmd.exe" -ArgumentList "/C","C:\Windows\system32\sc.exe","delete","npggsvc" -WindowStyle Minimized
	}
}

"Checking PSO2 Tweaker settings..."
$JSONPath = $null
$JSONData = $null
$PSO2NABinFolder = $null
$PSO2NAFolder = $null
$JSONPath = [System.Environment]::ExpandEnvironmentVariables("%APPDATA%\PSO2 Tweaker\settings.json")
If ($JSONPath)
{
	"Loading Tweaker Config from $($JSONPath)"
	$JSONData = Get-Content -LiteralPath $JSONPath -Verbose
}
Else
{
	""
	"ERROR: Cannot find %APPDATA% folder - Is your Windows properly set up?" | PauseAndFail -ErrorLevel 5
}
If ($JSONData)
{
	$JSONObj = $JSONData | ConvertFrom-Json -Verbose
	"Tweaker Settings for logging:"
	$JSONObj
}
Else
{
	""
	"ERROR: Cannot read Tweaker Setting JSON - Did you set up the Tweaker yet?" | PauseAndFail -ErrorLevel 6
}
If ($JSONObj)
{
	$PSO2NABinFolder = ""
	try {
		$PSO2NABinFolder = $JSONObj | Select-Object -ExpandProperty PSO2NABinFolder
	}
	catch {}
}
Else
{
	""
	"ERROR: Can not convert JSON into PowerShell Object. This shouldn't happen!" | PauseAndFail -ErrorLevel 7
}
If ($PSO2NABinFolder -eq "")
{
	""
	"ERROR: Old version of the Tweaker config file found, please update Tweaker."| PauseAndFail -ErrorLevel 20
}
ElseIF ($PSO2NABinFolder -contains "[" -or $PSO2NABinFolder -contains "]")
{
	""
	"ERROR: The $($PSO2NABinFolder) folder have { or ], PowerShell have issues with folder name." | PauseAndFail -ErrorLevel 28
}
ElseIf ($PSO2NABinFolder -eq $null)
{
	""
	"ERROR: Tweaker NA Setup is not done, please tell me where to install PSO2NA." | PauseAndFail -ErrorLevel 20
}
ElseIf (-Not (Test-Path -LiteralPath "$($PSO2NABinFolder)" -PathType Container))
{
	""
	"ERROR: The $($PSO2NABinFolder) folder does not exist. Please check your PSO2 Tweaker settings." | PauseAndFail -ErrorLevel 16
}
ElseIf ($PSO2NABinFolder)
{
	$PSO2NAFolder = $PSO2NABinFolder | Split-Path
}
Else
{
	""
	"ERROR: Cannot find a PSO2NABinFolder setting - Did you set up PSO2NA through the Tweaker yet? If not, do it." | PauseAndFail -ErrorLevel 8
}
If (-Not (Test-Path -LiteralPath $PSO2NAFolder -PathType Container))
{
	""
	"ERROR: The $($PSO2NAFolder) folder does not exist. Please check your PSO2 Tweaker settings." | PauseAndFail -ErrorLevel 17
}
ElseIf ($PSO2NAFolder)
{
	$LeafPath = $PSO2NAFolder | Split-Path -Leaf
	If ($LeafPath -eq "ModifiableWindowsApps")
	{
		""
		"ERROR: You cannot use the Windows Store copy of PSO2 with this script. Go back to http://na.arks-layer.com/setup.html and do a fresh install."
		""
		"WARNING: If you just wanted to fix your XBOX login issue, you should be fine now."
		"No more work for broken MS Store copy" | PauseAndFail -ErrorLevel 10
	}
	#"Moving instance to $($PSO2NAFolder) Folder..."
	#Set-Location -LiteralPath $PSO2NAFolder -Verbose
}
Else
{
	""
	"ERROR: Cannot get PSO2NA Folder - Did you follow the instructions?" | PauseAndFail -ErrorLevel 9
}

"Get Storage Service Ready"
Restart-Service -Name "StorSvc"

"Report of Drive status"
If ($SkipStorageCheck -ne $true)
{
	Get-Volume | Where-Object DriveLetter -NE $null | Where-Object DriveType -NE "CD-ROM" | Select -Property DriveLetter, DriveType, FileSystem, FileSystemLabel, HealthStatus, OperationalStatus, Path
}
"End of Report"
"Checking if Volume is formated as NTFS..."
$PSO2Vol = @()
Try
{
	$BrokenVolume = $true
	If ($SkipStorageCheck -ne $true)
	{
		$PSO2Vol += Get-Volume -FilePath $PSO2NAFolder
	}
	$BrokenVolume = $false
}
Catch
{
	#PauseAndFail -ErrorLevel 19
}
$PSO2Vol_exFAT = @()
$PSO2Vol_NTFS = @()
$PSO2Vol_ReFS = @()
$PSO2Vol_exFAT +=  $PSO2Vol | Where-Object -Property FileSystemType -EQ exFAT
$PSO2Vol_NTFS +=  $PSO2Vol | Where-Object -Property FileSystemType -EQ NTFS
$PSO2Vol_ReFS +=  $PSO2Vol | Where-Object -Property FileSystemType -EQ ReFS

If ($BrokenVolume -eq $true)
{
	""
	"WARNING: Your system's WMI database is broken, please repair it."
}
ElseIf ($PSO2Vol_exFAT.Count -gt 0)
{
	""
	"WARNING: Your PSO2NA installation on an exFAT formatted drive, please move the PSO2NA installation elsewhere." | PauseAndFail -ErrorLevel 15
}
ElseIf ($PSO2Vol_ReFS.Count -gt 0)
{
	""
	"WARNING: Your PSO2NA installation on an ReFS formatted drive, please move the PSO2NA installation elsewhere." | PauseAndFail -ErrorLevel 15
}

If ($PSO2Vol_NTFS.Count -gt 0)
{
	"Your PSO2NA installation is on a NTFS drive \o/"
}
ElseIF ($PSO2Vol.Count -gt 0)
{
	"WARNING: Your PSO2NA installtion in on an unknown filesytem: $($PSO2Vol.FileSystem -join ",")?" | PauseOnly
}
Else
{
	PauseOnly
}

$MissingFiles = $false
"Checking for appxmanifest.xml..."
If (-Not (Join-Path -Path $PSO2NAFolder -ChildPath "appxmanifest.xml" | Test-Path -PathType Leaf))
{
	$MissingFiles = $true
	"	MISSING"
}
else
{
	"	FOUND"
	$XMLPath = (Join-Path -Path $PSO2NAFolder -ChildPath "appxmanifest.xml")
	[xml]$XMLContent = Get-Content -LiteralPath $XMLPath -Verbose
	If ($XMLContent.Package.Extension -ne $null)
	{
		"	BUT it is the MS Store copy, not Custom one"
		Remove-Item -LiteralPath $XMLPath -Force -Verbose
		$MissingFiles = $true
	}
}
"Checking for MicrosoftGame.config..."
If (-Not (Join-Path -Path $PSO2NAFolder -ChildPath "MicrosoftGame.config" | Test-Path -PathType Leaf))
{
	$MissingFiles = $true
	"	MISSING"
}
else
{
	"	FOUND"
}
"Checking for pso2_bin/pso2.exe file..."
If (-Not (Join-Path -Path $PSO2NABinFolder -ChildPath "pso2.exe" | Test-Path -PathType Leaf))
{
	$MissingFiles = $true
	"	MISSING"
}
else
{
	"	FOUND"
}
"Checking for pso2_bin/Logo.png file..."
If (-Not (Join-Path -Path $PSO2NABinFolder -ChildPath "Logo.png" | Test-Path -PathType Leaf))
{
	$MissingFiles = $true
	"	MISSING"
}
else
{
	"	FOUND"
}
"Checking for pso2_bin/SmallLogo.png file..."
If (-Not (Join-Path -Path $PSO2NABinFolder -ChildPath "SmallLogo.png" | Test-Path -PathType Leaf))
{
	$MissingFiles = $true
	"	MISSING"
}
else
{
	"	FOUND"
}
"Checking for pso2_bin/SplashScreen.png file..."
If (-Not (Join-Path -Path $PSO2NABinFolder -ChildPath "SplashScreen.png" | Test-Path -PathType Leaf))
{
	$MissingFiles = $true
	"	MISSING"
}
else
{
	"	FOUND"
}
If ($MissingFiles -eq $true)
{
	"Downloading Starter files... (3 MB)"
	$URI = "https://github.com/Arks-Layer/PSO2WinstoreFix/raw/master/pso2_bin_na_starter.zip"
	$FileD = "pso2_bin_na_starter.zip"
	$MISSING = $URI | DownloadMe -OutFile $FileD -ErrorLevel 11
	$TMPFolder = New-Item -Path "UNPACK" -ItemType Directory -Verbose -Force
	$TMPBinFolder = New-Item -Path "UNPACK\pso2_bin" -ItemType Directory -Verbose -Force
	Expand-Archive -LiteralPath $MISSING -DestinationPath $TMPFolder -Force
	Get-ChildItem -LiteralPath $TMPFolder -File | ForEach-Object {
		$OldFile = Join-Path -Path $PSO2NAFolder -ChildPath $_.Name
		If (-Not (Test-Path -LiteralPath $OldFile -PathType Leaf))
		{
			Copy-Item -LiteralPath $_.FullName -Destination $OldFile
		}
	}
	Get-ChildItem -LiteralPath $TMPBinFolder -File | ForEach-Object {
		$OldFile = Join-Path -Path $PSO2NABinFolder -ChildPath $_.Name
		If (-Not (Test-Path -LiteralPath $OldFile -PathType Leaf))
		{
			Copy-Item -LiteralPath $_.FullName -Destination $OldFile
		}
	}
	Remove-Item -LiteralPath $TMPFolder -Recurse -Force -Confirm:$false
}

Write-Host -NoNewline "Checking for Developer Mode..."
$DevMode = $false
$RegistryKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock"
if (Test-Path -LiteralPath $RegistryKeyPath)
{
	$AppModelUnlock = Get-ItemProperty -LiteralPath $RegistryKeyPath
	if ($AppModelUnlock -ne $null -and ($AppModelUnlock | Get-Member -Name AllowDevelopmentWithoutDevLicense) -ne $null)
	{
		$RegData = $AppModelUnlock | Select -ExpandProperty AllowDevelopmentWithoutDevLicense
		If ($RegData -eq 1)
		{
			$DevMode = $true
		}
	}
}
If ($DevMode -EQ $false)
{
	Write-Host -Object "You need to enable Developer mode. Please see https://www.howtogeek.com/292914/what-is-developer-mode-in-windows-10/" -ForegroundColor Red
	"Developer mode is disabled" | PauseAndFail -ErrorLevel 4
}
"[OK]"

$NAFiles = @()
If (Test-Path "client_na.json" -PathType Leaf)
{
	"Reading Tweaker's UpdateEngine for PSO2NA"
	$NAState = Get-Content -Path "client_na.json" -Force -Encoding UTF8 -Verbose | ConvertFrom-Json -Verbose
	"Getting list of data files to exclude"
	$NAFiles += ($NAState | Get-Member -MemberType NoteProperty).Name
}

If ($NAFiles.Count -eq 0)
{
    $NAFiles += "version.ver"
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
If ($OldPackages.Count -gt 0)
{
	"Found MS Store copy of PSO2NA, this may take a while" | PauseOnly
}

If ($OldBackups.Count -gt 0)
{
	"Found some MutableBackup folders!"
	$OldBackups | fl
	$OldBackups | ForEach-Object -Process {
		$OldBin = $_
		Takeownship -path $OldBin
		"Removing $($NAFiles.Count) unneeded files..."
		$NAFiles | Join-Paths -Path $OldBin | Remove-Item -Force -ErrorAction SilentlyContinue
		"Going to move the old MS STORE backup files from $($OldBin) to your Tweaker copy of PSO2..."
		RobomoveByFolder -source $OldBin -destination $PSO2NABinFolder
		"Deleting old $($OldBin) folder..."
try {
		"Deleting files in $($OldBin) Folder..."
		Get-ChildItem -LiteralPath $OldBin -ErrorAction Continue -File -Recurse | Remove-Item -Force -Confirm:$false -ErrorAction SilentlyContinue
} Catch {}
try {
		"Deleting subfolders in $($OldBin) Folder..."
		Get-ChildItem -LiteralPath $OldBin -ErrorAction Continue -Directory | Remove-Item -Recurse -Force -Confirm:$false -Verbose -ErrorAction SilentlyContinue
} Catch {}
try {
		"Deleting $($OldBin) Folder..."
		Remove-Item -LiteralPath $OldBin -Recurse -Force -Confirm:$false -Verbose -ErrorAction SilentlyContinue
} Catch {}
	}
	$JSONObj.PSO2NARemoteVersion = 0
	$JSONObj | ConvertTo-Json | Out-File -FilePath $JSONPath
}

If ($MWA.Count -gt 0)
{
	$MWA | ForEach-Object -Process {
		$OldBin = $_
		"Found the old MS STORE's pso2_bin patch folder!"
		Takeownship -path $OldBin
		"Removing $($NAFiles.Count) unneeded files..."
		$NAFiles | Join-Paths -Path $OldBin | Remove-Item -Force -ErrorAction SilentlyContinue
		"Going to move the MS STORE patch files to your Tweaker copy of PSO2..."
		RobomoveByFolder -source $OldBin -destination $PSO2NABinFolder
		"Deleting old MS STORE's pso2_bin patch folder..."
try {
		"Deleting files in $($OldBin) Folder..."
		Get-ChildItem -LiteralPath $OldBin -ErrorAction Continue -File -Recurse | Remove-Item -Force -Confirm:$false -ErrorAction SilentlyContinue
} Catch {}
try {
		"Deleting subfolders in $($OldBin) Folder..."
		Get-ChildItem -LiteralPath $OldBin -ErrorAction Continue -Directory | Remove-Item -Recurse -Force -Confirm:$false -Verbose -ErrorAction SilentlyContinue
} Catch {}
try {
		"Deleting $($OldBin) Folder..."
		Remove-Item -LiteralPath $OldBin -Recurse -Force -Confirm:$false -Verbose -ErrorAction SilentlyContinue
} Catch {}
	}
	$JSONObj.PSO2NARemoteVersion = 0
	$JSONObj | ConvertTo-Json | Out-File -FilePath $JSONPath
}


If ($OldPackages.Count -gt 0)
{
	$OldPackages | Where-Object InstallLocation -ne $null | ForEach-Object -Process {
		$OldBin = $_
		"Found the old MS STORE's pso2_bin core's data folder!"
		Takeownship -path $OldBin
		"Removing $($NAFiles.Count) unneeded files..."
		$NAFiles | Join-Paths -Path $OldBin | Remove-Item -Force -ErrorAction SilentlyContinue
		"Going to move the MS STORE core's data files to your Tweaker copy of PSO2..."
		RobomoveByFolder -source $OldBin -destination $PSO2NABinFolder
		"Deleting old MS STORE's pso2_bin core's date folder..."
try {
		"Deleting files in $($OldBin) Folder..."
		Get-ChildItem -LiteralPath $OldBin -ErrorAction Continue -File -Recurse | Remove-Item -Force -Confirm:$false -ErrorAction SilentlyContinue
} Catch {}
try {
		"Deleting subfolders in $($OldBin) Folder..."
		Get-ChildItem -LiteralPath $OldBin -ErrorAction Continue -Directory | Remove-Item -Recurse -Force -Confirm:$false -Verbose -ErrorAction SilentlyContinue
} Catch {}
try {
		"Deleting $($OldBin) Folder..."
		Remove-Item -LiteralPath $OldBin -Recurse -Force -Confirm:$false -Verbose -ErrorAction SilentlyContinue
} Catch {}
	}
	"If this takes more then 30 minutes, you may have to reboot."
	"Unregistering the old PSO2 from the Windows Store... (This may take a while, don't panic!)"
	$OldPackages | Remove-AppxPackage -AllUsers -Verbose
	$JSONObj.PSO2NARemoteVersion = 0
	$JSONObj | ConvertTo-Json | Out-File -FilePath $JSONPath
}
Else
{
	"No Windows Store PSO2NA installation found. This is OK!"
}

"Checking if we need to install the requirements..."
$NewPackages = @()

$DirectXRuntime_All = @()
$DirectXRuntime_User = @()
$DirectXRuntime_version = [Version]"9.29.952.0"
$DirectXRuntime_All += Get-AppxPackage -Name "Microsoft.DirectXRuntime" -PackageTypeFilter Framework -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" -AllUsers | PackageVersion -Version $DirectXRuntime_version
$DirectXRuntime_User += Get-AppxPackage -Name "Microsoft.DirectXRuntime" -PackageTypeFilter Framework -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" | PackageVersion -Version $DirectXRuntime_version

$DirectXRuntime_User_Error = @()
$DirectXRuntime_User_Error += $DirectXRuntime_All.PackageUserInformation | Where-Object -FilterScript {$_.UserSecurityId.Sid -like $myWindowsID.User.Value} | Where-Object InstallState -ne "Installed"
$DirectXRuntime_All_Error = @()
$DirectXRuntime_All_Error += $DirectXRuntime_All.PackageUserInformation | Where-Object -FilterScript {$_.UserSecurityId.Sid -like "S-1-5-18"} | Where-Object InstallState -ne "Installed"

if ($DirectXRuntime_All.Count -gt 0 -and ($DirectXRuntime_User.Count -eq 0 -or $DirectXRuntime_User_Error.Count -gt 0) -and $DirectXRuntime_All_Error.Count -eq 0)
{
	"System already has a good copy of DirectX, trying to install the user profile..."
	$DirectXRuntime_All | Where-Object InstallLocation -ne $null | Sort-Object -Unique InstallLocation | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -Verbose}
	$DirectXRuntime_User += Get-AppxPackage -Name "Microsoft.DirectXRuntime" -PackageTypeFilter Framework -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" | PackageVersion -Version $DirectXRuntime_version
}

If ($DirectXRuntime_User.Count -eq 0 -or $DirectXRuntime_All_Error.Count -gt 0)
{
	"Downloading DirectX Runtime requirement... (56MB)"
	$URI = "https://download.microsoft.com/download/c/c/2/cc291a37-2ebd-4ac2-ba5f-4c9124733bf1/UAPSignedBinary_Microsoft.DirectX.x64.appx"
	$FileD = "UAPSignedBinary_Microsoft.DirectX.x64.appx"
	$NewPackages += $URI | DownloadMe -OutFile $FileD -ErrorLevel 12
}


$VCLibs_All = @()
$VCLibs_User = @()
$VCLibs_Version = [Version]"14.0.24217.0"
$VCLibs_All += Get-AppxPackage -Name "Microsoft.VCLibs.140.00.UWPDesktop" -PackageTypeFilter Framework -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" -AllUsers | PackageVersion -Version $VCLibs_Version
$VCLibs_User += Get-AppxPackage -Name "Microsoft.VCLibs.140.00.UWPDesktop" -PackageTypeFilter Framework -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" | PackageVersion -Version $VCLibs_Version

$VCLibs_User_Error = @()
$VCLibs_User_Error += $VCLibs_All.PackageUserInformation | Where-Object -FilterScript {$_.UserSecurityId.Sid -like $myWindowsID.User.Value} | Where-Object InstallState -ne "Installed" 
$VCLibs_All_Error = @()
$VCLibs_All_Error += $VCLibs_All.PackageUserInformation | Where-Object -FilterScript {$_.UserSecurityId.Sid -like "S-1-5-18"} | Where-Object InstallState -ne "Installed" 

If ($VCLibs_All.Count -gt 0 -And ($VCLibs_User.Count -eq 0 -or $VCLibs_User_Error.Count -gt 0) -and $VCLibs_All_Error.Count -eq 0)
{
	"System already has a good copy of VCLibs, trying to install the user profile"
	$VCLibsAll | Where-Object InstallLocation -ne $null | Sort-Object -Unique InstallLocation | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -Verbose}
	$VCLibs_User += Get-AppxPackage -Name "Microsoft.VCLibs.140.00.UWPDesktop" -PackageTypeFilter Framework -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" | PackageVersion -Version $VCLibs_Version
}

if ($VCLibs_User.Count -eq 0 -or $VCLibs_All_Error.Count -gt 0)
{
	"Downloading VCLibs requirement... (7MB)"
	$URI = "https://github.com/Arks-Layer/PSO2WinstoreFix/blob/master/appx/Microsoft.VCLibs.x64.14.00.Desktop.appx?raw=true"
	$FileD = "Microsoft.VCLibs.x64.14.00.Desktop.appx"
	$NewPackages += $URI | DownloadMe -OutFile $FileD -ErrorLevel 13
}

If ($NewPackages.Count -gt 0)
{
	"Installing requirements... If you see an error about it not being installed becuase of a higher version, that's OK!"
	$NewPackages | Add-AppxPackage -Stage -Volume $SystemVolume -Verbose -ErrorAction Continue
	$NewPackages | Add-AppxPackage -Volume $SystemVolume -Verbose -ErrorAction Continue
	#$NewPackages | Remove-Item -Verbose
}
Else
{
	"Requirements already installed"
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
$PSO2Packages += Get-AppxPackage -Name "100B7A24.oxyna" -AllUser | Where-Object -Property SignatureKind -EQ "None"
$PSO2Packages_User += Get-AppxPackage -Name "100B7A24.oxyna" | Where-Object -Property SignatureKind -EQ "None"
$PSO2Packages_Good += $PSO2Packages | Where-Object InstallLocation -eq $PSO2NAFolder | Where-Object Status -EQ "Ok"
$PSO2Packages_Bad += $PSO2Packages | Where-Object InstallLocation -ne $PSO2NAFolder
$PSO2Packages_Bad += $PSO2Packages | Where-Object Status -ne "Ok"
#$PSO2Packages_Bad += $PSO2Packages | PackageVersion -Version "1.0.7.0"

$XBOXURI = Test-Path -LiteralPath "Registry::HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\windows.protocol\ms-xbl-78a72674" -PathType Container
If ($XBOXURI -eq $false -or $PSO2Packages_User.Count -eq 0)
{
	$ForceReinstall = $true
}

If ($ForceReinstall)
{
	"Bad install found, forcing a PSO2 reinstall..."
	Get-AppxPackage -Name "100B7A24.oxyna" -AllUsers | Remove-AppxPackage -Verbose -AllUsers
}
ElseIf ($PSO2Packages_Bad.Count -gt 0)
{
	"Found a old custom PSO2 install:"
	$PSO2Packages_Bad
	"removing it..."
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
try {
Add-AppxVolume -Path ("{0}:" -f (Resolve-Path -LiteralPath $PSO2NAFolder).Drive.Name) -ErrorAction Continue
$Appxvols += Get-AppxVolume -Path ("{0}:" -f (Resolve-Path -LiteralPath $PSO2NAFolder).Drive.Name)
} catch {}
If ($AppxVols.Count -eq 0)
{
	"	TRAP"
}
ElseIf ($AppxVols.IsOffline -In $true)
{
	"	Custom PSO2 folder is on a drive with a broken Appx setup"
	#PauseAndFail -ErrorLevel 29
}
else
{
	"	OK"
}
""

If ($EmptyFiles.Count -gt 0)
{
	$JSONObj.PSO2NARemoteVersion = 0
	$JSONObj | ConvertTo-Json | Out-File -FilePath $JSONPath
	""
	"ERROR: Bad PSO2 files found, please run a full file check in Tweaker."
	"(Troubleshooting -> New Method)"
	#"List of bad files:"
	#$EmptyFiles | Format-Table Name
	$EmptyFiles | Remove-Item -Force -Verbose
	""
}

If ($PSO2Packages_Good.Count -eq 0 -or $ForceReinstall -eq $true) #Try
{
	$APPXXML = Join-Path -Path $PSO2NAFolder -ChildPath "appxmanifest.xml"
	"Registering our new shiny PSO2 with the Windows Store... (This may take a while, don't panic!)"
	If ($NewPackages.Count -gt 0 -and $false)
	{
		Add-AppxPackage -Register $APPXXML -Verbose -DependencyPath $PSO2NAFolder
	}
	Else
	{
		Add-AppxPackage -Register $APPXXML -Verbose -ErrorAction Continue
	}
	$JSONObj.PSO2NARemoteVersion = 0
	$JSONObj | ConvertTo-Json | Out-File -FilePath $JSONPath
}
Else
{
	"There is already a custom PSO2 install?"
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

"Now double checking the custom PSO2 install..."
$CustomPSO2 = @()
$CustomPSO2 += Get-AppxPackage -Name "100B7A24.oxyna" | Where-Object IsDevelopmentMode -eq $true | Where-Object Status -EQ "Ok"

"Raw PSO2 install status:"
Get-AppxPackage -Name "100B7A24.oxyna"
""
If ($CustomPSO2.Count -eq 0)
{
	 "Cannot find a custom PSO2 installation!"
}
ElseIf ($CustomPSO2.Count -eq 1)
{
	"Good, only found one custom PSO2 install." | PauseOnly
}
Else
{
	"What? why are there $($CustomPSO2) custom PSO2 install?!"
}
""
Stop-Transcript -ErrorAction Continue
Set-ConsoleQuickEdit -Mode $true
Write-Host -NoNewLine 'Script complete! You can now close this window by pressing any key.';
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
