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
}
Else
{
	$ScriptLog = Join-Path -Path "." -ChildPath "PSO2NA_PSLOG.log"
}

#Start logging
Start-Transcript -Path $ScriptLog
#Version number
"Version 2020_06_16_1446" # Error codes: 29

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
	$global:result = $Error.Exception.Response.GetResponseStream()
	$global:reader = New-Object System.IO.StreamReader($global:result)
	$global:responseBody = $global:reader.ReadToEnd();
	"Status: A system exception was caught."
	$global:responsebody
	Stop-Transcript
	$null = $global:Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
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
		$Overwrite = $false
	)
	Try
	{
		If (-Not (Test-Path -Path $OutFile -PathType Leaf) -Or $Overwrite)
		{
			Invoke-WebRequest -Uri $URI -OutFile $OutFile -UserAgent "Arks-Layer pso2_winstore_fix" -Verbose  -ErrorAction Stop
		}
		If (-Not (Test-Path -Path $OutFile -PathType Leaf))
		{
			""
			"Error: Failed to download file! You can manually download it by using the link below and saving it to the same place this script is:"
			""
			$URI
			""
			PauseAndFail -ErrorLevel $ErrorLevel
		}
		Return Resolve-Path -Path $OutFile
	}
	Catch
	{
		$_ | Failure
		PauseAndFail -ErrorLevel $ErrorLevel
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
			If (Test-Path $Test -PathType Container)
			{
				Return Resolve-Path -Path $Test -Verbose
			}
		}
		$Backups = @()
		$Backups += $Mutable | ForEach-Object {
			Return Get-ChildItem -Path $_.ProviderPath -Filter "$($Package)*" | Resolve-Path
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
	If (-Not (Test-Path -Path $source -PathType Container))
	{
		"ERROR: $($source) is not a folder"
		return
	}
	If (-Not (Test-Path -Path $destination -PathType Container))
	{
		New-Item -Path $destination -ItemType Directory -Verbose -ErrorAction Continue | Out-Null
		If (-Not (Test-Path -Path $destination -PathType Container))
		{
			return
		}
	}
	If (-Not (Test-Path -Path $logfile -PathType Leaf))
	{
		New-Item -Path $logfile -ItemType File #-WhatIf
	}
	$logpath = Resolve-Path -Path $logfile
	"Deleting empty files..."
	Get-ChildItem -Path $source -File -ErrorAction Continue | Where-Object Length -eq 0 | Remove-Item -ErrorAction Continue
	"Starting robocopy job..."
	$Cmdlist = "/C","Robocopy.exe", ('"{0}"' -f $source),('"{0}"' -f $destination),('"{0}"' -f $file),"/XF","*.pat","/TEE","/DCOPY:DA","/COPY:DAT","/MOV","/ZB","/ETA","/XO","/R:0","/W:1",('/LOG+:"{0}"' -f $logpath.Path)
	If ($Details -eq $true)
	{
		$Cmdlist += "/V"
	}
	Start-Process -Wait -FilePath "C:\Windows\system32\cmd.exe" -ArgumentList $Cmdlist
	$Subs = @()
	$Subs += Get-ChildItem -Directory -Depth 0 -Path $source -ErrorAction Continue
	If ($Subs.Count -gt 0)
	{
		$Subs | ForEach-Object {
			$NewSub = $_.Name
			$FilesCount = @()
			$DirsCount = @()
			If ($NewSub -notlike "win32*")
			{
				"Counting Files..."
				$FilesCount += Get-ChildItem -Path $_.FullName -Force -File -ErrorAction Continue | Where-Object BaseName -NotLike "*.pat"
				"Counting Folders..."
				$DirsCount += Get-ChildItem -Path $_.FullName -Force -Directory -ErrorAction Continue
				"Digging into $($_.FullName) Folder"
				"	$($FilesCount.Count) Files"
				"	$($DirsCount.Count) Directories"
			}
			$Details = $false
			If ($NewSub -like "win32*")
			{
				(0..0xf|% ToString X1) | ForEach-Object {
					""
					"WARNING: large number of files detected, only moving files starting with $($_) of (0123456789ABCDEF)"
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
	If (Test-Path -Path $takeownEXE)
	{
		"Reseting ACL of $($path)"
		Start-Process -Wait -FilePath $takeownEXE -ArgumentList "/R","/A","/F",('"{0}"' -f $path) -ErrorAction Continue
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
		$ErrorLevel = 255
	)
	Stop-Transcript
	If ($PauseOnFail = $false)
	{
		exit $ErrorLevel
	}
	ElseIf (Test-Path variable:global:psISE)
	{
		$ObjShell = New-Object -ComObject "WScript.Shell"
		$Button = $ObjShell.Popup("Click OK to fail hard.", 0, "Script failing", 0)
		throw $ErrorLevel
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
	If (Test-Path variable:global:psISE)
	{
		$ObjShell = New-Object -ComObject "WScript.Shell"
		$Button = $ObjShell.Popup("Click OK to keep going.", 0, "Script pausing", 0)
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
			If (Test-Path -Path $ModifiableFolder -PathType Container)
			{
				$_
			}
		}
	}
	If ($MutableVolumes.Count -gt 0)
	{
		$PackageFolders += $MutableVolumes | ForEach-Object {
			$MutableFolder = Join-Path -Path $_.PackageStorePath -ChildPath "..\WindowsModifiableApps\$($Folder)"
			If (Test-Path -Path $MutableFolder -PathType Container)
			{
				Return Resolve-Path -Path $MutableFolder
			}
		}
	}
	If (Test-Path -Path "C:\Program Files\WindowsModifiableApps\$($Folder)" -PathType Container)
	{
		$PackageFolders +=  Resolve-Path -Path "C:\Program Files\WindowsModifiableApps\$($Folder)"
	}
	If ($PackageFolders.Count -gt 0)
	{
		Return $PackageFolders.ProvidePath
	}
}


If ($TweakerMode -eq $true)
{
	$PauseOnFail = $false
	$SkipRobomove = $true
}

#Start-Service -Name "Winmgmt" -ErrorAction Stop

Write-Host -NoNewline "Checking Windows version..."
$WinVer = [Version](Get-CimInstance Win32_OperatingSystem).version
if ($WinVer.Major -lt 10)
{
	""
	"Reported Windows Major version $($WinVer.Major)"
	"ERROR: PSO2NA is only supported on Windows 10."
	PauseAndFail -ErrorLevel 1
}
Elseif ($WinVer.Minor -gt 0) {}
ElseIf ($WinVer.Build -lt 18362)
{
	""
	"Reported Windows Build $($WinVer.Build), Verion $(Window10Version -Build $WinVer.Build)"
	"ERROR: PSO2NA is only supported on Windows 10 Version 1903 or higher. You need to upgrade Windows to a newer build/version."
	PauseAndFail -ErrorLevel 2
}
Elseif ([System.Environment]::Is64BitOperatingSystem -eq $false)
{
	""
	"PSO2NA is only supported on 64-bit OS. You need to reinstall your Windows OS if your CPU is 64-bit."
	PauseAndFail -ErrorLevel 21
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
	Start-Process -FilePath "powershell.exe" -ArgumentList "-NoLogo","-NoProfile","-ExecutionPolicy","ByPass","-File",('"{0}"' -f $MyInvocation.MyCommand.Path) -Verb RunAs
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
	#PauseOnly
}

"Getting Software list..."
"Please note: if you have any broken MSI installtions, you may get errors"
$MSIList = @()
$MSIList_Bad = @()
$MSIList += Get-WmiObject -Class win32_product
"[OK]"
$MSIList_Bad += $MSIList | Where-Object Name -Like "Nahimic*"
If ($MSIList_Bad.Count -gt 0)
{
	"Found Bad software:"
	$MSIList_Bad | select -Property Vendor, Name, Caption, Description, IdentifyingNumber, PackageName
	PauseOnly
}

If ("{FD585866-680F-4FE0-8082-731D715F90CE}" -In $MSIList_Bad.IdentifyingNumber) #(Test-Path -Path "C:\Program Files\Nahimic\Nahimic2\UserInterface\x64\Nahimic2DevProps.dll" -PathType Leaf)
{
	"WARNING: Nahimic2 software detected, it is known to crash PSO2, We will uninstall it"
	$MSILog = Join-Path -Path $PSScriptRoot -ChildPath "Nahimic2.log"
	Start-Process -Wait -FilePath "MsiExec.exe" -ArgumentList "/x","{FD585866-680F-4FE0-8082-731D715F90CE}","/l*vx",$MSILog,"/qf"
}

If ("{85D06868-AE2D-4B82-A4B1-913A757F0A32}" -In $MSIList_Bad.IdentifyingNumber) #(Test-Path -Path "C:\Program Files\Alienware\AWSoundCenter\UserInterface\x64\AWSoundCenterDevProps.dll" -PathType Leaf)
{
	"WARNING: AWSoundCenter software detected, it is known to crash PSO2, We will uninstall it"
	$MSILog = Join-Path -Path $PSScriptRoot -ChildPath "AWSoundCenter.log"
	Start-Process -Wait -FilePath "MsiExec.exe" -ArgumentList "/x","{85D06868-AE2D-4B82-A4B1-913A757F0A32}","/l*vx",$MSILog,"/qf"
}


"Checking MS Store Setup"
Set-Service -Name "wuauserv" -StartupType Manual -ErrorAction Continue
#Set-Service -Name "BITS" -StartupType AutomaticDelayedStart -ErrorAction Continue
Set-Service -Name "StorSvc" -StartupType Manual -ErrorAction Continue
Get-Service -Name "wuauserv","BITS","StorSvc" | Where-Object Statis -NE "Running" | Start-Service -ErrorAction Continue -Verbose

"Restarting XBOX services..."
Get-Service -Name "XblAuthManager","XboxNetApiSvc" | Where-Object Statis -NE "Running" | Start-Service -Verbose
"Killing any XBOX process"
Get-Process -IncludeUserName | Where-Object UserName -eq ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) | Where-Object Name -like "*xbox*" | Stop-Process -Force -ErrorAction Continue

$SystemVolume = Get-AppxVolume | Where-Object -Property IsSystemVolume -eq $true

$XBOXIP_User = @()
$XBOXIP_All = @()
$XBOXIP_User += Get-AppxPackage -Name "Microsoft.XboxIdentityProvider" -PackageTypeFilter Main -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" -Verbose
$XBOXIP_All += Get-AppxPackage -Name "Microsoft.XboxIdentityProvider" -PackageTypeFilter Main -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" -AllUsers -Verbose

If ($XBOXIP_All.Count -gt 0 -and $XBOXIP_User.Count -eq 0)
{
	"XBOX Identify Provider not installed to the user account, forcing install..."
	$XBOXIP_All | Where-Object InstallLocation -ne $null |  Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -Verbose}
}
ElseIf ($XBOXIP_All.Count -eq 0)
{
	""
	"ERROR: Looks like the XBOX Identify Provider has been removed from the OS?"
	""
}

$XBOXIP = Get-AppxPackage -Name "Microsoft.XboxIdentityProvider" -PackageTypeFilter Main -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" -Verbose

If ($XBOXIP -ne $null)
{
	"Looking for the XBOX Identify Provider folder to wipe..."
	$PackageF = Join-Path -Path $env:LOCALAPPDATA -ChildPath "Packages" -Verbose
	$XBOXIPFN = $XBOXIP.PackageFamilyName
	$XBOXIPF = Join-Path -Path $PackageF -ChildPath $XBOXIPFN  -Verbose
	$XBOXTBF = Join-Path $XBOXIPF -ChildPath "AC\TokenBroker" -Verbose
	If (Test-Path -Path $XBOXTBF -PathType Container)
	{
		Takeownship -path $XBOXTBF
		Get-ChildItem $XBOXTBF | Remove-Item -Force -Recurse -Confirm:$false -ErrorAction Continue
	}
}
Else
{
	""
	"ERROR: Look like XBOX Identify Provider has been uninstalled. Please use the Windows Store to get it back."
	""
	[Diagnostics.Process]::Start("ms-windows-store://pdp?productid=9wzdncrd1hkw")
	PauseAndFail -ErrorLevel 27
}

"Checking for NET Framework 2.2 (2.2.27912.0+)"
$NETFramework = @()
$NETFramework += Get-AppxPackage -Name "Microsoft.NET.Native.Framework.2.2" -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" -PackageTypeFilter Framework | PackageVersion -Version "2.2.27912.0"
If ($NETFramework.Count -eq 0)
{
	"	NOT INSTALLED"
}
Else
{
	"	INSTALLED"
}
"Checking for needed Gaming Services App runtime..."
$GamingServices_User = @()
$GamingServices_Any = @()
$GamingServices_All = @()
$GamingServices_User += Get-AppxPackage -Name "Microsoft.GamingServices" -PackageTypeFilter Main -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" | PackageVersion -Version "2.42.5001.0"
$GamingServices_Any += Get-AppxPackage -Name "Microsoft.GamingServices" -PackageTypeFilter Main -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" -AllUsers
$GamingServices_All += $GamingServices_Any | PackageVersion -Version "2.42.5001.0"

Try
{
	$ForceReinstallGS = $true
	"Checking if we can get the Gaming Services working..."
	Get-Service | Where-Object Name -In "GamingServices","GamingServicesNet" | Where-Object Status -NE "Running" | Restart-Service
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
	"	Please udpate Gaming Services from the MS Store."
	[Diagnostics.Process]::Start("ms-windows-store://pdp?productid=9mwpm2cqnlhn")
	PauseOnly
}
ElseIf ($ForceReinstallGS -eq $true -and $GamingServices_All.Count -gt 0)
{
	"Removing Gaming Services app..."
	Get-Service -Name "GamingServices","GamingServicesNet" -ErrorAction Continue | Stop-Service -ErrorAction Continue
	$GamingServices_Any | Remove-AppxPackage -Verbose -PreserveApplicationData:$false
	$GamingServices_Any | Remove-AppxPackage -AllUsers -Verbose
	""
	"ERROR: Gaming Services has been removed, a reboot will be needed to reinstall it"
	PauseAndFail -ErrorLevel 24
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
	$GamingServices_Any += Get-AppxPackage -Name "Microsoft.GamingServices" -PackageTypeFilter Main -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" -AllUsers
	If ($BadInstall -eq $false -and $GamingServices_Any.Count -gt 0)
	{
		""
		"ERROR: Gaming Services installed, please reboot."
		PauseAndFail -ErrorLevel 25
		#Resolve-Path -Path $FileD | Remove-Item -Verbose
	}
}

If ($GamingServices_Any.Count -eq 0 -or $ForceReinstallGS -eq $true)
{
	""
	"ERROR: Please make sure to install the Gaming Services from the MS Store."
	[Diagnostics.Process]::Start("ms-windows-store://pdp?productid=9mwpm2cqnlhn")
	PauseAndFail -ErrorLevel 26
}

""
"Status of GamingService App"
Get-AppxPackage -Name "Microsoft.GamingServices" -PackageTypeFilter Main -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
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
	If (-Not (Test-Path -Path $npggsvcK))
	{
		$BrokenGG = $true
	}
	
	If ($BrokenGG)
	{
		#Delete-Service do not exist in Power-Shell 5.1
		Start-Process -Wait -FilePath "C:\Windows\system32\cmd.exe" -ArgumentList "/C","C:\Windows\system32\sc.exe","delete","npggsvc"
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
	$JSONData = Get-Content -Path $JSONPath -Verbose
}
Else
{
	""
	"ERROR: Cannot find %APPDATA% folder - Is your Windows properly set up?"
	PauseAndFail -ErrorLevel 5
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
	"ERROR: Cannot read Tweaker Setting JSON - Did you set up the Tweaker yet?"
	PauseAndFail -ErrorLevel 6
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
	"ERROR: Can not convert JSON into PowerShell Object. This shouldn't happen!"
	PauseAndFail -ErrorLevel 7
}
If ($PSO2NABinFolder -eq "")
{
	""
	"ERROR: Old version of the Tweaker config file found, please update Tweaker."
	PauseAndFail -ErrorLevel 20
}
ElseIF ($PSO2NABinFolder -contains "[" -or $PSO2NABinFolder -contains "]")
{
	""
	"ERROR: The $($PSO2NABinFolder) folder have { or ], PowerShell have issues with folder name."
	PauseAndFail -ErrorLevel 28
}
ElseIf ($PSO2NABinFolder -eq $null)
{
	""
	"ERROR: Tweaker NA Setup is not done, please tell me where to install PSO2NA."
	PauseAndFail -ErrorLevel 20
}
ElseIf (-Not (Test-Path -Path "$($PSO2NABinFolder)" -PathType Container))
{
	""
	"ERROR: The $($PSO2NABinFolder) folder does not exist. Please check your PSO2 Tweaker settings."
	PauseAndFail -ErrorLevel 16
}
ElseIf ($PSO2NABinFolder)
{
	$PSO2NAFolder = $PSO2NABinFolder | Split-Path
}
Else
{
	""
	"ERROR: Cannot find a PSO2NABinFolder setting - Did you set up PSO2NA through the Tweaker yet? If not, do it."
	PauseAndFail -ErrorLevel 8
}
If (-Not (Test-Path -Path $PSO2NAFolder -PathType Container))
{
	""
	"ERROR: The $($PSO2NAFolder) folder does not exist. Please check your PSO2 Tweaker settings."
	PauseAndFail -ErrorLevel 17
}
ElseIf ($PSO2NAFolder)
{
	$LeafPath = $PSO2NAFolder | Split-Path -Leaf
	If ($LeafPath -eq "ModifiableWindowsApps")
	{
		""
		"ERROR: You cannot use the Windows Store copy of PSO2 with this script. Go back to http://arks-layer.com/setup.html and do a fresh install."
		""
		"WARNING: If you just wanted to fix your XBOX login issue, you should be fine now."
		PauseAndFail -ErrorLevel 10
	}
	"Moving instance to $($PSO2NAFolder) Folder..."
	Set-Location -Path $PSO2NAFolder -Verbose
}
Else
{
	""
	"ERROR: Cannot get PSO2NA Folder - Did you follow the instructions?"
	PauseAndFail -ErrorLevel 9
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
$PSO2Vol_exFAT +=  $PSO2Vol | Where-Object -Property FileSystemType -EQ exFAT
$PSO2Vol_NTFS +=  $PSO2Vol | Where-Object -Property FileSystemType -EQ NTFS

If ($BrokenVolume -eq $true)
{
	""
	"WARNING: Your system's WMI database is broken, please repair it."
}
ElseIf ($PSO2Vol_exFAT.Count -gt 0)
{
	""
	"WARNING: Your PSO2NA installation on an exFAT formatted drive, please move the PSO2NA installation elsewhere."
	PauseAndFail -ErrorLevel 15
}

If ($PSO2Vol_NTFS.Count -gt 0)
{
	"Your PSO2NA installation is on a NTFS drive \o/"
}
ElseIF ($PSO2Vol.Count -gt 0)
{
	"WARNING: Your PSO2NA installtion in on an unknown filesytem: $($PSO2Vol.FileSystem -join ",")?"
	PauseOnly
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
	""
	"ERROR: Cannot find required files - Go back to http://arks-layer.com/setup.html and make sure you follow ALL the steps and do a fresh new install."
	"If you think you did it right (you probably didn't!), download"
	""
	"https://github.com/Arks-Layer/PSO2WinstoreFix/blob/master/pso2_bin_na_starter.zip"
	""
	"extract it to your PHANTASYSTARONLINE2 or PHANTASYSTARONLINE2_NA folder and DO A FILE CHECK!"
	"(Troubleshooting -> New Method)"
	PauseAndFail -ErrorLevel 11
}

Write-Host -NoNewline "Checking for Developer Mode..."
$DevMode = $false
$RegistryKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock"
if (Test-Path -Path $RegistryKeyPath)
{
	$AppModelUnlock = Get-ItemProperty -Path $RegistryKeyPath
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
	"You need to enable Developer mode. Please see https://www.howtogeek.com/292914/what-is-developer-mode-in-windows-10/"
	PauseAndFail -ErrorLevel 4
}
"[OK]"

$OldBackups = @()
"Looking for old PSO2NA MutableBackup folders..."
$OldBackups += FindMutableBackup
$OldPackages = @()
$OldPackages = Get-AppxPackage -Name "100B7A24.oxyna" -AllUsers | Where-Object -Property SignatureKind -EQ "Store"
If ($OldBackups.Count -gt 0)
{
	"Found some MutableBackup folders!"
	$OldBackups |fl
	$OldBackups | ForEach-Object -Process {
		$OldBin = $_
		Takeownship -path $OldBin
		"Going to move the old MS STORE backup files from $($OldBin) to your Tweaker copy of PSO2..."
		RobomoveByFolder -source $OldBin -destination $PSO2NABinFolder
		"Deleting old $($OldBin) folder..."
try {
		"Deleting files in $($OldBin) Folder..."
		Get-ChildItem -Path $OldBin -ErrorAction Continue -File | Remove-Item -Force -Recurse -Confirm:$false -ErrorAction SilentlyContinue
} Catch {}
try {
		"Deleting $($OldBin) Folder..."
		Remove-Item -Path $OldBin -Force -Recurse -Confirm:$false -ErrorAction SilentlyContinue
} Catch {}

	}
}

If ($OldPackages.Count -gt 0)
{
	$OldPackages | Where-Object InstallLocation -ne $null | ForEach-Object -Process {
		$OldBin = $_.InstallLocation
		"Found the old MS STORE's pso2_bin core folder!"
		Takeownship -path $OldBin
		"Going to move the MS STORE core files to your Tweaker copy of PSO2..."
		RobomoveByFolder -source $OldBin -destination $PSO2NABinFolder
		"Deleting old MS STORE's pso2_bin core folder..."
try {
		"Deleting files in $($OldBin) Folder..."
		Get-ChildItem -Path $OldBin -ErrorAction Continue -File | Remove-Item -Force -Recurse -Confirm:$false -ErrorAction SilentlyContinue
} Catch {}
try {
		#"Deleting $($OldBin) Folder..."
		#Remove-Item -Path $OldBin -Force -Recurse -Confirm:$false -ErrorAction SilentlyContinue
} Catch {}
	}
	"If this takes more then 30 minutes, you may have to reboot."
	"Unregistering the old PSO2 from the Windows Store... (This may take a while, don't panic!)"
	$OldPackages | Remove-AppxPackage -AllUsers -Verbose
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

if ($DirectXRuntime_All.Count -gt 0 -and $DirectXRuntime_User.Count -eq 0)
{
	"System already has a good copy of DirectX, trying to install the user profile..."
	$DirectXRuntime_All | Where-Object InstallLocation -ne $null | Sort-Object -Unique InstallLocation | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -Verbose}
	$DirectXRuntime_User += Get-AppxPackage -Name "Microsoft.DirectXRuntime" -PackageTypeFilter Framework -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" | PackageVersion -Version $DirectXRuntime_version
}

If ($DirectXRuntime_User.Count -eq 0)
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

If ($VCLibs_All.Count -gt 0 -And $VCLibs_User.Count -eq 0 )
{
	"System already has a good copy of VCLibs, trying to install the user profile"
	$VCLibsAll | Where-Object InstallLocation -ne $null | Sort-Object -Unique InstallLocation | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -Verbose}
	$VCLibs_User += Get-AppxPackage -Name "Microsoft.VCLibs.140.00.UWPDesktop" -PackageTypeFilter Framework -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" | PackageVersion -Version $VCLibs_Version
}

if ($VCLibs_User.Count -eq 0)
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
Get-AppxPackage -Name "Microsoft.DirectXRuntime" -PackageTypeFilter Framework -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
"Status of VCLIB framework"
Get-AppxPackage -Name "Microsoft.VCLibs.140.00.UWPDesktop" -PackageTypeFilter Framework -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
"End of Framework status"


$PSO2Packages = @()
$PSO2Packages_User = @()
$PSO2Packages_Good = @()
$PSO2Packages_Bad = @()
$EmptyFiles = Get-ChildItem -Path $PSO2NABinFolder | Where-Object Name -ne "patchlist.txt" | Where-Object Name -NotLike "*.pat" | Where-Object Length -eq 0
$PSO2Packages += Get-AppxPackage -Name "100B7A24.oxyna" -AllUser | Where-Object -Property SignatureKind -EQ "None"
$PSO2Packages_User += Get-AppxPackage -Name "100B7A24.oxyna" | Where-Object -Property SignatureKind -EQ "None"
$PSO2Packages_Good += $PSO2Packages | Where-Object InstallLocation -eq $PSO2NAFolder | Where-Object Status -EQ "Ok"
$PSO2Packages_Bad += $PSO2Packages | Where-Object InstallLocation -ne $PSO2NAFolder
$PSO2Packages_Bad += $PSO2Packages | Where-Object Status -ne "Ok"
#$PSO2Packages_Bad += $PSO2Packages | PackageVersion -Version "1.0.7.0"

$XBOXURI = Test-Path -Path "Registry::HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\windows.protocol\ms-xbl-78a72674" -PathType Container
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
Add-AppxVolume -Path ("{0}:" -f (Resolve-Path -Path $PSO2NAFolder).Drive.Name) -ErrorAction Continue
$Appxvols += Get-AppxVolume -Path ("{0}:" -f (Resolve-Path -Path $PSO2NAFolder).Drive.Name)
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
	"List of bad files:"
	$EmptyFiles
	""
}
ElseIf ($PSO2Packages_Good.Count -eq 0 -or $ForceReinstall -eq $true) #Try
{
	"Registering our new shiny PSO2 with the Windows Store... (This may take a while, don't panic!)"
	If ($NewPackages.Count -gt 0 -and $false)
	{
		Add-AppxPackage -Register .\appxmanifest.xml -Verbose -DependencyPath $PSO2NAFolder
	}
	Else
	{
		Add-AppxPackage -Register .\appxmanifest.xml -Verbose -ErrorAction Continue
	}
}
Else
{
	"There is already a custom PSO2 install?"
	$PSO2Packages_Good
}
If ($False) #Catch
{
	$_ | Failure
	PauseAndFail -ErrorLevel 14
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
	"Good, only found one custom PSO2 install."
}
Else
{
	"What? why are there $($CustomPSO2) custom PSO2 install?!"
}
""
Stop-Transcript -ErrorAction Continue
Write-Host -NoNewLine 'Script complete! You can now close this window by pressing any key.';
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
