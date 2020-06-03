Start-Transcript -Path PSO2NA_PSLOG.log

function Failure {
    $result = $_.Exception.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($global:result)
    $responseBody = $global:reader.ReadToEnd();
    "Status: A system exception was caught."
    $responsebody
    Stop-Transcript
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	#exit 254
}

"Checking Windows version"
$WinVer = [Version](Get-CimInstance Win32_OperatingSystem).version
if ($WinVer.Major -lt 10)
{
	"PSO2NA is only supported on Windows 10. Press any key to exit."
	Stop-Transcript
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	exit 1
}
ElseIf ($WinVer.Build -lt 18362)
{
	"PSO2NA is only supported on Windows 10 (1903+). You need to update your Windows. Press any key to exit."
	Stop-Transcript
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	exit 2
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
	"You need to run this PowerShell script with Administrator power"
	Stop-Transcript
	Start-Process powershell.exe "-NoLogo","-NoProfile","-ExecutionPolicy","ByPass","-File",('"{0}"' -f $MyInvocation.MyCommand.Path) -Verb RunAs
	exit
	#$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	#exit 3
}
"[OK]"
""
""
""
""

Write-Host -NoNewline "Checking for Developer Mode..."
$DevMode = $true
$RegistryKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock"
if (Test-Path -Path $RegistryKeyPath)
{
    $AppModelUnlock = Get-ItemProperty -Path $RegistryKeyPath
	if (Get-Member -InputObject $AppModelUnlock -Name AllowDevelopmentWithoutDevLicense)
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
	"You need to enable Developer mode"
	Stop-Transcript
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	exit 4
}
"[OK]"

Write-Host -NoNewline "Check PSO2 Tweaker settings..."
$JSONPath = $null
$JSONData = $null
$PSO2NABinFolder = $null
$PSO2NAFolder = $null
$JSONPath = [System.Environment]::ExpandEnvironmentVariables("%APPDATA%\PSO2 Tweaker\settings.json")
If ($JSONPath)
{
    $JSONData = Get-Content -Path $JSONPath -Verbose
}
Else
{
    "Cannot find %APPDATA% folder - Is your Windows OK? Press any key to exit."
	Stop-Transcript
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	exit 5
}
If ($JSONData)
{
    $JSONObj = $JSONData | ConvertFrom-Json -Verbose
}
Else
{
    "Cannot read Tweaker Setting JSON - Did you set up the Tweaker yet? Press any key to exit."
	Stop-Transcript
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	exit 6
}
If ($JSONObj)
{
    $PSO2NABinFolder = $JSONObj | Select-Object -ExpandProperty PSO2NABinFolder
}
Else
{
    "Can not convert JSON into PowerShell Object. Press any key to exit."
	Stop-Transcript
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	exit 7
}
If ($PSO2NABinFolder)
{
    $PSO2NAFolder = $PSO2NABinFolder | Split-Path
}
Else
{
    "Cannot find a PSO2NABinFolder setting - Did you set up PSO2NA through the Tweaker yet? If not, do it. Press any key to exit."
	Stop-Transcript
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	exit 8
}
If ($PSO2NAFolder)
{
    $LeafPath = $PSO2NAFolder | Split-Path -Leaf
    If ($LeafPath -eq "ModifiableWindowsApps")
    {
        "You cannot use the Windows Store copy of PSO2 with this script. Go back to http://arks-layer.com/setup.html and do a fresh install."
        "Press any key to exit."
	    Stop-Transcript
	    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	    exit 10
    }
    "Moving instance to $($PSO2NAFolder) Folder"
    Set-Location -Path $PSO2NAFolder -Verbose
}
Else
{
    "Cannot get PSO2NA Folder - Did you follow the instructions? Press any key to exit."
	Stop-Transcript
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	exit 9
}

"Checking if Volume is formated as NTFS"
$PSO2Vol = @()
$PSO2Vol += Get-Volume - FilePath $PSO2NAFolder | Where-Object -Property FileSystemType -EQ NTFS
If ($PSO2Vol.Count -eq 0)
{
    "Your PSO2NA installtion is not installed on a NTFS drive, please move the PSO2NA installtion elsewhere"
    Stop-Transcript
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
    exit 15
}

"Checking for appxmanifest.xml..."
$Files = @()
$Files += Get-ChildItem | Where-Object -Property Name -EQ "appxmanifest.xml"
If ($Files.Count -ne 1)
{
    "Cannot find appxmanifest.xml file - Go back to http://arks-layer.com/setup.html and make sure you follow ALL the steps and do a fresh new install."
    Stop-Transcript
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	exit 11
}

"Checking if we need to install the requirments"
$NewPackages = @()
$DirectXRuntime = @()
$DirectXRuntime_Good = @()
$DirectXRuntime += Get-AppxPackage -Name "Microsoft.DirectXRuntime" -PackageTypeFilter Framework -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" | Where-Object -Property Architecture -EQ "X64"
$VersionCheck = [Version]"9.29.952.0"
$DirectXRuntime_Good += ([Version]$DirectXRuntime.Version -ge $VersionCheck) -eq $true
$VCLibs = @()
$VCLibs_Good = @()
$VersionCheck = [Version]14.0.24217.0
$VCLibs += Get-AppxPackage -Name "Microsoft.VCLibs.140.00.UWPDesktop" -PackageTypeFilter Framework -Publisher "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" | Where-Object -Property Architecture -EQ "X64"
$VCLibs_Good += ([Version]$VCLibs.Version -ge $VersionCheck) -eq $true

If ($DirectXRuntime_Good.Count -eq 0)
{
    "Downloading DirectXRuntime requirement... (56MB)"
    $URI = "https://download.microsoft.com/download/c/c/2/cc291a37-2ebd-4ac2-ba5f-4c9124733bf1/UAPSignedBinary_Microsoft.DirectX.x64.appx"
    $FileD = "UAPSignedBinary_Microsoft.DirectX.x64.appx"
    Try
    {
        Invoke-WebRequest -Uri $URI -OutFile $FileD  -Verbose -ErrorAction:Stop
    }
    Catch 
    {
        Failure
        exit 12
    }
    
    "Adding DirectXRuntime requirement to TODO list..."
    $NewPackages += $FilesD
}

If ($VCLibs_Good.Count -eq 0)
{
    "Downloading VCLibs requirement... (7MB)"
    $URI = "https://arks-layer.com/docs/Microsoft.VCLibs.x64.14.00.Desktop.appx"
    $FileD = "Microsoft.VCLibs.x64.14.00.Desktop.appx"
    Try
    {
        Invoke-WebRequest -Uri $URI -OutFile $FileD -Verbose -ErrorAction:Stop
    }
    Catch 
    {
        Failure
        exit 13
    }
    "Adding VCLibs requirement to TODO list..."
    $NewPackages += $FilesD
}
If ($NewPackages.Count -gt 0)
{
    "Installing requirements... If you see an error about it not being installed becuase of a higher version, that's OK!"
    $NewPackages | Add-AppxPackage -Verbose
    $NewPackages | Remote-Item -Verbose
}


$OldPackages = @()
"Look For a PSO2NA Windows Store Installtion"
$OldPackages = Get-AppxPackage -Name "100B7A24.oxyna" -AllUsers
If ($OldPackages.Count -gt 0)
{
    "Unregistering the old PSO2 from the Windows Store... (This may take a while, don't panic!)"
    $OldPackages | Remove-AppxPackage -AllUsers -Verbose
}
Else
{
    "Had not detected a PSO2NA Windows Store Installation"
}

"Registering our new shiny PSO2 with the Windows Store... (This may take a while, don't panic!)"
Try
{
    Add-AppxPackage -Register .\appxmanifest.xml -Verbose -ErrorAction Stop
}
Catch
{
    Failure
    exit 14
}

Stop-Transcript
Write-Host -NoNewLine 'Fixes complete! You can now close this window by pressing any key.';
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
