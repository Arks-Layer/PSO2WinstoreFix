$UpdateState = @()
If (-Not ( Test-Path -Path "client_na.json" -PathType Leaf))
{
"client_na.json file is missing, please move me into the Tweaker folder"
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
exit 0
}
"Loading Tweaker's NA Update state file, client_na.json"
$UpdateState += Get-Content -Raw -Path "client_na.json" | ConvertFrom-Json
$BadEXEs = @()
"Selecting EXEs listings"
$BadEXEs += $UpdateState | Get-Member -Name "*.exe"
If ($BadEXEs.Count -gt 0)
{
"Removing EXEs listing"
$NewState = $UpdateState | Select-Object -Property * -ExcludeProperty $BadEXEs.Name
}
Else
{
"No EXE listing found"
$NewState = $UpdateState
}
"Saving to Tweaker's NA Update state file, client_na.json"
$NewState  | ConvertTo-Json | Out-File  -FilePath "client_na.json"