"------------------------------------------------------------------------------------------------------"
"BASIC SYSTEM INFO"
"------------------------------------------------------------------------------------------------------"
Get-ComputerInfo | Select-Object OsVersion, WindowsRegisteredOwner, CsDomainRole, csname, OsRegisteredUser, OsArchitecture, OsNumberOfUsers, OsNumberOfProcesses, OsMaxProcessMemorySize, OsName, CsModel

"IP INFO"  
Get-NetIPaddress | sort ifIndex | Select-Object ifIndex, IPAddress, InterfaceAlias


"------------------------------------------------------------------------------------------------------"
"DOMAIN INFO"
"------------------------------------------------------------------------------------------------------"
get-adcomputer

$COMPUTERS = Get-ADComputer -Filter * | %{$_.name} 

arp -a

get-ciminstance Win32_OperatingSystem -ComputerName $COMPUTERS -Property * name, version, OSArchitecture, BuildNumber, Buildtype 

<#------------------------------------------------------------------------------------------------------
WINDOWS DEFENDER STATUS + FIREWALL RULES
------------------------------------------------------------------------------------------------------#>
if (set-MpPreference -DisableRealtimeMonitoring $True) {
set-MpPreference -DisableRealtimeMonitoring $False
}

Get-service Windefend

"FIREWALL STATUS"
Get-NetFirewallRule -Direction Inbound | Select-Object -Property DisplayName,Profile,Enabled

"------------------------------------------------------------------------------------------------------"
"SCAN NETWORK FOR OPEN PORTS"
"------------------------------------------------------------------------------------------------------"
Import-Module .\port-scan.ps1
port-scan-tcp 192.168.50.1 80


"-----------------------------------------------------------------------------------------------------"
"CHANGING LOCK SCREEN TIMEOUT SETTINGS"
"-----------------------------------------------------------------------------------------------------"
powercfg.exe /setacvalueindex SCHEME_CURRENT SUB_VIDEO VIDEOCONLOCK "<time in seconds>"
powercfg.exe /setactive SCHEME_CURRENT
