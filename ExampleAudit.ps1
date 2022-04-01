"------------------------------------------------------------------------------------------------------"
"BASIC SYSTEM INFO"
"------------------------------------------------------------------------------------------------------"
Get-ComputerInfo | Select-Object CsName, OsName, OsVersion, CsDomainRole, WindowsRegisteredOwner, OsRegisteredUser, OsArchitecture, OsNumberOfUsers, OsNumberOfProcesses, OsMaxProcessMemorySize, CsModel

"IP INFO"  
Get-NetIPaddress | sort ifIndex | Select-Object ifIndex, IPAddress, InterfaceAlias | ft

"Ports"
get-nettcpconnection | select local*,remote*,state,@{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} |?{$_.localport -le 49000} |sort localport |group-object localport,process| ft

"Tasks"
Get-ScheduledTask | Sort-Object State , TaskName | % {if ($_.state -ne "Disabled") {$_}} 

"ACTIVE USERS (consider using get-aduser for domain users)"
Get-LocalUser | ? {$_.enabled -eq "True"} | Select-Object Name, Enabled, PrincipalSource, ObjectClass, Description, LastLogin, passwordlastset |ft

"------------------------------------------------------------------------------------------------------"
"DOMAIN INFO"
"------------------------------------------------------------------------------------------------------"
"Domain Computers"
Get-ADComputer -Filter * -Properties ipv4Address, OperatingSystem | Select-Object Name, IPv4Address, OperatingSystem, Enabled | ft 

"ARP"
Get-NetNeighbor | sort IPAddress | % {if (!($_.IPAddress -match '.255') -and !($_.IPAddress -match '224.') -and !($_.IPAddress -match 'ff02:') -and !($_.IPAddress -match 'fe80:')){$_}} | Select-Object ifindex, ipaddress, LinkLayerAddress, interfacealias | ft

"Users"
get-aduser -Filter * | sort name | Select-Object Name, enabled, objectclass, DistinguishedName

"Domain Admins"
Get-ADGroupMember Administrators 

"WinRM (Disable if not using: stop-service winrm)"
get-service winrm

"------------------------------------------------------------------------------------------------------"
"Updates"
"------------------------------------------------------------------------------------------------------"
"Windows update"
Install-Module PSWindowsUpdate 
Get-WindowsUpdate -AcceptAll -Install -AutoReboot 

"------------------------------------------------------------------------------------------------------"
"WINDOWS DEFENDER"
"------------------------------------------------------------------------------------------------------"
set-MpPreference -DisableRealtimeMonitoring $False
Start-service windefend 
Get-MpPreference | Select-Object DisableRealtimeMonitoring

"------------------------------------------------------------------------------------------------------"
"FIREWALL STATUS"
"------------------------------------------------------------------------------------------------------"
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
