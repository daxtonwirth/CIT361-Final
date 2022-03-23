"------------------------------------------------------------------------------------------------------"
"BASIC SYSTEM INFO"
# In order to start a security audit, we need to get the basic system info and these commands will do that"
"------------------------------------------------------------------------------------------------------"
# Get-ComputerInfo (This command corresponds to systeminfo in cmd)
# This gives a lot of info we probably do not need. Here is one that filters out the info that is not as important:
Get-ComputerInfo | Select-Object OsVersion, WindowsRegisteredOwner, CsDomainRole, csname, OsRegisteredUser, OsArchitecture, OsNumberOfUsers, OsNumberOfProcesses, OsMaxProcessMemorySize, OsName, CsModel

"IP INFO" # Get-NetIPaddress 
# This command can also have a lot of info so we can make it easier to read as a table adding "| ft", but still too much info so we can filter out unnecessary info:
Get-NetIPaddress | sort ifIndex | Select-Object ifIndex, IPAddress, InterfaceAlias


"------------------------------------------------------------------------------------------------------"
"DOMAIN INFO + other computers on network"
"------------------------------------------------------------------------------------------------------"
get-adcomputer
arp -a
Invoke-Command -ComputerName $COMPUTERS -ScriptBlock {get-netipaddress | Select-Object PSComputerName, IPAddress}

"------------------------------------------------------------------------------------------------------"
"LISTENING PORTS:"
"------------------------------------------------------------------------------------------------------"
netstat -ano

"------------------------------------------------------------------------------------------------------"
"SCHEDULED TASKS"
"------------------------------------------------------------------------------------------------------"
schtasks /query /fo LIST /v

"------------------------------------------------------------------------------------------------------"
"WINDOWS DEFENDER STATUS + FIREWALL RULES"
"------------------------------------------------------------------------------------------------------"
Get-service Windefend
sc query windefend

# if (status -ne "running") {enable}

"------------------------------------------------------------------------------------------------------"
"UPDATES"
"------------------------------------------------------------------------------------------------------"
.\updates.ps1

"------------------------------------------------------------------------------------------------------"
"SCAN NETWORK FOR OPEN PORTS"
"------------------------------------------------------------------------------------------------------"
Import-Module .\port-scan.ps1
port-scan-tcp 192.168.50.1 80
