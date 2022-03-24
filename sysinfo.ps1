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
# If the computer is a member of a domain, it is essential to get information about the domain so we know what we are working with for the audit
"------------------------------------------------------------------------------------------------------"
get-adcomputer

# It is helpful to put the computers in a single variable for later use. This can be done with the following command:
$COMPUTERS = Get-ADComputer -Filter * | %{$_.name} 

arp -a

# It is easy to run commands on domain computers with Invoke-Command. Here is an example that gets the IP info for the computers in the domain. 
# The $COMPUTERS variable is an array that contains all of the computer names in the domain as seen in the command above.
Invoke-Command -ComputerName $COMPUTERS -ScriptBlock {get-netipaddress | Select-Object PSComputerName, IPAddress}

# Other important commands to be run on other computers could include:
# Powershell version
Invoke-Command -ComputerName $COMPUTERS -ScriptBlock {$psversiontable} 
# OS and version
get-ciminstance Win32_OperatingSystem -ComputerName $COMPUTERS -Property * name, version, OSArchitecture, BuildNumber, Buildtype 
# Mac address
Invoke-Command -ComputerName $comp -ScriptBlock {get-netadapter | Select-Object name, macaddress}
# Services running on computer
$counter=0
get-ciminstance win32_service -ComputerName DC | % {if ($_.state -eq 'Running') {$counter+=1}}

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