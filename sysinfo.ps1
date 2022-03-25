<#------------------------------------------------------------------------------------------------------
BASIC SYSTEM INFO
 In order to start a security audit, we need to get the basic system info and these commands will do that
------------------------------------------------------------------------------------------------------#>
Get-ComputerInfo (This command corresponds to systeminfo in cmd)
# This gives a lot of info we probably do not need. Here is one that filters out the info that is not as important:
Get-ComputerInfo | Select-Object OsVersion, WindowsRegisteredOwner, CsDomainRole, csname, OsRegisteredUser, OsArchitecture, OsNumberOfUsers, OsNumberOfProcesses, OsMaxProcessMemorySize, OsName, CsModel

"IP INFO" # Get-NetIPaddress 
# This command can also have a lot of info so we can make it easier to read as a table adding "| ft", but still too much info so we can filter out unnecessary info:
Get-NetIPaddress | sort ifIndex | Select-Object ifIndex, IPAddress, InterfaceAlias


<#------------------------------------------------------------------------------------------------------
DOMAIN INFO + other computers on network
 If the computer is a member of a domain, it is essential to get information about the domain so we know what we are working with for the audit
------------------------------------------------------------------------------------------------------#>
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



To update passwords on the domain: 
Set-ADAccountPassword

<# Changing weak passwords can be very important but also be a burden without automation
First in order to get the users in the domain, we can use the following command:
$users = Get-ADUser -Filter * -SearchBase $domain -Properties DistinguishedName

Then we can reset the password with the below options. Feel free to change the switches to whatever works best for you:

$users | % {Select-Object -expand DistinguishedName | Set-ADAccountPassword -Identity $name -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $password)}

There are also other commands that can change certain types of user including the following which only changes users in the user's group:

dsquery user ou=Users,dc=NAME | dsmod user -pwd STR0NGP4$$W0RD
#>


"------------------------------------------------------------------------------------------------------"
"LISTENING PORTS:"
"------------------------------------------------------------------------------------------------------"
netstat -ano

"------------------------------------------------------------------------------------------------------"
"SCHEDULED TASKS"
"------------------------------------------------------------------------------------------------------"
schtasks /query /fo LIST /v

<#------------------------------------------------------------------------------------------------------
WINDOWS DEFENDER STATUS + FIREWALL RULES
------------------------------------------------------------------------------------------------------#>
Get-service Windefend
sc query windefend

# Check the status:
Get-MpComputerStatus | select RealTimeProtectionEnabled
# For a domain:
Get-CimInstance -ComputerName MyRemoteServer -Query 'Select * from MSFT_MPComputerStatus' -Namespace 'root\Microsoft\Windows\Defender' | Select RealTimeProtectionEnabled,PSComputerName

# If the firewall is not disabled, this command can enable it:
set-MpPreference -DisableRealtimeMonitoring $False

# Confirm it is enabled:
Get-MpPreference | Select-Object DisableRealtimeMonitoring

Get-NetFirewallRule -Direction Inbound | Select-Object -Property DisplayName,Profile,Enabled

<#------------------------------------------------------------------------------------------------------
SCAN NETWORK FOR OPEN PORTS
------------------------------------------------------------------------------------------------------#>
Import-Module .\port-scan.ps1
port-scan-tcp 192.168.50.1 80



<#-----------------------------------------------------------------------------------------------------
CHANGING LOCK SCREEN TIMEOUT SETTINGS
-----------------------------------------------------------------------------------------------------#>
powercfg.exe /setacvalueindex SCHEME_CURRENT SUB_VIDEO VIDEOCONLOCK "<time in seconds>"
powercfg.exe /setactive SCHEME_CURRENT
