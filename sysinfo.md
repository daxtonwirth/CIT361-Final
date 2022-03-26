# BASIC SYSTEM INFO
In order to start a security audit, we need to get the basic system info that can be done with the following commands
This command corresponds to systeminfo in cmd: 
```
Get-ComputerInfo
``` 
This gives us more information than we need. Filter the output with "Select-Object" to only the interesting ones. I selected these objects as important to gaining necessary info about the system:
```
Get-ComputerInfo | Select-Object OsVersion, WindowsRegisteredOwner, CsDomainRole, csname, OsRegisteredUser, OsArchitecture, OsNumberOfUsers, OsNumberOfProcesses, OsMaxProcessMemorySize, OsName, CsModel
```

## IP INFO 
This command can also have too much info so we can make it easier to read as a table using "ft" (Format-Table):
```
Get-NetIPaddress | ft
```

But, this can still be too much info so I chose to only select these objects (I also sorted it to make it easier to read):
```
Get-NetIPaddress | sort ifIndex | Select-Object ifIndex, IPAddress, InterfaceAlias
```
## LISTENING PORTS
We can get the listening port with the following command (netstat -ano would be equivilant in cmd): 
```
Get-NetTcpConnection 
```
Again, we can make it prettier:
```
Get-NetTcpConnection | sort LocalPort | Group-Object LocalPort
```

## SCHEDULED TASKS
Scheduled tasks can also be a good place to look for potentially suspicious activity (schtasks /query /fo LIST /v):
```
Get-ScheduledTask 
```
Look for ones you do not recognize, especially ones NOT in the \Microsoft\Windows\ folder, and make sure they are legitimate. To make it pretty (Remove ones that are disabled and sort):
```
Get-ScheduledTask | Sort-Object State , TaskName | % {if ($_.state -ne "Disabled") {$_}}
```

---
# DOMAIN INFO + other computers on network
If the computer is a member of a domain, it is essential to get information about the domain so we know what we are working with for the audit
* If you are registered for this class, you can get access to practice: ssh USERNAME@cit361-lab.citwdd.net -p 443
First, get the info about the computers on the domain:
```
get-adcomputer -Filter * | ft
```

It is helpful to put the computers in a single variable for later use. This can be done with the following command:
```
$COMPUTERS = Get-ADComputer -Filter * | % {$_.name} 
```
We can also find what ip addresses the machine has contacted with to get more into with the arp table ("arp -a" in CMD):
```
Get-NetNeighbor 
```
To make this much prettier, you can filter by removing the broadcast, multicast, IPv6, and link local addresses:
```
Get-NetNeighbor | sort IPAddress | % {if (!($_.IPAddress -match '.255') -and !($_.IPAddress -match '224.') -and !($_.IPAddress -match 'ff02:') -and !($_.IPAddress -match 'fe80:')){$_}}
```

## Run commands on other computers in domain
It is easy to run commands on domain computers with Invoke-Command. We can run all of the previous commands shown above on other computers in the domain. Here is an example that gets the IP info for the computers in the domain. (The $COMPUTERS variable is an array that contains all of the computer names in the domain as seen in the command above):
```
Invoke-Command -ComputerName $COMPUTERS -ScriptBlock {get-netipaddress | Select-Object PSComputerName, IPAddress}
```

Other important commands to be run on other computers could include:
* Powershell version (some commands may not run properly depending on version)
```
Invoke-Command -ComputerName $COMPUTERS -ScriptBlock {$psversiontable} 
```
* OS and version
This command was made to remote to other computers with -ComputerName:
```
get-ciminstance Win32_OperatingSystem -ComputerName $COMPUTERS -Property * name, version, OSArchitecture, BuildNumber, Buildtype 
```
* Services running on computer
```
$counter=0
get-ciminstance win32_service -ComputerName DC | % {if ($_.state -eq 'Running') {$counter+=1}}
```

## To update passwords on the domain: 
```
Set-ADAccountPassword
```

Changing weak passwords can be very important but also be a burden without automation
First in order to get the users in the domain, we can use the following command:
```
$users = Get-ADUser -Filter * -SearchBase $domain -Properties DistinguishedName
```
Then we can reset the password with the below options. Feel free to change the switches to whatever works best for you:
```
$users | % {Select-Object -expand DistinguishedName | Set-ADAccountPassword -Identity $name -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $password)}
```
There are also other commands that can change certain types of user including the following which only changes users in the user's group:
```
dsquery user ou=Users,dc=NAME | dsmod user -pwd STR0NGP4$$W0RD
```





# WINDOWS DEFENDER STATUS + FIREWALL RULES
```
Get-service Windefend
sc query windefend
```

Check the status:
```
Get-MpComputerStatus | select RealTimeProtectionEnabled
```
For a domain:
```
Get-CimInstance -ComputerName MyRemoteServer -Query 'Select * from MSFT_MPComputerStatus' -Namespace 'root\Microsoft\Windows\Defender' | Select RealTimeProtectionEnabled,PSComputerName
```
If the firewall is not disabled, this command can enable it:
```
set-MpPreference -DisableRealtimeMonitoring $False
```

Confirm it is enabled:
```
Get-MpPreference | Select-Object DisableRealtimeMonitoring
```

## Firewall Rules
```
Get-NetFirewallRule -Direction Inbound | Select-Object -Property DisplayName,Profile,Enabled
```

---
# SCAN NETWORK FOR OPEN PORTS
```
Import-Module .\port-scan.ps1
port-scan-tcp 192.168.50.1 80
```


# CHANGING LOCK SCREEN TIMEOUT SETTINGS
```
powercfg.exe /setacvalueindex SCHEME_CURRENT SUB_VIDEO VIDEOCONLOCK "<time in seconds>"
powercfg.exe /setactive SCHEME_CURRENT
```
