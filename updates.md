## Updates the antimalware definitions on a computer.
```
Update-MpSignature
```
Example that runs it as a job because it can take longer to complete on a cim session: 
```
Update-MpSignature -AsJob -CimSession SESSION
```
To learn more: https://docs.microsoft.com/en-us/powershell/module/defender/update-mpsignature?view=windowsserver2022-ps 

---
## Module for updates 
Install a module that allows you to patch a new installation or create a custom script to automate the process. Type "a" to accept the terms (It is a community module by Michal Gajda).
```
Install-Module PSWindowsUpdate
```
Get availible updates:
```
Get-WindowsUpdate
```
Install the availible updates:
```
Install-WindowsUpdate
```
Automatically gets and installs all updates
```Get-WindowsUpdate -AcceptAll -Install -AutoReboot
```
Example that installs specific KB:
```
Get-WindowsUpdate -Install -KBArticleID 'KB5007186'
```
