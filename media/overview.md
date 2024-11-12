# PowerShellTool.ps1 Overview
## Read a registry key
- Retrieves the values of a registry path
```
.\PowerShellTool.ps1 -registry -regPath HKLM:\SYSTEM\CurrentControlSet\Services
```
## Hash a file
- Hash a file by passing a valid file path. 
- Hash algorithm may be md5, sha1, or sha256
```
PS D:\Code\PowerShell\PowerShellTool> .\PowerShellTool.ps1 -hash -filePath C:\WINDOWS\xhunter1.sys -sha256
0D1FD685DC98D0C193529DF3DDDE7144D839F56B7B38251FD7039C33C0FCF760
```

## Get Virus Total information from a file hash 
- Checks a file hash on VirusTotal's website with an API key specified by the user
- Results are deserialized JSON
```
.\PowerShellTool -virusTotal -vtAPIKey $Env:VT_API_KEY -vtHash 0D1FD685DC98D0C193529DF3DDDE7144D839F56B7B38251FD7039C33C0FCF760
```

## Get Authenticode Information for a File
- Gets the Authenticode Signature Information for a file path
```
.\PowerShellTool -getAuthenticode -filePath C:\Windows\xhunter1.sys
```

## Get Service Names from Registry
- Enumerates all services from Windows Registry
```
PS D:\Code\PowerShell\PowerShellTool> .\PowerShellTool -services
...
```
## Get Information for a Service in Registry
- Enumerates a service entry from Windows Registry. Will show "hidden services"
```
PS D:\Code\PowerShell\PowerShellTool> .\PowerShellTool -services -serviceName xhunter1
...
```
## Find Services not signed by Microsoft / Launched with another process
- Enumerates services from Windows Registry that are not directly signed by Microsoft
- This does not skip svchost.exe entries. Going to figure out a way to filter out the svchost entries which are from Microsoft.
```
PS D:\Code\PowerShell\PowerShellTool> .\PowerShellTool -servicesNotSigned
...
HKLM:\SYSTEM\CurrentControlSet\Services\xhunter1
    DisplayName : xhunter1
    ImagePath : \??\C:\WINDOWS\xhunter1.sys
    ErrorControl : 1
    Start : 3
    Type : 1
Skipping, Microsoft service
Skipping, Microsoft service
...
```
## Get USB devices
- Returns USB class items with a `Name`, and `DeviceID`
```
PS D:\Code\PowerShell\PowerShellTool> .\PowerShellTool.ps1 -getUSBInfo
...
Name     : USB Input Device
DeviceID : USB\VID_046D&PID_C349&MI_01\7&2DB1E2E3&0&0001
...
```
## Get information for a device ID 
- Returns in-depth information about the driver, service, PNP, authenticode, and other various information about a device ID within a computer.
```
PS D:\Code\PowerShell\PowerShellTool> .\PowerShellTool.ps1 -getDeviceInfo -deviceId "USB\VID_046D&PID_C349&MI_02\7&2DB1E2E3&0&0002"
```

## Get all USB device information 
- Returns `-getDeviceInfo -deviceId` for every Device ID found within `-getUSBInfo`
```
PS D:\Code\PowerShell\PowerShellTool> .\PowerShellTool.ps1 -getAllUSBDeviceInfo
```

## Extract data from an INF file
- Returns driver information for a given INF file.
```
PS D:\Code\PowerShell\PowerShellTool> .\PowerShellTool.ps1 -getINFInfo -filePath C:\Windows\INF\input.inf
```
### [Output log from -getINFInfo -filePath C:\Windows\INF\input.inf](getInfInfo.log)


### Get Device IDs out of an INF file
- This will extract Device IDs from an INF file path
```
PS D:\Code\PowerShell\PowerShellTool> .\PowerShellTool.ps1 -getInfDeviceIds -filePath C:\Windows\INF\input.inf
```

### Get File Security Information
- Gets verbose file security information
```
PS D:\Code\PowerShell\PowerShellTool> .\PowerShellTool.ps1 -getFilePerms -filePath C:\Windows\INF\input.inf
File path found at: C:\Windows\INF\input.inf
Permissions:
Access : System.Security.AccessControl.FileSystemAccessRule System.Security.AccessControl.FileSystemAccessRule System.Security.AccessControl.FileSystemAccessRule System.Security.AccessControl.FileSystemAccessRule System.Security.AccessControl.FileSystemAccessRule System.Security.AccessControl.FileSystemAccessRule
Group : NT SERVICE\TrustedInstaller
Owner : NT SERVICE\TrustedInstaller
Path : Microsoft.PowerShell.Core\FileSystem::C:\Windows\INF\input.inf
Sddl : O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;FA;;;SY)(A;;0x1200a9;;;BA)(A;;0x1200a9;;;BU)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;AC)(A;;0x1200a9;;;S-1-15-2-2)
PSChildName : input.inf
PSDrive : C
PSParentPath : Microsoft.PowerShell.Core\FileSystem::C:\Windows\INF
PSPath : Microsoft.PowerShell.Core\FileSystem::C:\Windows\INF\input.inf
PSProvider : Microsoft.PowerShell.Core\FileSystem
AccessRightType : System.Security.AccessControl.FileSystemRights
AccessRuleType : System.Security.AccessControl.FileSystemAccessRule
AreAccessRulesCanonical : True
AreAccessRulesProtected : True
AreAuditRulesCanonical : True
AuditRuleType : System.Security.AccessControl.FileSystemAuditRule
AccessToString : NT AUTHORITY\SYSTEM Allow  FullControl
BUILTIN\Administrators Allow  ReadAndExecute, Synchronize
BUILTIN\Users Allow  ReadAndExecute, Synchronize
NT SERVICE\TrustedInstaller Allow  FullControl
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadAndExecute, Synchronize
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES Allow  ReadAndExecute, Synchronize
```
### Getting Bluetooth Devices
```
PS D:\Code\PowerShell\PowerShellTool> .\PowerShellTool.ps1 -getBluetoothDevices
```
### Getting Network Profiles
#### REQUIRES ADMIN PRIVILEGES
```
PS D:\Code\PowerShell\PowerShellTool> .\PowerShellTool.ps1 -getNetworkProfiles
```
## Renaming Network Profiles
![](renamed-network-profiles.png)
```
> .\PowerShellTool.ps1 -renameNetworkProfile -npName "Network" -npNameNew "WAN Out"  -npDescNew "Public Internet Connection"
> .\PowerShellTool.ps1 -renameNetworkProfile -npName "Network 2" -npNameNew "LAb LAN"  -npDescNew "Private Internet Connection"
```
## Getting Network Adapter information 
To get all adapter information you can execute this command
```
PS D:\Code\PowerShell\PowerShellTool> .\PowerShellTool.ps1 -getNetworkAdapterInfo
```
To get information for a single adapter
```
PS D:\Code\PowerShell\PowerShellTool> .\PowerShellTool.ps1 -getNetworkAdapterInfo -adapterName "Network Out"
```
## Getting Network Connection Information
### Get TCP connections
```
PS D:\Code\PowerShell\PowerShellTool> .\PowerShellTool.ps1 -getNetworkConnections -netProtocol TCP
```
### Get UDP connections
```
PS D:\Code\PowerShell\PowerShellTool> .\PowerShellTool.ps1 -getNetworkConnections -netProtocol UDP
```
### Get TCP and UDP Connections
```
PS D:\Code\PowerShell\PowerShellTool> .\PowerShellTool.ps1 -getNetworkConnections
```
### Add Service Information 
```
PS D:\Code\PowerShell\PowerShellTool> .\PowerShellTool.ps1 -getNetworkConnections -netGetServiceNames 
```
### Filter for specific services used 
```
PS D:\Code\PowerShell\PowerShellTool> .\PowerShellTool.ps1 -getNetworkConnections -netGetServiceNames -netServiceName 'Encrypting File System (EFS)' 
```
### Get TCP Connections using Encrypting File System on 0.0.0.0
```
PS D:\Code\PowerShell\PowerShellTool> .\PowerShellTool.ps1 -getNetworkConnections -netAddress 0.0.0.0 -netProtocol TCP -netGetServiceNames -netServiceName 'Encrypting File System (EFS)'
Getting TCP Connections
Getting Services
Sorting data

Matches Protocol LocalAddress LocalPort RemoteAddress RemotePort  State ProcessName ProcessId Services
------- -------- ------------ --------- ------------- ----------  ----- ----------- --------- --------
      3 TCP      0.0.0.0          49664 0.0.0.0                0 Listen lsass            1076 Encrypting File System (EFS), CNG Key Isolation, Security Accounts Manager, Credential Manager
```