# PowerShellTool
A tool which uses PowerShell to provide analysis-level details about different parts of Windows 

### Example
```
.\PowerShellTool.ps1 -logFileOnly -logFile '.\Network-Details.txt' -getNetworkAdapterInfo -adapterName 'Network' -adapterDriverInfo
```

### Help Output
[Get-Help .\PowerShellTool.ps1](./media/help-output-111020240828PST.txt)

## Renaming Network Profiles
![](./media/renamed-network-profiles.png)
```
> .\PowerShellTool.ps1 -renameNetworkProfile -npName "Network" -npNameNew "WAN Out"  -npDescNew "Public Internet Connection"
> .\PowerShellTool.ps1 -renameNetworkProfile -npName "Network 2" -npNameNew "LAb LAN"  -npDescNew "Private Internet Connection"
```
### Note: After the command:
- Disable and re-enable the network adapter for the changes
- Have not tried just using `ipconfig /renew` with it yet

```
Type Tree 
NetAdapter (MSFT_NetAdapter)
    Win32_NetworkAdapter

```