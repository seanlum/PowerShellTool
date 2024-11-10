# PowerShellTool
A tool which uses PowerShell to provide analysis-level details about different parts of Windows 

```shell
> Get-Help .\PowerShellTool.ps1 -Full

NAME
    PowerShellTool.ps1

SYNOPSIS
    This tool is for collecting and validating information on OS internals for analysis


SYNTAX
    PowerShellTool.ps1 -logStdOutOnly [<CommonParameters>]

    PowerShellTool.ps1 [-logFileOnly] -logFile <String> [<CommonParameters>]

    PowerShellTool.ps1 -registry -regPath <String> [<CommonParameters>]

    PowerShellTool.ps1 -services [-regPath <String>] -serviceName <String> [<CommonParameters>]

    PowerShellTool.ps1 -services [-serviceName <String>] [<CommonParameters>]

    PowerShellTool.ps1 -getAuthenticode -filePath <String> [<CommonParameters>]

    PowerShellTool.ps1 -hash [-sha256] [-sha1] [-md5] -filePath <String> [<CommonParameters>]

    PowerShellTool.ps1 -filePath <String> -getInfDeviceIds [<CommonParameters>]

    PowerShellTool.ps1 -filePath <String> -getInfInfo [<CommonParameters>]

    PowerShellTool.ps1 -filePath <String> -getFilePerms [<CommonParameters>]

    PowerShellTool.ps1 -virusTotal [-vtSigInfo] -vtAPIKey <String> -vtHash <String> [<CommonParameters>]

    PowerShellTool.ps1 -servicesNotSigned [<CommonParameters>]

    PowerShellTool.ps1 -getUSBInfo [<CommonParameters>]

    PowerShellTool.ps1 -getAllUSBDeviceInfo [<CommonParameters>]

    PowerShellTool.ps1 -getDeviceInfo -deviceId <String> [<CommonParameters>]

    PowerShellTool.ps1 -getDriverInfo -deviceId <String> [<CommonParameters>]

    PowerShellTool.ps1 -getBluetoothDevices [<CommonParameters>]

    PowerShellTool.ps1 -getNetworkProfiles [<CommonParameters>]

    PowerShellTool.ps1 -renameNetworkProfile -npName <String> -npNameNew <String> [-npDescNew <String>] [<CommonParameters>]


DESCRIPTION
    Documentation is in progress of being built!
    The parameter sets are working.

    This tool can:
        Check Virus Total Signature information by MD5, SHA1, and SHA256
            - Requires API Key
        Get file hashes in MD5, SHA1, and SHA256
        Check Bluetooth Devices
        Check USB Devices
            - Get possible device names for connection instances
            - Show all USB devices
            - Show detailed info for all drivers
            - Check FS permissions for driver files
        Check File Authenticode Signatures
        View Network Profiles
            - It can rename network profiles
            - It can rename network profile descriptions
        See services in registry
        Validate service installation


PARAMETERS: 

    *** IN PROGRESS OF BEING WRITTEN *** 

    <CommonParameters>
        This cmdlet supports the common parameters: Verbose, Debug,
        ErrorAction, ErrorVariable, WarningAction, WarningVariable,
        OutBuffer, PipelineVariable, and OutVariable. For more information, see
        about_CommonParameters (https:/go.microsoft.com/fwlink/?LinkID=113216).

INPUTS

OUTPUTS


RELATED LINKS
```