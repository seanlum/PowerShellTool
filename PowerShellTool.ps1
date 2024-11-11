<#
.SYNOPSIS
    This tool is for collecting and validating information on OS internals for analysis

.DESCRIPTION
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
        Get Verbose info about Network Adapters
        See services in registry
        Validate service installation


.PARAMETER services
    To retrieve system service names. Called with no optional parameters,
    This will retrieve all the registry key names for services in HKLM
        Optional parameters:
            -serviceName <service_name>  - Name of service in registry

.PARAMETER servicesNotSigned
    To go over the services in registry and determine if they are signed
    by Microsoft. Note, this will show all svchost.exe executions and all 
    dllhost.exe executions. This is a work in progress.

.PARAMETER serviceName
    To specify a single service for -services

.PARAMETER getAuthenticode
    To get the authenticode signature for a given file

.PARAMETER hash
    To hash a file using md5, sha1, or sha256
        Required parameters one of [-md5 | -sha1 | -sha256]

.PARAMETER virusTotal
    To query a file on virus total
        Required parameters:
            -vtAPIKey <api_key>     - VirusTotal.com API key
            -vtHash   <file_hash>   - File hash, can be md5, sha1, or sha256
            -vtSigInfo              - To display only the signature information

.PARAMETER getUSBInfo
    To list USB devices and their DeviceIDs


#>
param (
    [Parameter(ParameterSetName = "LogStdOutOnly", Mandatory = $true)]
    [Parameter(ParameterSetName = "Registry", Mandatory = $false)]
    [Parameter(ParameterSetName = "Service", Mandatory = $false)]
    [Parameter(ParameterSetName = "ServiceName", Mandatory = $false)]
    [Parameter(ParameterSetName = "Authenticode", Mandatory = $false)]
    [Parameter(ParameterSetName = "Hash", Mandatory = $false)]
    [Parameter(ParameterSetName = "FilePerms", Mandatory = $true)]
    [Parameter(ParameterSetName = "INFInfo", Mandatory = $true)]
    [Parameter(ParameterSetName = "INFDeviceIds", Mandatory = $false)]
    [Parameter(ParameterSetName = "VirusTotal", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetNetworkAdapters", Mandatory = $false)]
    [Parameter(ParameterSetName = "ServicesNotSigned", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetUSBInfo", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetAllUSBDeviceInfo", Mandatory = $false)]
    [Parameter(ParameterSetName = "DeviceInfo", Mandatory = $false)]
    [Parameter(ParameterSetName = "DriverInfo", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetBluetoothDevices", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetNetworkProfiles", Mandatory = $false)]
    [Parameter(ParameterSetName = "RenameNetworkProfiles", Mandatory = $false)]
    [switch]$logStdOutOnly,
    [Parameter(ParameterSetName = "LogFile", Mandatory = $false)]
    [Parameter(ParameterSetName = "Registry", Mandatory = $false)]
    [Parameter(ParameterSetName = "Service", Mandatory = $false)]
    [Parameter(ParameterSetName = "ServiceName", Mandatory = $false)]
    [Parameter(ParameterSetName = "Authenticode", Mandatory = $false)]
    [Parameter(ParameterSetName = "Hash", Mandatory = $false)]
    [Parameter(ParameterSetName = "FilePerms", Mandatory = $true)]
    [Parameter(ParameterSetName = "INFInfo", Mandatory = $true)]
    [Parameter(ParameterSetName = "INFDeviceIds", Mandatory = $false)]
    [Parameter(ParameterSetName = "VirusTotal", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetNetworkAdapters", Mandatory = $false)]
    [Parameter(ParameterSetName = "ServicesNotSigned", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetUSBInfo", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetAllUSBDeviceInfo", Mandatory = $false)]
    [Parameter(ParameterSetName = "DeviceInfo", Mandatory = $false)]
    [Parameter(ParameterSetName = "DriverInfo", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetBluetoothDevices", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetNetworkProfiles", Mandatory = $false)]
    [Parameter(ParameterSetName = "RenameNetworkProfiles", Mandatory = $false)]
    [switch]$logFileOnly,
    [Parameter(ParameterSetName = "LogFile", Mandatory = $true)]
    [Parameter(ParameterSetName = "Registry", Mandatory = $false)]
    [Parameter(ParameterSetName = "Service", Mandatory = $false)]
    [Parameter(ParameterSetName = "ServiceName", Mandatory = $false)]
    [Parameter(ParameterSetName = "Authenticode", Mandatory = $false)]
    [Parameter(ParameterSetName = "Hash", Mandatory = $false)]
    [Parameter(ParameterSetName = "FilePerms", Mandatory = $true)]
    [Parameter(ParameterSetName = "INFInfo", Mandatory = $true)]
    [Parameter(ParameterSetName = "INFDeviceIds", Mandatory = $false)]
    [Parameter(ParameterSetName = "VirusTotal", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetNetworkAdapters", Mandatory = $false)]
    [Parameter(ParameterSetName = "ServicesNotSigned", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetUSBInfo", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetAllUSBDeviceInfo", Mandatory = $false)]
    [Parameter(ParameterSetName = "DeviceInfo", Mandatory = $false)]
    [Parameter(ParameterSetName = "DriverInfo", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetBluetoothDevices", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetNetworkProfiles", Mandatory = $false)]
    [Parameter(ParameterSetName = "RenameNetworkProfiles", Mandatory = $false)]
    [string]$logFile,
    [Parameter(ParameterSetName = "Registry", Mandatory = $true)]
    [switch]$registry,
    [Parameter(ParameterSetName = "Service", Mandatory = $true)]
    [Parameter(ParameterSetName = "ServiceName", Mandatory = $true)]
    [switch]$services,
    [Parameter(ParameterSetName = "Registry", Mandatory = $true)]
    [Parameter(ParameterSetName = "ServiceName", Mandatory = $false)]
    [string]$regPath,
    [Parameter(ParameterSetName = "Service", Mandatory = $false)]
    [Parameter(ParameterSetName = "ServiceName", Mandatory = $true)]
    [string]$serviceName,
    [Parameter(ParameterSetName = "Authenticode", Mandatory = $true)]
    [switch]$getAuthenticode,
    [Parameter(ParameterSetName = "Hash", Mandatory = $true)]
    [switch]$hash,
    [Parameter(ParameterSetName = "Hash", Mandatory = $false)]
    [switch]$sha256,
    [Parameter(ParameterSetName = "Hash", Mandatory = $false)]
    [switch]$sha1,
    [Parameter(ParameterSetName = "Hash", Mandatory = $false)]
    [switch]$md5,
    [Parameter(ParameterSetName = "Hash", Mandatory = $true)]
    [Parameter(ParameterSetName = "Authenticode", Mandatory = $true)]
    [Parameter(ParameterSetName = "FilePerms", Mandatory = $true)]
    [Parameter(ParameterSetName = "INFInfo", Mandatory = $true)]
    [Parameter(ParameterSetName = "INFDeviceIds", Mandatory = $true)]
    [string]$filePath,
    [Parameter(ParameterSetName = "FilePerms", Mandatory = $true)]
    [switch]$getFilePerms,
    [Parameter(ParameterSetName = "VirusTotal", Mandatory = $true)]
    [switch]$virusTotal,
    [Parameter(ParameterSetName = "VirusTotal", Mandatory = $false)]
    [switch]$vtSigInfo,
    [Parameter(ParameterSetName = "VirusTotal", Mandatory = $true)]
    [string]$vtAPIKey,
    [Parameter(ParameterSetName = "VirusTotal", Mandatory = $true)]
    [string]$vtHash,
    [Parameter(ParameterSetName = "ServicesNotSigned", Mandatory = $true)]
    [switch]$servicesNotSigned,
    [Parameter(ParameterSetName = "GetUSBInfo", Mandatory = $true)]
    [switch]$getUSBInfo,
    [Parameter(ParameterSetName = "GetAllUSBDeviceInfo", Mandatory = $true)]
    [switch]$getAllUSBDeviceInfo,
    [Parameter(ParameterSetName = "DeviceInfo", Mandatory = $true)]
    [switch]$getDeviceInfo,
    [Parameter(ParameterSetName = "DriverInfo", Mandatory = $true)]
    [switch]$getDriverInfo,
    [Parameter(ParameterSetName = "DriverInfo", Mandatory = $true)]
    [Parameter(ParameterSetName = "DeviceInfo", Mandatory = $true)]
    [string]$deviceId,
    [Parameter(ParameterSetName = "INFInfo", Mandatory = $true)]
    [switch]$getInfInfo,
    [Parameter(ParameterSetName = "INFDeviceIds", Mandatory = $true)]
    [switch]$getInfDeviceIds,
    [Parameter(ParameterSetName = "GetBluetoothDevices", Mandatory = $true)]
    [switch]$getBluetoothDevices,
    [Parameter(ParameterSetName = "GetNetworkProfiles", Mandatory = $true)]
    [switch]$getNetworkProfiles,
    [Parameter(ParameterSetName = "GetNetworkAdapters", Mandatory = $true)]
    [switch]$getNetworkAdapterInfo,
    [Parameter(ParameterSetName = "GetNetworkAdapters", Mandatory = $false)]
    [string]$adapterName,
    [switch]$adapterDriverInfo,
    [Parameter(ParameterSetName = "RenameNetworkProfiles", Mandatory = $true)]
    [switch]$renameNetworkProfile,
    [Parameter(ParameterSetName = "RenameNetworkProfiles", Mandatory = $true)]
    [string]$npName,
    [Parameter(ParameterSetName = "RenameNetworkProfiles", Mandatory = $true)]
    [string]$npNameNew,
    [Parameter(ParameterSetName = "RenameNetworkProfiles", Mandatory = $false)]
    [string]$npDescNew
)

$networkProfilesRegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\"
$barLine =  "================================================================================="
function Write-OutputLog {
    param (
        [Parameter(Mandatory = $false)]
        [string]$Prefix = "",
        
        [Parameter(ValueFromRemainingArguments = $true)]
        [object[]]$Args
    )
    
    # Concatenate all arguments into a single line and remove extra whitespace
    $output = ($Args -join " ").Trim()
    $finalOutput = "$Prefix$output"
    
    if ($logStdOutOnly) {
        # Write to console
        Write-Host $finalOutput
    } elseif ($logFileOnly) {
        # If -LogToFile is specified, write to the specified log file
        if ($logFile) {
            # Ensure the path is valid and write output to file
            $finalOutput | Out-File -FilePath $logFile -Append -Encoding utf8
        }
    } else {
        Write-Host $finalOutput
        if ($logFile) {
            # Ensure the path is valid and write output to file
            $finalOutput | Out-File -FilePath $logFile -Append -Encoding utf8
        }
    }
}

function Write-OutputCapture {
    param([object]$InputObject)
    $outputString = $InputObject | Out-String
    Write-OutputLog $outputString
}

function Get-PropertiesTwoLevelsDeep {
    param (
        [Parameter(Mandatory=$true)]
        [object]$InputObject,
        
        [int]$IndentLevel = 0,  # Used for formatting output
        [int]$MaxDepth = 2      # Maximum depth of recursion
    )
    
    # Helper function to create indented output
    function Write-Indented {
        param (
            [string]$Text,
            [int]$Level
        )
        Write-OutputLog (" " * $Level * $MaxDepth) $Text
    }

    # Get the properties of the input object
    $properties = $InputObject | Get-Member -MemberType Properties

    foreach ($property in $properties) {
        $propertyName = $property.Name
        try {
            $propertyValue = $InputObject.$propertyName
        } catch {
            # Skip properties that can't be accessed
            continue
        }
        if ($propertyValue) {
            # Print the property name and value
            Write-Indented "$propertyName : $propertyValue" $IndentLevel -No

            # Recursively check if the current depth is less than the maximum depth
            if ($IndentLevel -lt ($MaxDepth - 1) -and
                $propertyValue -is [System.Collections.IEnumerable] -and
                $propertyValue -notlike [string]) {
                foreach ($item in $propertyValue) {
                    # Recursively call the function if the property is an object with its own properties
                    Get-PropertiesTwoLevelsDeep -InputObject $item -IndentLevel ($IndentLevel + 1) -MaxDepth $MaxDepth
                }
            }
        }
    }

    return $properties
}

# Function to verify driver signature
function Verify-FileSignature {
    param ($filePath)
    Write-OutputLog "Verifying driver signature for $filePath..."
    Get-ChildItem -Path "C:\Windows\System32\DriverStore\FileRepository\" -Recurse | Where-Object { $_.Name -like $filePath } | ForEach-Object {
        $signature = Get-AuthenticodeSignature -FilePath $_.FullName
        Write-OutputLog "Driver Path: " $_.FullName
        if ($signature.Status -eq 'Valid') {
            Write-OutputLog "Driver Valid: Driver signature is valid."
        } else {
            Write-OutputLog "Driver Valid: Driver signature is invalid or not found!"
        }
    }
}

# Function to check the driver file with VirusTotal or antivirus (mocked here)
function Analyze-DriverFile {
    param ($driverFilePath)
    Write-OutputLog "Analyzing driver file: $driverFilePath..."
    # Here, you could upload to VirusTotal or run an antivirus scan on the file
    # Example mock result:
    Write-OutputLog "Virus scan recommended for $driverFilePath. Ensure it’s clean."
}

function Get-Perms {
    param([string]$filePath)
    if (Test-Path $filePath) {
        $permissions = Get-Acl -Path $filePath
        Write-OutputLog "File path found at: "$filePath
        if ($permissions) {
            Write-OutputLog "Permissions:"
            Get-PropertiesTwoLevelsDeep -InputObject $permissions -MaxDepth 1
        } else {
            Write-OutputLog "Could not find permissions"
        }
        
    } else {
        Write-OutputLog "File not found at the expected path: $filePath"
    }
}

# Function to check file installation path and permissions
function Get-FSPerms {
    param ($filePath)
    Write-OutputLog ""
    Write-OutputLog "Checking file installation path and permissions for $filePath..."
    Get-ChildItem -Path "C:\Windows\System32\DriverStore\FileRepository\" -Recurse | Where-Object { $_.Name -like $filePath } | ForEach-Object {
        Get-Perms -filePath $_.FullName
    }
}

function Get-PnPInfo {
    if ($deviceId -and $getDeviceInfo) {
        Write-OutputLog "Getting PnP Device Information: " $tempvid
        $pnpDevice = Get-PnpDevice -InstanceId $deviceId
        Get-PropertiesTwoLevelsDeep $pnpDevice -MaxDepth 1

        # Extract relevant information
        $hardwareId = ($device | Where-Object { $_.KeyName -eq "DEVPKEY_Device_HardwareIds" }).Data
        $compatibleId = ($device | Where-Object { $_.KeyName -eq "DEVPKEY_Device_CompatibleIds" }).Data

        # Display the IDs
        Write-OutputLog "HardwareID: $hardwareId"
        Write-OutputLog "CompatibleID: $compatibleId"

        # Check for known device types
        if ($hardwareId -match "Class_03&SubClass_01") {
            Write-OutputLog "Device Type: Likely a Keyboard"
        }
        elseif ($hardwareId -match "Class_03&SubClass_02") {
            Write-OutputLog "Device Type: Likely a Mouse"
        }
        elseif ($hardwareId -match "Class_06") {
            Write-OutputLog "Device Type: Likely a Camera (Imaging Class)"
        }
        elseif ($compatibleId -match "USBSTOR") {
            Write-OutputLog "Device Type: Likely a USB Storage Device"
        }
        else {
            Write-OutputLog "Device Type: General HID or Unknown"
        }
    }
}

# Function to cross-reference device IDs
function CrossReference-DeviceIDs {
    param ([string]$infFilePath)
    Write-OutputLog "Cross-referencing device IDs in the INF file..."
    $infFileContent = Get-Content -Path $infFilePath -Raw
    $hardwareIdRegex = "(USB|PCI|ACPI|HID)\\VID_[A-Fa-f0-9]{4}(&PID_[A-Fa-f0-9]{4}(&MI_[A-Fa-f0-9]{2})?)?"
    $matches = [regex]::Matches($infFileContent, $hardwareIdRegex)
    $foundVIDs = $matches | Sort-Object -Unique

    $vids = $($foundVIDs -join ', ')
    Write-OutputLog "Found driver supported device IDs: "$vids
}

# Function to validate service installation
function Validate-ServiceInstallation {
    param ($serviceName)
    Write-OutputLog ""
    Write-OutputLog "Validating service installation for $serviceName..."
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service) {
        Write-OutputLog "Service $serviceName is installed. Status: $($service.Status)"
        Get-PropertiesTwoLevelsDeep $service -MaxDepth 1
    } else {
        Write-OutputLog "Service $serviceName is not found."
    }
}

# Function to review event logs for driver installation
function Review-DriverEventLogs {
    param ($driverFileName)
    Write-OutputLog "Reviewing event logs for driver installation..."
    Get-WinEvent -LogName System | Where-Object {
        $_.Message -match $driverFileName -and $_.Id -eq 7045
    } | Format-Table -Property TimeCreated, Id, LevelDisplayName, Message -AutoSize
}

function Get-INFData {
    param([string] $infFilePath)
    Write-OutputLog $infFilePath
    if ($infFilePath) {
        if (Test-Path -Path $infFilePath) {
            Write-OutputLog "Continuing"
        } else {
            return
        }
    } else {
        return
    }
    # Initialize variables
    $driverFileNames = @()
    $driverFileName = ""
    $catalogFileName = ""
    $driverDate = ""
    $driverVersion = ""
    $deviceVIDs = @()
    $serviceNames = @()

    # Read the INF file contents
    $infFileContent = Get-Content -Path $infFilePath


    # Parse each line in the INF file
    foreach ($line in $infFileContent) {
        # Check for driver version and date
        if ($line -match "^DriverVer\s*=\s*([0-9/]+),(.+)$") {
            $driverDate = $matches[1].Trim()
            $driverVersion = $matches[2].Trim()
        }

        # Check for catalog file
        elseif ($line -match "^CatalogFile\s*=\s*(.+)$") {
            $catalogFileName = $matches[1].Trim()
        }

        # Check for driver file in [SourceDisksFiles] section
        elseif ($line -match "^\s*(sshid\.sys)\s*=") {
            $driverFileName = $matches[1].Trim()
        }

        # Check for all .sys files in [SourceDisksFiles] section
        elseif ($line -match "^\s*(\S+\.sys)\s*=") {
            $sysFile = $matches[1].Trim()
            if ($driverFileNames -notcontains $sysFile) {
                $driverFileNames += $sysFile
            }
        }

        # Collect any hardware ID in a similar format, like USB\VID_xxxx&PID_xxxx
        elseif ($line -match "(USB|PCI|ACPI|HID)\\(VID|VEN|DEV|PID)_\w+&[A-Z0-9]+") {
            $hardwareID = $matches[0].Trim()
            if ($deviceVIDs -notcontains $hardwareID) {
                $deviceVIDs += $hardwareID
            }
        }

        # Collect service names in [Services] section
        elseif ($line -match "^AddService\s*=\s*([^,]+)") {
            $serviceName = $matches[1].Trim()
            if ($serviceNames -notcontains $serviceName) {
                $serviceNames += $serviceName
            }
        }
    }

    # Define driver directory path (may vary depending on installation)
    $driverDirectory = "C:\Windows\System32\DriverStore\FileRepository"
    Write-OutputLog "Analyzing $infFilePath"
    # Output the parsed information
    Write-OutputLog "Driver File Name: $($driverFileNames -join ', ')" 
    Write-OutputLog "Catalog File Name: $catalogFileName"
    Write-OutputLog "Driver Date: $driverDate"
    Write-OutputLog "Driver Version: $driverVersion"
    Write-OutputLog "Device VIDs: $($deviceVIDs -join ', ')"
    Write-OutputLog "Service Names: $($serviceNames -join ', ')"
    Write-OutputLog ""
    Write-OutputLog ""

    # Variables used in the forensic analysis script
    #$catalogFilePath = Join-Path -Path $driverDirectory -ChildPath $catalogFileName
    #$driverFilePath = Join-Path -Path $driverDirectory -ChildPath $driverFileName

    # Run all checks
    Verify-FileSignature -filePath $catalogFilePath

    foreach ($checkPath in $driverFileNames) {
        Analyze-DriverFile -driverFilePath $checkPath
        Write-OutputLog ""
        Verify-FileSignature -filePath $checkPath
        Write-OutputLog "Driver Permissions"
        Get-FSPerms -filePath $checkPath

    }
    Write-OutputLog ""
    CrossReference-DeviceIDs -infFilePath $infFilePath -deviceVIDs $deviceVIDs
    Write-OutputLog ""
    $serviceNames | ForEach-Object { Validate-ServiceInstallation -serviceName $_ }
    # Review-DriverEventLogs -driverFileName $driverFileName
}

function Get-NetworkAdapterInfo {
    param($adapter)
    #Write-OutputLog ""
    #Write-OutputLog "Getting info for "$($adapter.Name)
    #Write-OutputLog $barLine

    if ($adapterDriverInfo) {
        $adapterProperties = Get-PropertiesTwoLevelsDeep $adapter -MaxDepth 1
        Write-OutputLog $barLine
        Write-OutputLog ""
        $macAddress = $($adapter.MacAddress -replace '-', ':')
        $wmiInfo = Get-WmiObject -Class Win32_NetworkAdapter | Where-Object {$_.MACAddress -eq $macAddress}
        Write-OutputLog $barLine
        Write-OutputLog ""
        Write-OutputLog "Network Adapter Information"
        $wmiProperties = Get-PropertiesTwoLevelsDeep $wmiInfo -MaxDepth 1
        $cimInstance = Get-CimInstance -ClassName Win32_NetworkAdapter | Where-Object {$_.MACAddress -eq $macAddress}
        Write-OutputLog $barLine
        Write-OutputLog ""
        Write-OutputLog "CIM Instance Properties"
        $cimInstanceProperties = Get-PropertiesTwoLevelsDeep $cimInstance -MaxDepth 1
        Write-OutputLog $barLine
        Write-OutputLog ""
        $ipAddresses = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex
        foreach ($ipAddress in $ipAddresses) {
            Write-OutputLog $barLine
            Write-OutputLog "IP Address properties for " $($ipAddress.IPAddress)
            $ipAddressProperties = Get-PropertiesTwoLevelsDeep $ipAddress -MaxDepth 1
            Write-OutputLog $barLine
            Write-OutputLog ""
        }
        $routes = Get-NetRoute -InterfaceIndex $adapter.InterfaceIndex | Format-Table -AutoSize
        Write-OutputCapture -InputObject $routes
        Write-OutputLog $barLine
        $deviceId = $($adapter.PNPDeviceID)
        Get-DriverInfo
    } else {
        Write-OutputLog $barLine
        $properties = Get-PropertiesTwoLevelsDeep $adapter -MaxDepth 1
    }
}

function Get-NetworkAdaptersInfo {
    $adapters = $(Get-NetAdapter)
    foreach ($adapterInfo in $adapters) {
        if ($adapterName) {
            if ($adapterName -eq $adapterInfo.Name) {
                Get-NetworkAdapterInfo -adapter $adapterInfo
            }
        } else {
            Get-NetworkAdapterInfo -adapter $adapterInfo
        }
    }
}

function Get-NetworkProfile {
    param ([string]$profileName)
    $regKeys = Get-ChildItem -Path $networkProfilesRegPath | Select-Object -ExpandProperty PSChildName
    $foundGuid = $null
    foreach ($profileGuid in $regKeys) {
        $fullPath = "$networkProfilesRegPath$profileGuid" -replace "HKEY_LOCAL_MACHINE", "HKLM:\"
        $details = $(Get-ItemProperty -Path $fullPath)
        if ($details.ProfileName -eq $profileName) {
            $foundGuid = $profileGuid
        } 
    }
    return $foundGuid
}

function Remove-NetworkProfile {

    if ($removeNetworkProfile -and -$npName) {
        $foundGuid = Get-NetworkProfile -profileName $npName
        $fullPath = "$networkProfilesRegPath$profileGuid" -replace "HKEY_LOCAL_MACHINE", "HKLM:\"
        if ($profileGuid) {
            if (Test-Path -Path $fullPath) {
                Remove-Item -Path $fullPath
            }
        }
    }

}

function Rename-NetworkProfile {
    if ($renameNetworkProfile -and $npName -and ($npNameNew -or $npDescNew) ) {
        $profileGuid = Get-NetworkProfile -profileName $npName
        $fullPath = "$networkProfilesRegPath$profileGuid" -replace "HKEY_LOCAL_MACHINE", "HKLM:\"
        if ($profileGuid) {
            if (Test-Path -Path $fullPath) {
                if ($npNameNew) {
                    if ((Get-ItemProperty -Path $fullPath -Name "ProfileName" -ErrorAction SilentlyContinue) -ne $null) {
                        Set-ItemProperty -Path $fullPath -Name "ProfileName" -Value $npNameNew
                        Get-Item -Path $fullPath | Format-Table
                    } else {
                        "Profile name does not exist"
                    }
                }
                if ($npDescNew) {
                    if ((Get-ItemProperty -Path $fullPath -Name "Description" -ErrorAction SilentlyContinue) -ne $null) {
                        Set-ItemProperty -Path $fullPath -Name "Description" -Value $npDescNew
                        Get-Item -Path $fullPath | Format-Table
                    } else {
                        "Profile description does not exist"
                    }
                }

            }
        } else {
            Write-OutputLog "Could not find network profile by name"
        }
        
    }
}

function Get-NetworkProfiles {
    $regKeys = Get-ChildItem -Path $networkProfilesRegPath | Select-Object -ExpandProperty PSChildName
    foreach ($profileGuid in $regKeys) {
        $fullPath = "$networkProfilesRegPath$profileGuid" -replace "HKEY_LOCAL_MACHINE", "HKLM:\"
        Write-OutputLog $profileGuid
        $details = $(Get-ItemProperty -Path $fullPath)
        Write-OutputLog "    Name: "$details.ProfileName
        Write-OutputLog "    Description: "$details.Description
        $profile = Get-NetworkProfile -profileGuid $profileGuid
    }
}

# Define the C# code to import necessary Windows API functions
$code = @"
using System;
using System.Text;
using System.Runtime.InteropServices;

public class ResourceLoader
{
    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    public static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    public static extern bool FreeLibrary(IntPtr hModule);

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int LoadString(IntPtr hInstance, uint uID, StringBuilder lpBuffer, int nBufferMax);
}
"@

# Add the C# code to PowerShell
Add-Type -TypeDefinition $code -Language CSharp

# Function to expand a resource string
function Expand-ResourceString {
    param (
        [string]$resourcePath
    )

    # Extract the DLL path and the resource ID
    if ($resourcePath -match '^@(.*?),(.*)') {
        $dllPath = $matches[1] -replace "%SystemRoot%", $Env:SystemRoot
        $resourceID = [int]$matches[2] -as [uint32]

        # Load the DLL
        $hModule = [ResourceLoader]::LoadLibrary($dllPath)
        if ($hModule -eq [IntPtr]::Zero) {
            Write-OutputLog "Failed to load library: $dllPath"
            returns
        }

        # Load the string resource
        $buffer = New-Object System.Text.StringBuilder 256
        $result = [ResourceLoader]::LoadString($hModule, $resourceID, $buffer, $buffer.Capacity)
        
        # Free the DLL
        [ResourceLoader]::FreeLibrary($hModule)

        # Check if the string was loaded successfully
        if ($result -gt 0) {
            return $buffer.ToString()
        } else {
            Write-OutputLog "Failed to load resource string: ID $resourceID"
        }
    } else {
        Write-OutputLog "Invalid resource path format"
    }
}

function Is-DLLImport {
    param(
        [string]$importPath
    )

    # Adjusted regular expression to match a more flexible path pattern
    $regex = '^@[a-zA-Z0-9%\\]+\\[^,]+\.dll,-\d+$'
    # Test if the string matches the format
    if ($importPath -match $regex) {
        return $true
    } else {
        return $false
    }
}


function Is-MicrosoftSigned {
    param([string]$imagePath)
    # Resolve to a full path if necessary
    if ($imagePath -like "\SystemRoot\*") {
        $fullPath = $imagePath -replace "\\SystemRoot", $Env:SystemRoot
    } elseif ($imagePath -like "System32\*") {
        $fullPath = $imagePath -replace "^System32", "C:\Windows\System32\"
    } else {
        $fullPath = $imagePath
    }

    # Check if the file exists before verifying
    try { 
        if (Test-Path -Path $fullPath) {
            # Check the digital signature
            $signature = Get-AuthenticodeSignature -FilePath $fullPath

            # Determine if the signer is Microsoft
            if ($signature.SignerCertificate.Subject -match "CN=Microsoft") {
                return 1
            } else {
                return 0
            }
        } else {
            return 2
        }
    }
    catch [System.Exception] {
        return 2
    }
}

function Get-USBInfo {
    $usbDevices = Get-WmiObject Win32_PnPEntity | Where-Object { $_.DeviceID -match '^USB' } | Select-Object Name, DeviceID
    return $usbDevices
}

function Search-Directory {
    param([string]$inputPath,
          [string]$fileName)
    if ($fileName -and (Test-Path -Path $inputPath)) {
        $files = Get-ChildItem -Path $inputPath | Where-Object { $_.Name -like "$fileName" } | ForEach-Object { Get-INFData -infFilePath $_.FullName }
    }
}

function Get-DriverInfo {
    if ($deviceId) {
        # Replace "YOUR_DEVICE_INSTANCE_ID" with the actual InstanceId from Get-PnpDevice
        $deviceInfo = Get-WmiObject Win32_PnPSignedDriver | Where-Object { $_.DeviceID -eq $deviceId } | Select-Object DeviceName, DriverVersion, Manufacturer, DriverProviderName, InfName
        Write-OutputLog "Device Info"
        $driverProperties = Get-PropertiesTwoLevelsDeep $deviceInfo -MaxDepth 1
        $fileName = [System.IO.Path]::GetFileNameWithoutExtension($deviceInfo.InfName)
        $driverDirectories = @(
            "C:\Windows\System32\DriverStore\FileRepository\",
            "C:\Windows\INF\",
            "C:\Windows\System32\drivers\",
            "C:\Windows\System32\spool\drivers\",
            "C:\Windows\System32\DriverStore\Temp\",
            "C:\Windows\System32\DRVSTORE\",
            "$env:SystemRoot\OEMDrv\"  # Use environment variable for dynamic system root
        )
        foreach ($driversDir in $driverDirectories) {
            $infPath =  $(Search-Directory -inputPath $driversDir -fileName $($deviceInfo.InfName))
        }
    }
    
}

function Get-FirmwareInfo {
    if ($deviceId -and $getDeviceInfo) {
        # Replace "YOUR_DEVICE_INSTANCE_ID" with the actual InstanceId from Get-PnpDevice
        $deviceInfo = Get-WmiObject Win32_PnPEntity | Where-Object { $_.DeviceID -like $deviceId } | Select-Object Name, DeviceID, Description
        return $deviceInfo
    }
}

function Get-BluetoothDevices {
    return Get-PnpDevice -Class Bluetooth
}

$servicePath = "HKLM:\SYSTEM\CurrentControlSet\Services"
if ($services) {
    $inputPath = $servicePath
} else {
    $inputPath = $regPath
}
if ($serviceName) {
    $inputPath = "$inputPath\$serviceName"
}

if ($virusTotal) {
    if ($vtHash) {
        # VirusTotal API URL for hash lookup
        $vtApiUrl = "https://www.virustotal.com/api/v3/files/{0}" -f $(echo $fileHash)

        # Set up headers with the API key
        $headers = @{
            "x-apikey" = $vtAPIKey
        }
        Write-OutputLog $vtApiUrl
        $response = Invoke-RestMethod -Uri $vtApiUrl -Headers $headers -Method Get
        if ($vtSigInfo) {
            $response.data.attributes.signature_info | Format-List
        } else {
            $response.data | Format-List
        }
    }
} elseif ($hash) {
    if ($filePath) {
        if ($sha256) {
            $hashAlgol = 'SHA256'
        } elseif ($sha1) {
            $hashAlgol = 'SHA1'
        } elseif ($md5) {
            $hashAlgol = 'MD5'
        }
        if ($hashAlgol) {
             $fileHash = (Get-FileHash -Path $filePath -Algorithm SHA256).Hash
            $fileHash | Format-List
        } else {
            Write-OutputLog "Please supply a hash algorithm"
        }
       
    } else {
        Write-OutputLog "Please supply a path"
    }
} elseif ($getAuthenticode) {
    Write-OutputLog "Authenticode"
    if ($filePath) {
        $signature = Get-AuthenticodeSignature -FilePath $filePath
        $signature | Format-List
    } else {
        Write-OutputLog "Please supply an input path"
    }
} elseif ($services -or $registry) {
    Write-OutputLog "Services"
    if ($serviceName) {
        Write-OutputLog $inputPath
        $registryKey = Get-Item $inputPath
        $registryKey | Format-List
        Write-OutputLog "Service Registry Properties"
        $itemProperties = Get-ItemProperty -Path $inputPath 
        $itemProperties | Format-List
    } else {
        $subKeyNames = Get-ChildItem -Path $inputPath | Select-Object -ExpandProperty PSChildName
        $subKeyNames | Format-List
    }
} elseif ($servicesNotSigned) {
    $serviceNames = Get-ChildItem -Path $servicePath | Select-Object -ExpandProperty PSChildName
    foreach ($subkey in $serviceNames) {
        $properties = Get-Item "$servicePath\$subkey"
        if ($properties.Property.Count -gt 0) {
            # Loop through each item in the Property array and display details
            $mssignedIgnore = 3
            if ($properties.Property -contains "ImagePath") {
                $imagePathValue = (Get-ItemProperty -Path "$servicePath\$subkey" -Name "ImagePath").ImagePath
                $mssignedIgnore = $(Is-MicrosoftSigned -imagePath $imagePathValue)
                if ($mssignedIgnore -eq 1) {
                    Write-OutputLog "Skipping, Microsoft service"

                }
            }
            if ($mssignedIgnore -ne 1) {
                Write-OutputLog "$servicePath\$subkey"
                foreach ($prop in $properties.Property) {
                    # Get the value of each property
                    $propValue = Get-ItemProperty -Path "$servicePath\$subkey" -Name $prop
                    if ($prop) {
                        $outputProp = $($propValue.$prop)
                        Write-OutputLog "    $prop : $outputProp"
                    }
                }
            }
            
        } else {
            #Write-OutputLog "$servicePath\$subkey"
            #Write-OutputLog "Property : {}"
        }
    }
} elseif ($getUSBInfo) {
    Get-USBInfo | Format-List
} elseif ($getAllUSBDeviceInfo) {
    foreach ($device in Get-USBInfo) {
       Write-OutputLog "========================================================================="
       Write-OutputLog "Getting Information for: " $device.DeviceId
       $getDeviceInfo = $true
       $deviceId = $device.DeviceId
       Get-DriverInfo | Format-List
       # Get-FirmwareInfo | Format-List
       Get-PnPInfo | Format-List 
       Write-OutputLog "========================================================================="
       # Get-PropertiesTwoLevelsDeep $device -MaxDepth 1
    }
} elseif ($getDeviceInfo) {
    Get-DriverInfo | Format-List
    Get-PropertiesTwoLevelsDeep $(Get-FirmwareInfo) -MaxDepth 1
    Get-PnPInfo | Format-List
} elseif ($getDriverInfo) {
    Get-DriverInfo | Format-List
} elseif ($getInfInfo) {
    if ($filePath) {
        Get-INFData -infFilePath $filePath
    }
} elseif ($getInfDeviceIds) {
    if ($filePath) {
        CrossReference-DeviceIDs -infFilePath $filePath
    }
} elseif ($getFilePerms) {
    if ($filePath) {
        Get-Perms -filePath $filePath
    }
} elseif ($getBluetoothDevices) {
    Get-BluetoothDevices | Format-List
} elseif ($getNetworkProfiles) {
    Get-NetworkProfiles
} elseif ($renameNetworkProfile) {
    Rename-NetworkProfile
} elseif ($getNetworkAdapterInfo) {
    Get-NetworkAdaptersInfo
}
