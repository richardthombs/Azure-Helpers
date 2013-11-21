Function New-WebServer
{
    Param
    (
        [Parameter(Mandatory=$True)]
        [string]$ServiceName,

        [string]$Name = $ServiceName,

        [Parameter(Mandatory=$True)]
        [string]$AffinityGroup,

        [Parameter(Mandatory=$True)]
        [string]$AdminUsername,

        [Parameter(Mandatory=$True)]
        [string]$Password,

        [Parameter(Mandatory=$True)]
        [string]$VNetName,

        [Parameter(Mandatory=$True)]
        [string]$SubnetName,

        [string]$AvailabilitySetName = $ServiceName,

        [string]$InstanceSize = "Small",

        [string]$ImageFamilyName = "Windows Server 2012 R2 Datacenter"
    )

    $webImage = Get-LatestVMImage -FamilyName $ImageFamilyName
    Install-Server -Name $Name -ServiceName $ServiceName -ImageName $webImage -InstanceSize $InstanceSize -AffinityGroup $AffinityGroup -AvailabilitySetName $ServiceName -AdminUsername $AdminUserName -Password $Password -VNetName $VNetName -SubnetNames $SubnetName
    Initialize-Server -ServiceName $ServiceName -Name $Name -AdminUsername $AdminUserName -Password $Password
    Initialize-WebServer -ServiceName $ServiceName -Name $Name -AdminUsername $AdminUserName -Password $Password
}

Function New-SqlServer
{
    Param
    (
        [Parameter(Mandatory=$True)]
        [string]$ServiceName,

        [string]$Name = $ServiceName,

        [Parameter(Mandatory=$True)]
        [string]$AffinityGroup,

        [Parameter(Mandatory=$True)]
        [string]$AdminUsername,

        [Parameter(Mandatory=$True)]
        [string]$Password,

        [Parameter(Mandatory=$True)]
        [string]$VNetName,

        [Parameter(Mandatory=$True)]
        [string]$SubnetName,

        [string]$AvailabilitySetName = $ServiceName,

        [string]$InstanceSize = "Medium",

        [int]$NumberOfDisks = 4,

        [int]$DatabaseVolumeSizeInGb = 500,

        [string]$ImageFamilyName = "SQL Server 2012 SP1 Standard on Windows Server 2012"
    )

    $sqlImage = Get-LatestVMImage -ImageFamily $ImageFamilyName
    Install-Server -Name $Name -ServiceName $ServiceName -ImageName $sqlImage -InstanceSize $InstanceSize -AffinityGroup $AffinityGroup -AvailabilitySetName $ServiceName -AdminUsername $AdminUserName -Password $Password -VNetName $VNetName -SubnetNames $SubnetName
    Get-AzureVM -Name $Name -ServiceName $ServiceName | Add-DataDisks -TotalSizeInGb $DatabaseVolumeSizeInGb -NumberOfDisks $NumberOfDisks | Update-AzureVM
    Initialize-Server -ServiceName $ServiceName -Name $Name -AdminUsername $AdminUserName -Password $Password
    Initialize-SqlServer -ServiceName $ServiceName -Name $Name -AdminUsername $AdminUserName -Password $Password
}

Function Install-Server
{
    Param(
        [Parameter(Mandatory=$True)]
        [string]$Name,

        [Parameter(Mandatory=$True)]
        [string]$ImageName,

        [Parameter(Mandatory=$True)]
        [string]$ServiceName = $Name,

        [Parameter(Mandatory=$True)]
        [string]$AffinityGroup,

        [Parameter(Mandatory=$True)]
        [string]$AdminUsername,

        [Parameter(Mandatory=$True)]
        [string]$Password,

        [Parameter(Mandatory=$True)]
        [string]$InstanceSize,

        [Parameter(Mandatory=$True)]
        [string]$SubnetNames,

        [Parameter(Mandatory=$True)]
        [string]$VNetName
    )

    $vm = New-AzureVMConfig -Name $Name -InstanceSize $InstanceSize -ImageName $ImageName -AvailabilitySetName $ServiceName -ErrorAction Stop
    $vm = $vm  | Add-AzureProvisioningConfig -Windows -AdminUsername $AdminUsername -Password $Password -ErrorAction Stop
    $vm = $vm | Set-AzureSubnet -SubnetNames $SubnetNames -ErrorAction Stop
    New-AzureVM -ServiceName $ServiceName -AffinityGroup $AffinityGroup -VNetName $VNetName -WaitForBoot -VMs $vm -ErrorAction Stop

    Install-WinRMCertificate -ServiceName $ServiceName -Name $Name -ErrorAction Stop
}

Function IsAdmin
{
    $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator") 
    return $IsAdmin
}

Function Install-WinRMCertificate()
{
    param([string] $ServiceName, [string] $Name)
	if((IsAdmin) -eq $false)
	{
		Write-Error "Must run PowerShell elevated to install WinRM certificates."
		return
	}
	
    Write-Host "Installing WinRM Certificate for remote access: $ServiceName $Name"
	$WinRMCert = (Get-AzureVM -ServiceName $ServiceName -Name $Name | select -ExpandProperty vm).DefaultWinRMCertificateThumbprint
	$AzureX509cert = Get-AzureCertificate -ServiceName $ServiceName -Thumbprint $WinRMCert -ThumbprintAlgorithm sha1

	$certTempFile = [IO.Path]::GetTempFileName()
	$AzureX509cert.Data | Out-File $certTempFile

	# Target The Cert That Needs To Be Imported
	$CertToImport = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $certTempFile

	$store = New-Object System.Security.Cryptography.X509Certificates.X509Store "Root", "LocalMachine"
	$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
	$store.Add($CertToImport)
	$store.Close()
	
	Remove-Item $certTempFile
}

Function Initialize-WebServer
{
    Param(
        [Parameter(Mandatory=$True)]
        [string]$Name,

        [Parameter(Mandatory=$True)]
        [string]$ServiceName,

        [Parameter(Mandatory=$True)]
        [string]$AdminUsername,

        [Parameter(Mandatory=$True)]
        [string]$Password
    )

    Get-AzureVM -ServiceName $ServiceName -Name $Name | Add-WebServerEndpoints | Update-AzureVM

    $ManagementUri = Get-AzureWinRMUri -ServiceName $ServiceName -Name $Name
    $SecurePassword = $Password | ConvertTo-SecureString -AsPlainText -Force
    $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $AdminUsername,$SecurePassword

    Invoke-Command -ConnectionUri $ManagementUri -Credential $Credential -ScriptBlock {

        # Install ASP.NET
        Write-Host "Installing ASP.NET..."
        Enable-WindowsOptionalFeature -Online -FeatureName IIS-ASPNET45 -All
        Enable-WindowsOptionalFeature -Online -FeatureName WCF-HTTP-Activation45 -All

        # Create the Application Pool our deploy script uses
        Write-Host "Creating IIS App Pool..."
        Import-Module WebAdministration
        $PoolName = "IIS:\AppPools\ASP.NET v4.0"
        if (!(test-path $PoolName))
        {
            new-item -Path $PoolName
        }
    }
}


Function Add-WebServerEndpoints
{
    Param
    (
        [Parameter(Mandatory=$True,ValueFromPipeline=$true)]
        [Microsoft.WindowsAzure.Commands.ServiceManagement.Model.IPersistentVM]$VM
    )

    $VM |
    Add-AzureEndpoint -Name "HTTP" -Protocol tcp -LocalPort 80 -PublicPort 80 -LBSetName "HTTP" -ProbePort 80 -ProbeProtocol http -ProbePath "/"
    Add-AzureEndpoint -Name "HTTPS" -Protocol tcp -LocalPort 443 -PublicPort 443 -LBSetName "HTTPS" -ProbePort 443 -ProbeProtocol http -ProbePath "/" |
    Add-AzureEndpoint -Name "Octopus" -Protocol tcp -LocalPort 10933 -PublicPort 10933
}

<#
.SYNOPSIS
    Adds 1 or more data disks to a VM provisioning pipeline.

.EXAMPLE
    Add-DataDisks -TotalSizeInGb 1024 -NumberOfDisks 16
    This will add 16 x 64Gb data disks each with unique disk labels and LUNs
#>
Function Add-DataDisks
{
    Param
    (
        [Parameter(Mandatory=$True,ValueFromPipeline=$true)]
        [Microsoft.WindowsAzure.Commands.ServiceManagement.Model.IPersistentVM]$VM,

        [Parameter(Mandatory=$True)]
        [int]$TotalSizeInGb,

        [int]$NumberOfDisks=1
    )

    $individualDiskSize = [Math]::Ceiling($TotalSizeInGb/$NumberOfDisks)

    for ($i =0; $i -lt $NumberOfDisks; $i++)
    {
        $VM = $VM | Add-AzureDataDisk -CreateNew -DiskSizeInGB $individualDiskSize -DiskLabel "Disk$i" -LUN $i -HostCaching None
    }
    return $VM
}

Function Initialize-SqlServer
{
    Param
    (
        [Parameter(Mandatory=$True)]
        [string]$Name,

        [Parameter(Mandatory=$True)]
        [string]$ServiceName,

        [Parameter(Mandatory=$True)]
        [string]$AdminUsername,

        [Parameter(Mandatory=$True)]
        [string]$Password
    )

    New-AzureStripedVolume -ServiceName $ServiceName -Name $Name -AdminUsername $AdminUserName -Password $Password
}

<#
.SYNOPSIS
    Pool all available physical disks into a new storage pool and stripe them together
    into a single NTFS volume optimized for database use.
#>
Function New-AzureStripedVolume
{
    Param(
        [Parameter(Mandatory=$True)]
        [string]$Name,

        [Parameter(Mandatory=$True)]
        [string]$ServiceName,

        [Parameter(Mandatory=$True)]
        [string]$AdminUsername,

        [Parameter(Mandatory=$True)]
        [string]$Password
    )

    $ManagementUri = Get-AzureWinRMUri -ServiceName $ServiceName -Name $Name
    $SecurePassword = $Password | ConvertTo-SecureString -AsPlainText -Force
    $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $AdminUsername,$SecurePassword

    Invoke-Command -ConnectionUri $ManagementUri -Credential $Credential -ScriptBlock {

        write-host "Creating storage pool..."
        $availableDisks = Get-PhysicalDisk -CanPool $true
        New-StoragePool -FriendlyName "Storage" -StorageSubSystemFriendlyName "Storage Spaces*" -PhysicalDisks $availableDisks

        write-host "Creating database volume..."
        New-VirtualDisk -StoragePoolFriendlyName "Storage" -FriendlyName "Data" -ResiliencySettingName Simple -ProvisioningType Fixed -Interleave 1MB -NumberOfDataCopies 1 -NumberOfColumns $availableDisks.Count -UseMaximumSize |
        Initialize-Disk -PartitionStyle GPT -PassThru |
        New-Partition -DriveLetter F -UseMaximumSize |
        Format-Volume -FileSystem NTFS -AllocationUnitSize 64KB -NewFileSystemLabel "Data" -Confirm:$false
    }
}

Function Initialize-Server
{
    Param(
        [Parameter(Mandatory=$True)]
        [string]$Name,

        [Parameter(Mandatory=$True)]
        [string]$ServiceName,

        [Parameter(Mandatory=$True)]
        [string]$AdminUsername,

        [Parameter(Mandatory=$True)]
        [string]$Password
    )

    $ManagementUri = Get-AzureWinRMUri -ServiceName $ServiceName -Name $Name
    $SecurePassword = $Password | ConvertTo-SecureString -AsPlainText -Force
    $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $AdminUsername,$SecurePassword

    Invoke-Command -ConnectionUri $ManagementUri -Credential $Credential -ScriptBlock {
        write-host "Enabling ping.."
        netsh advfirewall firewall set rule name="File and Printer Sharing (Echo Request - ICMPv4-In)" new enable=yes

        write-host "Enabling file sharing..."
        netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes
    }
}

<#
.SYNOPSIS
    Launches a remote powershell to the specified server, prompting for credentials if none are supplied
#>
Function Enter-Server
{
    Param(
        [Parameter(Mandatory=$True)]
        [string]$Name,

        [Parameter(Mandatory=$True)]
        [string]$ServiceName,

        [System.Management.Automation.PSCredential]$Credential=(Get-Credential)
    )

    $ManagementUri = Get-AzureWinRMUri -ServiceName $ServiceName -Name $Name
    Enter-PSSession -ConnectionUri $ManagementUri -Credential $Credential
}

<#
.SYNOPSIS
    Returns the image name of most recent Azure VM Image based on a wildcard match of the ImageFamily.

.EXAMPLE
    Get-LatestVMImage -ImageFamily "Windows Server 2012 R2 Datacenter"
#>
Function Get-LatestVMImage
{
    Param
    (
        [Parameter(Mandatory=$True)]
        [string] $ImageFamily
    )

    return (Get-AzureVMImage | where { $_.ImageFamily -like "${ImageFamily}*" } | sort-object PublishedDate -Descending)[0].ImageName
}
