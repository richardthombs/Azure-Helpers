Function New-WebPair
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [string] $InstanceBaseName,

        [Parameter(Mandatory=$true)]
        [string] $ImageName,

        [Parameter(Mandatory=$true)]
        [string] $InstanceSize,

        [Parameter(Mandatory=$true)]
        [string] $AdminUserName,

        [Parameter(Mandatory=$true)]
        [string] $Password,

        [Parameter(Mandatory=$true)]
        [string] $DomainFQDN,

        [string] $DomainNetBiosName=$DomainFQDN.Split('.')[0].ToUpper(),

        [Parameter(Mandatory=$true)]
        [string] $SubnetName,

        [Parameter(Mandatory=$true)]
        [string] $ServiceName,

        [Parameter(Mandatory=$true)]
        [string] $AffinityGroup,

        [Parameter(Mandatory=$true)]
        [string] $VNetName,

        [Parameter(Mandatory=$true)]
        [Microsoft.WindowsAzure.Commands.ServiceManagement.Model.PersistentVMModel.DnsServer[]] $DnsSettings
    )

    $Instances = @("${InstanceBaseName}a","${InstanceBaseName}b")

    $VMs = @()
    $octopusPort=10933
    foreach ($i in $Instances)
    {
        $VMs += New-DomainJoinedVM -Name $InstanceA -ImageName $ImageName -InstanceSize $InstanceSize -AvailabilitySetName $ServiceName -AdminUserName $AdminUserName -Password $Password -DomainFQDN $DomainFQDN -DomainNetBiosName $DomainNetBiosName -SubnetName $SubnetName | Add-WebServerEndpoints | Add-OctopusEndpoint -LocalPort $octopusPort -PublicPort $octopusPort
        $octopusPort++
    }

    New-AzureVM -ServiceName $ServiceName -AffinityGroup $AffinityGroup -VNetName $VNetName -DnsSettings $DnsSettings -VMs $VMs -WaitForBoot

    return $Instances
}

Function New-SqlPair
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [string] $InstanceBaseName,

        [Parameter(Mandatory=$true)]
        [string] $ImageName,

        [Parameter(Mandatory=$true)]
        [string] $InstanceSize,

        [Parameter(Mandatory=$true)]
        [string] $AdminUserName,

        [Parameter(Mandatory=$true)]
        [string] $Password,

        [Parameter(Mandatory=$true)]
        [string] $DomainFQDN,

        [string] $DomainNetBiosName=$DomainFQDN.Split('.')[0].ToUpper(),

        [Parameter(Mandatory=$true)]
        [string] $SubnetName,

        [Parameter(Mandatory=$true)]
        [string] $ServiceName,

        [Parameter(Mandatory=$true)]
        [string] $AffinityGroup,

        [Parameter(Mandatory=$true)]
        [string] $VNetName,

        [Parameter(Mandatory=$true)]
        [Microsoft.WindowsAzure.Commands.ServiceManagement.Model.PersistentVMModel.DnsServer[]] $DnsSettings,

        [Parameter(Mandatory=$True)]
        [int]$TotalSizeInGb,

        [int]$NumberOfDisks=1
    )

    $Instances = @("${InstanceBaseName}a","${InstanceBaseName}b")

    $VMs = @()
    foreach ($i in $Instances)
    {
        $VMs += New-DomainJoinedVM -Name $i -ImageName $ImageName -InstanceSize $InstanceSize -AvailabilitySetName $ServiceName -AdminUserName $AdminUserName -Password $Password -DomainFQDN $DomainFQDN -DomainNetBiosName $DomainNetBiosName -SubnetName $SubnetName |
            Add-DataDisks -TotalSizeInGb $TotalSizeInGb -NumberOfDisks $NumberOfDisks
    }

    New-AzureVM -ServiceName $ServiceName -AffinityGroup $AffinityGroup -VNetName $VNetName -DnsSettings $DnsSettings -VMs $VMs -WaitForBoot

    return $Instances
}

<#
.SYNOPSIS
    Returns a VM configuration that is ready to be joined to the specified domain.

 .DESCRIPTION
    This assumes that the local admin credentials are the same as the domain admin.
#>
Function New-DomainJoinedVM
{
    Param
    (
        [Parameter(Mandatory=$True)]
        [string] $Name,

        [Parameter(Mandatory=$True)]
        [string] $ImageName,

        [Parameter(Mandatory=$True)]
        [string] $AvailabilitySetName,

        [Parameter(Mandatory=$True)]
        [string] $AdminUserName,

        [Parameter(Mandatory=$True)]
        [string] $Password,

        [Parameter(Mandatory=$True)]
        [string] $DomainFQDN,

        [Parameter(Mandatory=$True)]
        [string] $DomainNetBiosName,

        [Parameter(Mandatory=$True)]
        [string] $SubnetName,

        [Parameter(Mandatory=$True)]
        [string] $InstanceSize
    )

    return New-AzureVMConfig -Name $Name -InstanceSize $InstanceSize -ImageName $ImageName -AvailabilitySetName $AvailabilitySetName |
        Add-AzureProvisioningConfig -WindowsDomain -AdminUsername $AdminUserName -Password $Password -JoinDomain $DomainFQDN -Domain $DomainNetBiosName -DomainUserName $AdminUserName -DomainPassword $Password |
        Set-AzureSubnet -SubnetNames $SubnetName
}

Function IsAdmin
{
    $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator") 
    return $IsAdmin
}

<#
.SYNOPSIS
    Installs the WinRM certificate for the specified VM locally so it can be used with WinRM remoting.
#>
Function Install-WinRMCertificate()
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [string] $ServiceName,

        [Parameter(Mandatory=$true)]
        [string] $Name
    )

	if ((IsAdmin) -eq $false)
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

<#
.SYNOPSIS
    Adds load balanced endpoints for HTTP and HTTPS
#>
Function Add-WebServerEndpoints
{
    Param
    (
        [Parameter(Mandatory=$True,ValueFromPipeline=$true)]
        [Microsoft.WindowsAzure.Commands.ServiceManagement.Model.IPersistentVM]$VM
    )

    Add-AzureEndpoint -Name "HTTP" -Protocol tcp -LocalPort 80 -PublicPort 80 -LBSetName "HTTP" -ProbePort 80 -ProbeProtocol http -ProbePath "/" -VM $VM |
    Add-AzureEndpoint -Name "HTTPS" -Protocol tcp -LocalPort 443 -PublicPort 443 -LBSetName "HTTPS" -ProbePort 443 -ProbeProtocol http -ProbePath "/"
}

<#
.SYNOPSIS
    Adds an endpoint for Octopus Deploy.
#>
Function Add-OctopusEndpoint
{
    Param
    (
        [Parameter(Mandatory=$True,ValueFromPipeline=$true)]
        [Microsoft.WindowsAzure.Commands.ServiceManagement.Model.IPersistentVM]$VM,

        [int] $PublicPort = 10933,
        [int] $LocalPort = $PublicPort
    )

    Add-AzureEndpoint -Name "Octopus" -Protocol tcp -LocalPort $LocalPort -PublicPort $PublicPort -VM $VM
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

        [System.Management.Automation.PSCredential]$Credential = (Get-Credential)
    )

    $WinRMUri = Get-AzureWinRMUri -ServiceName $ServiceName -Name $Name

    Invoke-Command -ConnectionUri $WinRMUri -Credential $Credential -ScriptBlock {
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

<#
.SYNOPSIS
    Launches a remote PowerShell to the specified server, prompting for credentials if none are supplied
#>
Function Enter-Server
{
    Param(
        [Parameter(Mandatory=$True)]
        [string]$Name,

        [Parameter(Mandatory=$True)]
        [string]$ServiceName,

        [System.Management.Automation.PSCredential]$Credential = (Get-Credential)
    )

    $WinRMUri = Get-AzureWinRMUri -ServiceName $ServiceName -Name $Name
    Enter-PSSession -ConnectionUri $WinRMUri -Credential $Credential
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

<#
.SYNOPSIS
    Creates a new PSCredential from a plaintext username and password.

.EXAMPLE
    New-Credential -Username "Admin" -Password "SillyPassword"
#>
Function New-Credential
{
    Param
    (
        [Parameter(Mandatory=$True)]
        [string] $Username,

        [Parameter(Mandatory=$True)]
        [string] $Password
    )

    return New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Username,(ConvertTo-SecureString -String $Password -AsPlainText -Force)
}
