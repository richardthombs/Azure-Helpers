PowerShell tools to help automate VM creation in Windows Azure.

## Installation

1. Download and install the [Windows Azure Powershell cmdlets](http://msdn.microsoft.com/en-us/library/azure/jj156055.aspx)
2. Configure them with your Azure account information
```powershell
Add-AzureAccount
```

3. Install the Azure-Helpers module
```powershell
mkdir $home\Documents\WindowsPowerShell\Modules
cd $home\Documents\WindowsPowerShell\Modules
git clone https://github.com/richardthombs/Azure-Helpers
import-module Azure-Helpers
```

`New-WebPair` creates a new pair of VMs and configures them to be IIS servers.

`New-SqlPair` creates a new pair of VMs and configures them to be SQL Servers.

`New-DomainJoinedVM` creates a new VM and adds it to a domain.

`Add-WebServerEndpoints` used in a pipe to add load balanced endpoints for HTTP and HTTPS traffic.

`Add-OctopusEndpoint` used in a pipe to add an Octopus Deploy Tentacle endpoint.

`Add-DataDisks` used in a pipe to add set of data disks which can be used to create a striped volume.

`New-AzureStripedVolume` creates a new striped volume from all available disks.

`Enable-AzureAspNet` installs the necessary features for ASP.NET support onto a VM.

`New-AzureUser` creates a new user.

`New-AzureIISAppPool` creates a new IIS Application Pool and sets the identity.

### Common parameters

`InstanceBaseName` The common name shared by both instances in a cloud service. `-InstanceBaseName web` will create two VMs called `weba` and `webb`.

`ImageName` The name of the OS install image to use.

`InstanceSize` The name of the instance size to use.

`DomainFQDN` The fully qualified domain name to associate with these servers. Ie `www.mycomany.com`.

`SubnetName` The name of the subnet to install the servers on.

`ServiceName` The name of the service.

`AffinityGroup` The name of the affinity group to add the servers to.

`VNetName` The name of the virtual network to install the servers on.

`DnsSettings` An array of DNS servers to configure the machines to use.
