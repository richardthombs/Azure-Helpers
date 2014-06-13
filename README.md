PowerShell tools to help automate VM creation in Windows Azure.

## Installation

Download and install the [Windows Azure Powershell cmdlets](http://msdn.microsoft.com/en-us/library/azure/jj156055.aspx)

```powershell
mkdir $home\Documents\WindowsPowerShell\Modules
cd $home\Documents\WindowsPowerShell\Modules
git clone https://github.com/richardthombs/Azure-Helpers
import-module Azure-Helpers
```

`Install-WebServer` creates a new VM and configures it to be a web server.  

`Install-SqlServer` creates a new VM and configures it to be a database server.
