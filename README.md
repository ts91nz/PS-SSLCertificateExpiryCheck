# PS-SSLCertificateExpiryCheck
List installed SSL certificates due to expire in x days.  
Write results of findings to Windows event log for detection by monitoring systems.   
Excludes already expired certificates by default (optional).   

### Examples:   
   .\PS-SSLCertificateExpiryCheck.ps1 -dir C:\temp -daysThreshold 9000 -EventLogging $True     
   .\PS-SSLCertificateExpiryCheck.ps1 -dir C:\temp -daysThreshold 30 -EventLogging $False   
   .\PS-SSLCertificateExpiryCheck.ps1 -dir C:\temp -daysThreshold 700 -EventLogging $True -sslOnly $false   

### Inputs   
[string]$dir - Working directory for storing output log file.   
[int]$daysThreshold - Number of days to check for SSL certificate 'NotAfter' datestamp.   
[string]$scriptName - Used for log file naming.    
[bool]$EventLogging - Enable writing to event log ($TRUE).   
[string]$EventSource - Event source name for event logging.   
[int]$EventID - Event log ID to be used (requires $EventLog = $TRUE).   
[bool]$sslOnly - Optional switch, uses -SSLServerAuthentication.   
   
### Outputs   
Write results to event log for detection by monitoring system and also local log for script record.   

   
