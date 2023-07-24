# PS-SSLCertificateExpiryCheck
Powershell: List SSL certificates due to expire in x days. Write results to event log for parsing or detection by monitoring software. Exludes already expired certificates by default.

.Synopsis
   List SSL certificates due to expire in x days. 
   
.DESCRIPTION   
   List SSL certificates due to expire in x days. Write results to event log for parsing or detection by monitoring software. 
   Exludes already expired certificates by default. 
   
.EXAMPLE
   .\PS-SSLCertificateExpiryCheck.ps1 -dir C:\temp -daysThreshold 9000 -EventLogging $True   
   
   .\PS-SSLCertificateExpiryCheck.ps1 -dir C:\temp -daysThreshold 30 -EventLogging $False
   
   .\PS-SSLCertificateExpiryCheck.ps1 -dir C:\temp -daysThreshold 700 -EventLogging $True -sslOnly $false
   
   
.INPUTS
   Variable: daysThreshold - Number of days to check for SSL certificate 'NotAfter' datestamp. 
   
.OUTPUTS
   Write results to event log for detection by log parsing or RMM toolset and also local log for script record.  
   
.NOTES
   Includes optional event logging enable/disable.
   
