############################################################################# 
#                                                                           # 
#   This Sample Code is provided for the purpose of illustration only       # 
#   and is not intended to be used in a production environment.  THIS       # 
#   SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT    # 
#   WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT    # 
#   LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS     # 
#   FOR A PARTICULAR PURPOSE.  We grant You a nonexclusive, royalty-free    # 
#   right to use and modify the Sample Code and to reproduce and distribute # 
#   the object code form of the Sample Code, provided that You agree:       # 
#   (i) to not use Our name, logo, or trademarks to market Your software    # 
#   product in which the Sample Code is embedded; (ii) to include a valid   # 
#   copyright notice on Your software product in which the Sample Code is   # 
#   embedded; and (iii) to indemnify, hold harmless, and defend Us and      # 
#   Our suppliers from and against any claims or lawsuits, including        # 
#   attorneys' fees, that arise or result from the use or distribution      # 
#   of the Sample Code.                                                     # 
#                                                                           # 
#   Version 1.0         Date Last modified:      1 September 2020          # 
#                                                                           # 
############################################################################# 

<#
.Synopsis
   The script will check for event 2889 on domain controllers. 
   In August 2019 Microsoft released guidance to Microsoft Active Directory (AD) administrators around hardening configurations for 
   LDAP channel binding & LDAP signing on their AD domains. On February 4, 2020 Microsoft announced that the defaults would not be 
   changing but recommended that customers enable diagnostic event logging in their AD implementations to identify where hardening 
   might be needed.
   When this type of logging is enabled, a client that attempts certain types of LDAP binds to the directory server will cause a log 
   event with Event ID 2889 to be generated on that directory server. 

.DESCRIPTION
   The script will check for event 2889 on domain controllers. 
   In August 2019 Microsoft released guidance to Microsoft Active Directory (AD) administrators around hardening configurations for 
   LDAP channel binding & LDAP signing on their AD domains. On February 4, 2020 Microsoft announced that the defaults would not be 
   changing but recommended that customers enable diagnostic event logging in their AD implementations to identify where hardening 
   might be needed.
   When this type of logging is enabled, a client that attempts certain types of LDAP binds to the directory server will cause a log 
   event with Event ID 2889 to be generated on that directory server. 

.EXAMPLE
    This Example shows how to execute the script with default values
   .\Get-Ldap.ps1

.EXAMPLE
    The following sample will collect information only from the specified domain controller server1.contoso.com
   .\Get-Ldap.ps1 -DomainController server1.contoso.com

.EXAMPLE
  This sample will get events for the last 12 hours, the default is -24
  .\Get-Ldap.ps1 -last -12
   
.PARAMETER DomainController
    Overwrite the domain controllers to use, the default is to use all domain controllers in the forest.

.PARAMETER ExcludeDomain
    Exclude a domain controller for the specified domain

.PARAMETER last
 Specify in hours how far back the logs should be checked. Values should be negative for example, -12 for the last 12 hours.

.PARAMETER UseAlternatecredentials
   Specify alternate credentials for the execution of the script. You will be prompted to provide credentials

#>

Param([String[]]$DomainController,[string[]]$ExcludeDomain,[int]$Last='-24',[switch]$UseAlternatecredentials)

$DCs = @()
If ($DomainController -eq '' -or $null -eq $DomainController)
{
    $DCs += (get-adforest).domains |Where-Object{$_-notin $ExcludeDomain} | ForEach-Object{(Get-ADDomain $_).ReplicaDirectoryServers}
}   Else
{
    $DCs = $DomainController
}


$cmd = { #Start Remote ScriptBlock

$Result = @{$ENV:COMPUTERNAME = @{'2889' = @()}}

$LogLevel = (Get-ItemProperty 'HKLM:SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics').'16 LDAP Interface Events'

Foreach ($Event in (Get-EventLog -LogName 'Directory Service' -After (Get-date).AddHours(($args[0])) | Where-Object{$_.EventID -in @('2889','2888','2887')}))
{
    $obj = @{}

    If ($Event.EventID -eq '2889')
    {
        $Obj.EventID        = '2889'
        $Obj.MachineName    =  $Event.MachineName
        $Obj.TimeGenerated  =  $Event.TimeGenerated
        $Obj.TimeWritten    =  $Event.TimeWritten
        $Obj.AccountName    =  $Event.ReplacementStrings[1]
        $Obj.Address        =  $Event.ReplacementStrings[0]
        $Obj.BindingType    =  $Event.ReplacementStrings[2]
        $obj.LogLevel       =  $LogLevel
        $Result.$ENV:COMPUTERNAME.'2889' += [PSCustomObject]$obj
    }

}
$Result  
} #End remote ScriptBlock

if ([switch]$UseAlternatecredentials)
{
$credentials = Get-Credential -Message "Please provide Credentials to query domain contoller using remote powershell."
Invoke-Command -ScriptBlock $cmd -ComputerName $DCs -ArgumentList $Last -AsJob -JobName EventCollection -Credential $credentials -ErrorAction SilentlyContinue
}
else
{
Invoke-Command -ScriptBlock $cmd -ComputerName $DCs -ArgumentList $Last -AsJob -JobName EventCollection  -ErrorAction SilentlyContinue
}
Do   {
        Clear-Host
        (Get-Job -Name EventCollection -ErrorAction SilentlyContinue ).ChildJobs|where-object{$_.State -eq 'Running'}
        Write-host "Waiting for task to complete. Will check every 15 seconds." -ForegroundColor Yellow
        Start-sleep 15;
    }   while 
    ((Get-Job -Name EventCollection ).State -eq 'running')

Write-host "All jobs Completed. " -ForegroundColor Green

$Export = @()

Foreach ($Job in (Get-job -Name EventCollection).ChildJobs)
{
    if ($Job.state -Ne 'failed')
    {
    $Export += $job | receive-job -ErrorAction SilentlyContinue
    }else
    {
    
    $job | receive-job -ErrorAction SilentlyContinue -ErrorVariable Er
    Write-Host "Collection to $($Job.location) failed - With error - $($Er.Errordetails)" -ForegroundColor red 
    }
}
Get-job -Name EventCollection | remove-job

$Evt2889 = @($Export.keys | foreach-object {$Export.$psitem.'2889'} | Select-Object EventID,AccountName,TimeGenerated,BindingType,Address,TimeWritten,MachineName, LogLevel)


$fileName = ".\$('LDAP2889-')$(Get-date -f dd-MM-hhmmss).csv" #File for RAW Data
$Evt2889 | Export-Csv -LiteralPath $fileName -NoClobber -NoTypeInformation

$Html = @"
<html>
<head>
<Title>Domain Authentication</Title>
<Style>
th {
	font: bold 11px "Trebuchet MS", Verdana, Arial, Helvetica,
	sans-serif;
	color: #FFFFFF;
	border-right: 1px solid #C1DAD7;
	border-bottom: 1px solid #C1DAD7;
	border-top: 1px solid #C1DAD7;
	letter-spacing: 2px;
	text-transform: uppercase;
	text-align: left;
	padding: 6px 6px 6px 12px;
	background: #5F9EA0;
}
td {
	font: 11px "Trebuchet MS", Verdana, Arial, Helvetica,
	sans-serif;
	border-right: 1px solid #C1DAD7;
	border-bottom: 1px solid #C1DAD7;
	background: #fff;
	padding: 6px 6px 6px 12px;
	color: #6D929B;
}
</Style>
</head>
<body>
<table border=0>
<tr><th>Domain Controllers</th><th>Unsecure Binding attempts</th><th>LogLevel (Requires 2)</th>
</tr>
$($Evt2889 | Group-Object -Property MachineName | foreach-object {"<tr><td>$($PSItem.Name)</td><td>$($Psitem.Count)</td><td>$($Psitem.Group[0].LogLevel)</td></tr>"})
</table>
<br>
<Table>
<tr><th>Machine Name</th><th>Connection from</th><th>Account</th></tr>
$($Evt2889 | Select-object MachineName,Address,AccountName -Unique |foreach-object {"<tr><td>$($PSItem.MachineName)</td><td>$($Psitem.Address)</td><td>$($Psitem.AccountName)</td></tr>"})
</table>
</body>
</html>
"@

 $HTML |out-file .\report.html