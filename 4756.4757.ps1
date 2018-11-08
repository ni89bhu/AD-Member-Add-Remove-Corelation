#######################################################################################################################################
#<Description>                                                                                                                        #
#This script will write co-relate relevent details from 4756 and 4757 alert's csv outputs and generate an event if members were added #
#but not removed within 24 hours. Script will also truncate entries in output files later than 48 hours.                              # 
#                                                                                                                                     #
#CreatedBy:kumarnitesh@eventtracker.com                                                                                               #
#Created On:11/06/18                                                                                                                  #
#######################################################################################################################################
#######################################################################################################################################
$etpath = (Get-ItemProperty -Path 'registry::hklm\SOFTWARE\Wow6432Node\Prism Microsystems\EventTracker\Manager').INSTALLPATH
$scriptdir = split-path $SCRIPT:MyInvocation.MyCommand.Path -parent
$db1 = Import-Csv "$scriptdir\Data\memadd.csv"
$db2 = Import-Csv "$scriptdir\Data\memrem.csv"

#######################################################################################################################################
foreach ($1 in $Db1){
$umatch = $db2 |Where-Object {($1.ChangedBy -eq $_.ChangedBy) -and ($1.MemberChanged -eq $_.MemberChanged) -and ($1.GroupName -eq $_.GroupName) -and ((([datetime]$1.eventtime - [datetime]$_.eventtime)).TotalHours -le 24)}
If (!($umatch)) {
$mc = (($1.MemberChanged) -split ",*..=")[1]
$cb = ($1.ChangedBy)
$gn = ($1.GroupName)
$et = ($1.EventTime)
& "$etpath\ScheduledActionScripts\sendtrap.exe" ET $env:COMPUTERNAME $computer 3 2 "EventTracker" 0 8027 "Member $mc added to group $gn on $et by $cb, but was not removed within 24 Hrs." N/A N/A " " 14505
}}

#######################################################################################################################################
$db1 | Where-Object {($_.eventtime -gt (get-date (get-date).AddDays(-2) -Format G))} | export-csv Import-Csv "$scriptdir\Data\memadd.csv" -NoTypeInformation
$db2 | Where-Object {($_.eventtime -gt (get-date (get-date).AddDays(-2) -Format G))} | export-csv Import-Csv "$scriptdir\Data\memrem.csv" -NoTypeInformation

#######################################################################################################################################
#######################################################################################################################################