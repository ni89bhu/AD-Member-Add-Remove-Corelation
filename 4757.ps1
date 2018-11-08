#######################################################################################################################################
#<Description>                                                                                                                        #
#This script will write relevent details from 4757 alert to a csv file for correlation through remidial action.                       #
#                                                                                                                                     #
#CreatedBy:kumarnitesh@eventtracker.com                                                                                               #
#Created On:11/06/18                                                                                                                  #
#######################################################################################################################################
#######################################################################################################################################
param (
[string]$Event_log_type,
[string]$log_type,
[string]$computer,
[string]$source,
[string]$category,
[string]$event_id,
[string]$user,
[string]$description
)

$scriptdir = split-path $SCRIPT:MyInvocation.MyCommand.Path -parent
New-Item -ItemType Directory -Force -Path "$scriptdir\Data"
$db = "$scriptdir\Data\memrem.csv"
$et = get-date -Format G

#######################################################################################################################################
$regex = '(?s)Subject\:.*?Account Name\:\s+(.*?)Account Domain\:.*?Member\:.*?Account Name\:\s+(.*?)Group\:.*?Group Name\:\s+(.*?)Group Domain\:'
Filter Extract
{
$_ -match $regex > $null
[PSCustomObject]@{
EventTime = $et
EventID = $event_id
ChangedBy = $Matches[1].trim()
MemberChanged =  $Matches[2].trim()
GroupName = $Matches[3].trim()
}}

$event = ($description | Extract) | Select-Object -Property EventTime,EventID,ChangedBy,MemberChanged,GroupName 
$event | Export-csv -Path $db -Append -NoTypeInformation

#######################################################################################################################################
#######################################################################################################################################