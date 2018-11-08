#################################################################################################################################################################################################################
#################################################################################################################################################################################################################

$etpath = (Get-ItemProperty -Path 'registry::hklm\SOFTWARE\Wow6432Node\Prism Microsystems\EventTracker\Manager').INSTALLPATH
$scriptdir = split-path $SCRIPT:MyInvocation.MyCommand.Path -parent
New-Item -ItemType Directory -Force -Path "$scriptdir\Data"
$outputpath = "$scriptdir\Data"
$duration = "-1"
$apikey = "0d943d495cfbe973be694ff885e72678a9458986f1ee7ad6ad1115657480d327"

#######################################################################################################################################

Function Invoke-MDBSQLCMD ($mdblocation,$sqlquery){
$dsn = "Provider=Microsoft.Jet.OLEDB.4.0; Data Source=$mdblocation;"
$objConn = New-Object System.Data.OleDb.OleDbConnection $dsn
$objCmd  = New-Object System.Data.OleDb.OleDbCommand $sqlquery,$objConn
$objConn.Open()
$adapter = New-Object System.Data.OleDb.OleDbDataAdapter $objCmd
$dataset = New-Object System.Data.DataSet
[void] $adapter.Fill($dataSet)
$objConn.Close()
$dataSet.Tables | Select-Object -Expand Rows
$dataSet = $null
$adapter = $null
$objCmd  = $null
$objConn = $null
}

$logprocessdll = [System.Reflection.Assembly]::LoadFrom("$etpath\AdvancedReports\EventTracker.LogSearchProcess.dll")
$logparmeterdll = [System.Reflection.Assembly]::LoadFrom("$etpath\AdvancedReports\EventTracker.LogSearchParameter.dll")
$datapersist = [System.Reflection.Assembly]::LoadFrom("$etpath\AdvancedReports\EventTracker.Report.DataPersistance.dll")

function Get-VTReport {
    [CmdletBinding()]
    Param( 
    [String] $VTApiKey,
    [Parameter(ParameterSetName="hash", ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][String] $hash
    )
    Begin {
        $fileUri = 'https://www.virustotal.com/vtapi/v2/file/report'
    }
    Process {
        [String] $h = $null
        [String] $u = $null
        [String] $method = $null
        $body = @{}

        switch ($PSCmdlet.ParameterSetName) {
        "hash" {            
            $u = $fileUri
            $method = 'POST'
            $body = @{ resource = $hash; apikey = $VTApiKey}
            }
        }        

       $q = (Invoke-RestMethod -Method $method -Uri $u -Body $body)
       Start-Sleep -Seconds 15
       If($q.response_code -eq 1){
	$obj = New-Object PSObject -Property @{
		#"md5" = $q.resource;
		"score" = ("{0}/{1}" -f $q.positives,$q.total)
	}}
elseIf($q.response_code -eq 0){
	$obj = New-Object PSObject -Property @{
		#"md5" = $q.resource;
		"score" = "clean"
	}}
Write-Output $obj
}
       
}

#################################################################################################################################################################################################################
#################################################################################################################################################################################################################

$logparmeter01 = New-Object Prism.LogSearchParameter.AdvanceParameter
$logparmeter02 = New-Object Prism.LogSearchParameter.AdvanceParameter
$logparmeter05 = New-Object Prism.LogSearchParameter.AdvanceParameter
$logcerteria = New-Object Prism.LogSearchParameter.LogSearchParameter
$searchconfig = New-Object Prism.LogSearchParameter.SearchConfig
$searchconfig.IsParseTokens = "False"
$logcerteria.FromDate = (get-date).AddHours($duration)
$logcerteria.ToDate = (get-date)
#$logcerteria.SystemGroups = "Servers"
$logcerteria.SystemIncludeType = 1
$logparmeter01.ParameterId = 0
$logparmeter01.Operator = 1
$logparmeter01.ParameterName = "event_id"
$logparmeter01.ParameterType = 1
$logparmeter01.SearchValue = "8005"
$logparmeter02.ParameterId = 0
$logparmeter02.Operator = 1
$logparmeter02.ParameterName = "event_source"
$logparmeter02.ParameterType = 1
$logparmeter02.SearchValue = "EventTracker"
$logcerteria.AdvancedParameter = $logparmeter01
$logcerteria.AdvancedParameter += $logparmeter02
$logticks = (get-date).Ticks
$mdbname1 = "LogonAnalysis_{0}" -f $logticks
$param = new-object Prism.LogSearchParameter.LogSearchParameterContext ("$mdbname1")
$param.Update($logcerteria)
$search = new-object Prism.LogSearchProcess.LogSearchProcessing ("$mdbname1")
$search.StartProcessing(4) | Out-Null

$regex2 = '(?s)Hash\:\s+(.*?)System\:\s+(.*?)Time\:\s+(.*?)Image File Name\:\s+(.*?)User\:\s+(.*?)File Name\:.*?Creator Image File Name\:\s+(.*?)File Version\:'
#################################################################################################################################################################################################################
Filter Extract2 {
$_.event_description -match $regex2 > $null
[pscustomobject]@{
#EventTime1 = $_.event_datetime
#HostName1 = $_.event_computer   
FileHash = ($Matches[1]).trim()
HostName = ($Matches[2]).trim()
EventTime = ($Matches[3]).trim()
FileName = ($Matches[4]).trim()
UserName = ($Matches[5]).trim()
CreatorFileName = ($Matches[6]).trim()
VTResults = Get-VTReport -VTApiKey $apikey -hash (($Matches[1]).trim())
}}
$mdblocation1 = "$etpath\Reports\LogSearch\$mdbname1.mdb"
$query1 = Invoke-MDBSQLCMD $mdblocation1 -sqlquery "Select event_datetime,event_computer,event_description from Events" | Extract2
$result = $query1 | Select-Object -Property EventTime,HostName,UserName,FileName,FileHash,CreatorFileName,VTResults
#################################################################################################################################################################################################################
Filter Extract2 {
$_.event_description -match $regex2 > $null
[pscustomobject]@{
#EventTime1 = $_.event_datetime
#HostName1 = $_.event_computer   
FileHash = ($Matches[1]).trim()
HostName = ($Matches[2]).trim()
EventTime = ($Matches[3]).trim()
FileName = ($Matches[4]).trim()
UserName = ($Matches[5]).trim()
CreatorFileName = ($Matches[6]).trim()
}}
$result = $query1|foreach-object{
  $vttest =  Get-VTReport -VTApiKey $apikey -hash ($_.FileHash)
  $_|Select *,@{Name='VTResults';Expression=$vttest}
} 
#################################################################################################################################################################################################################
$result | export-csv -Path "$outputtpath\VT_Results.csv" -NoTypeInformation

