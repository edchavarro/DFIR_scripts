####################################################################################################################################
## By Eduardo Chavarro Ovalle
## eduardo.chavarro@csiete.org @echavarro
##
## Use velociraptor to collect information and decompress the evidence collected in any folder.
##
## Execute this script by runing: .\evidence-parser.ps1 <evidence path> <1: if you want to run plaso using docker>
##
##  evidence path must be the folder where evidence has been decompressed 
##
##	Evidence analysis tool
##
##	Requirements:
##		AnalyzeMFT:		https://github.com/dkovar/analyzeMFT
##		RegRipper:		https://github.com/keydet89/RegRipper3.0
##		Plaso docker 	https://plaso.readthedocs.io/en/latest/sources/user/Installing-with-docker.html
##		RipGrep			https://github.com/BurntSushi/ripgrep
##		WSL				https://docs.microsoft.com/en-us/windows/wsl/install-win10

$evidencePath = $args[0]
$IncludePlaso = $args[1]
$Malfname=		"SuspiciousEvents.txt"
$hivepath=		'C\Windows\System32\config'
$amcachepath=	'C\Windows\AppCompat\Programs'
$regripper=		'C:\Tools\WindowsForensics\RegRipper3.0'
$analyzeMFT=	'C:\Tools\WindowsForensics\NTFS_MFT_Analysis\analyzeMFT'
$WinEventIDFile="C:\Tools\WindowsForensics\WindowsEventID.txt"

####################################################################################################################################


function analyze_evidence {
param(
	 [string]$eventid,
     [string]$Message,
     [string]$command,
	 [string]$include_events,
	 [string]$thisMonth	 
   )  

	if ($thisMonth -eq "1"){
		$command=$command + '|rg '+$year_month
	}
	Write-Host " * Checking $eventid $Message ..." -fore green
	$events=bash -c "$command -c" 
	if ($events.length -gt 0){
		Write-Host " * $id $Message events :"$events -fore red
		echo " * $Message events :$events" >> $Malfname
		echo "try: $command" >> $Malfname
		if ($include_events -eq '1'){
			echo " + $Message events:" >> $Malfname
			bash -c $command >> $Malfname
		}	
		echo "" >> $Malfname
		}
}

Write-Host "####################################################################" -fore yellow
Write-Host "##	Checking updates for RegRipper and analyzeMFT " -fore yellow
Write-Host "####################################################################" -fore yellow
	bash -c "cd /mnt/c/Tools/WindowsForensics/RegRipper3.0; git reset --hard;git pull"
	bash -c "cd /mnt/c/Tools/WindowsForensics/NTFS_MFT_Analysis/analyzeMFT; git reset --hard;git pull"
	
Write-Host "####################################################################" -fore yellow
Write-Host "##	Verifying Registry Hive Files " -fore yellow
Write-Host "####################################################################" -fore yellow

if (Test-Path $evidencePath\$hivepath\SAM)
{
	Write-Host " * Parsing SAM hive ..." -fore green
	$command= $regripper+"\rip.exe -r "+$evidencePath+"\"+$hivepath+"\SAM -f SAM > "+$evidencePath+"\SAM.txt"
	cmd /c $command
	Write-Host " * Parsing SECURITY hive ..." -fore green
	$command= $regripper+"\rip.exe -r "+$evidencePath+"\"+$hivepath+"\SECURITY -f SECURITY > "+$evidencePath+"\SECURITY.txt"
	cmd /c $command
	Write-Host " * Parsing SOFTWARE hive ..."  -fore green
	$command= $regripper+"\rip.exe -r "+$evidencePath+"\"+$hivepath+"\SOFTWARE -f SOFTWARE > "+$evidencePath+"\SOFTWARE.txt"
	cmd /c $command
	Write-Host " * Parsing SYSTEM hive ..."  -fore green
	$command= $regripper+"\rip.exe -r "+$evidencePath+"\"+$hivepath+"\SYSTEM -f SYSTEM > "+$evidencePath+"\SYSTEM.txt"
	cmd /c $command
}
else
{
	Write-Host "[Registry Hive Error] SAM file not detected, please check the path: " $evidencePath"\"$hivepath  -fore red
}	

Write-Host "####################################################################" -fore yellow
Write-Host "##	Verifying AMCACHE Hive Files  " -fore yellow
Write-Host "####################################################################" -fore yellow

if (Test-Path $evidencePath\$amcachepath\Amcache.hve)
{
	Write-Host "Parsing AMCACHE hive ..."
	$command= $regripper+"\rip.exe -r "+$evidencePath+"\"+$amcachepath+"\Amcache.hve -f AMCACHE > "+$evidencePath+"\AMCACHE.txt"
	cmd /c $command
}
else
{
	Write-Host "[Registry Hive Error] Amcache.hve file not detected, please check the path: " $evidencePath"\"$amcachepath  -fore red
}	

Write-Host "####################################################################" -fore yellow
Write-Host "##	Verifying NTUSER Hive Files  " -fore yellow
Write-Host "####################################################################" -fore yellow

$ntusers=Get-ChildItem -Path $evidencePath\C\ -Filter NTUSER.dat -Recurse -ErrorAction SilentlyContinue -Force
ForEach ($f in $ntusers)
{
	Write-Host " * Parsing NTUSER hive from "$f.Directory.Name -fore green
	$fname=$f.Directory.Name
	$command= $regripper+"\rip.exe -r "+$f.Directory+"\ntuser.dat -f ntuser > "+$evidencePath+"\"+$fname+"NTUSER.txt"
	cmd /c $command
}

Write-Host "####################################################################" -fore yellow
Write-Host "##	Parsing MFT file  " -fore yellow
Write-Host "####################################################################" -fore yellow

	$command= "python.exe $analyzeMFT\analyzeMFT.py -f $evidencePath\C\`$MFT -o $evidencePath\MFT.csv -e"
	cmd /c $command
Write-Host " Parsed file saved to MFT.csv" -fore green


if ($IncludePlaso -eq "1"){
	Write-Host "####################################################################" -fore yellow
	Write-Host "##	Running Docker: log2timeline  " -fore yellow
	Write-Host "####################################################################" -fore yellow
	$command="docker run -v "+$evidencePath+":/data log2timeline/plaso log2timeline /data/evidences.plaso /data/C/" 
	cmd /c $command
	Write-Host "Plaso Timeline saved to evidences.plaso" -fore green
	 
	Write-Host "####################################################################" -fore yellow
	Write-Host "##	Running Docker: plaso  " -fore yellow
	Write-Host "####################################################################" -fore yellow

		$command="docker run -v "+$evidencePath+":/data log2timeline/plaso psort -w /data/timeline.log /data/evidences.plaso"
		cmd /c $command
	Write-Host "Timeline saved to timeline.log"  -fore green
}
else
{
	Write-Host "[Adv] Plaso was not selected for execution" -fore blue
}

	Write-Host "####################################################################" -fore green
	Write-Host "##	Process Finished. Parsed files were saved at:  					" -fore green
	Write-Host "##	$evidencePath								  					" -fore green
	Write-Host "####################################################################" -fore green

cd $evidencePath

	Write-Host ""
	Write-Host "####################################################################" -fore yellow
	Write-Host "##	Verifying suspicious activity from timeline		" -fore yellow
	Write-Host "####################################################################" -fore yellow

	echo "#############################################################################" > $Malfname
	bash -c "strings SOFTWARE.txt|rg -i winver -A4 " >> $Malfname
	bash -c "rg -iaN '\(System\) Gets ComputerName and Hostname' SYSTEM.txt -A3" >> $Malfname
	bash -c "rg -iaN '\(System\) Get TimeZoneInformation key contents' -A9 SYSTEM.txt">> $Malfname
	bash -c "rg -iaN 'IPAddress' -B3 -A2 SYSTEM.txt" >> $Malfname
	echo "#############################################################################" >> $Malfname
	echo "" >> $Malfname
	echo "Basic suspicious activity from timeline" >> $Malfname
	echo "" >> $Malfname

	$year_month=Get-Date -Format "yyyy-MM-"

	$EventsID=[System.IO.File]::ReadLines($WinEventIDFile)
		
	ForEach ($ev in $EventsID) {
		$a=$ev
		$evId, $evName, $evCmd, $evPrint, $thisMonth = $a.split(',')
		if ($evCmd.length -eq 0){$evCmd="rg '`\[$evId ' timeline.log"}
		analyze_evidence -eventid $evId -Message $evName -command $evCmd -include_events $evPrint -thisMonth $thisMonth
	}

	echo "For specific user logins this month try:" >> $Malfname
	echo "rg -aN '\[4624 ' timeline.log|rg $year_month|awk -F, '{print `$5}'|sort|awk -F\' '{print `$14`" \\`"`$12`" UID:`"`$10`" Type:`"`$18`" IPSource:`"`$38}'|sort|uniq -c" >> $Malfname
	echo "For specific failed user logins this month try:">> $Malfname
	echo "rg -aN '\[4625 ' timeline.log|rg -vi SuppressDuplicateDuration|rg 2020-06-|awk -F, '{print `$5}'|sort|awk -F\' '{print `$14`"  `"`$12`" UID:`"`$10`" Type:`"`$22`" IPSource:`"`$40}'|sort|uniq -c" >> $Malfname

	Write-Host "## Runing Loki (This can take a while)" -fore green 
	$command="cd C:\Tools\MalwareAnalisys\loki_0.31.1\loki && loki.exe --update --dontwait"
	cmd /c $command >> $Malfname
	$command="cd C:\Tools\MalwareAnalisys\loki_0.31.1\loki && loki.exe --dontwait -p "+$evidencePath
	cmd /c $command >> $Malfname

	Write-Host "####################################################################" -fore green
	Write-Host "##	Process Finished. 							  					" -fore green
	Write-Host "##	Suspicios event log saved at $Malfname		  					" -fore green
	Write-Host "####################################################################" -fore green

#	bash -c "batcat $Malfname -l powershell"