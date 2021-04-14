####################################################################################################################################
## By Eduardo Chavarro Ovalle
## eduardo.ovalle@kaspersky.com @echavarro
##
## Use velociraptor to collect information and decompress the evidence collected in any folder.
##
## Execute this script by runing: .\pssigma-check.ps1 <evidence path> -target <powershell or grep>
##
## Verifies malicious activity based on SigmaRules (using targets powershell or grep)
##
##	Requeriments:
##		Sigma:			https://github.com/Neo23x0/sigma
##		Windows bash	https://docs.microsoft.com/en-us/windows/wsl/install-win10
##		RipGrep			https://github.com/BurntSushi/ripgrep
##		WSL				https://docs.microsoft.com/en-us/windows/wsl/install-win10
####################################################################################################################################
$evidencePath = $args[0]
$target = $args[1]
$Results=		"pssigma_results.txt"
$sigmaPath=		'/mnt/c/Tools/Threat\ Hunting/sigma'
$evtPath=		'C\Windows\System32\winevt\Logs'
$sigmaRules=	'rules/windows/malware/'
$pssigma_commands=	'C:\Tools\WindowsForensics\pssigma.commands'


Write-Host "##	Checking updates for Sigma " -fore yellow
Write-Host "####################################################################" -fore yellow
	bash -c "cd $sigmaPath; git reset --hard;git pull"
	
Write-Host "##	Building pssigma commands for $sigmaRules using target $target" -fore yellow
Write-Host "####################################################################" -fore yellow

	bash -c "cd $sigmaPath && python3 ./tools/sigmac -t $target -rI $sigmaRules" > $pssigma_commands
Write-Host "##	Powershell Sigma commands saved at $pssigma_commands " -fore green 

Write-Host "##	Running commands to look for suspicious events based on SigmaRules for Windows " -fore yellow
Write-Host "####################################################################" -fore yellow

	echo "####################################################################" > $Results
	echo "## Sigma rules validation" >> $Results
	echo "####################################################################" >> $Results
	echo "" >> $Results

	$psSigmaCmd=[System.IO.File]::ReadLines($pssigma_commands)

	if ($target -eq 'powershell'){
	ForEach ($cmd in $psSigmaCmd) {
		if ($cmd -match '-logname '){
			$v='-logname '+$cmd.Split(' ')[2]
			$log=($cmd.Split(' ')[2] -replace '/', '%4') + '.evtx'
		}else{
			$log=''
		}
				
		if ($log -ne '')
		{
			$filterhash='-FilterHashtable @{path="'+$evidencePath+'\'+$evtPath+'\'+$log+'"}'		
			$sigmacmd=$cmd -replace $v, $filterhash
#			$cmdresult=iex($sigmacmd) 
			#if ($cmdresult.length -gt 0) {
				echo $sigmacmd >>$Results
				echo "####################################################" >> $Results
				echo "" >> $Results
			#	$cmdresult >> $Results
			#	Write-Host "[Findings]	Event identified " -fore red				
			#}
		}
	}
	}
	
	if ($target -eq 'grep'){
	echo "+ For faster results, try the rule against a specific date, ex:" >>$Results
	echo "  [command] rg -Ne '^YYYY-MM-DD' timeline.log|<command>" >>$Results
	echo "####################################################" >> $Results
	echo "" >> $Results
	
	ForEach ($cmd in $psSigmaCmd) {
		echo " * try: rg -Ne '^2020-' timeline.log|"($cmd -replace '\\', '\\') >>$Results
	}
	}
Write-Host "##	Process Finished. 							  					" -fore green
Write-Host "##	Sigma validation results saved at $Results				  		" -fore green

	bash -c "batcat $Results -l powershell"