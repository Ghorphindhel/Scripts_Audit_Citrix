#Requires -Version 5.1
<# Audit en lecture seule. Exécution depuis un poste d'administration avec WinRM activé.
 .\Audit-DDC.ps1 -ComputerName DDC01,DDC02 -OutputPath .\Audit-DDC.csv
 .\Audit-DDC.ps1 -ServerList .\serveurs.txt -OutputPath .\Audit-DDC.csv
#>
[CmdletBinding(DefaultParameterSetName='Names')]
param(
 [Parameter(Mandatory,ParameterSetName='Names')][string[]]$ComputerName,
 [Parameter(Mandatory,ParameterSetName='File')][string]$ServerList,
 [string]$OutputPath = '.\Audit-DDC.csv',
 [pscredential]$Credential
)
if($PSCmdlet.ParameterSetName -eq 'File') { $ComputerName = @(Get-Content -LiteralPath $ServerList | Where-Object { $_.Trim() -and -not $_.Trim().StartsWith('#') }) }
$checks = @(
 @{Id='R1';Name='IIS absent'; Type='Feature'; Feature='Web-Server'; Expected='Absent'},
 @{Id='R3';Name='Spouleur arrêté et désactivé';Type='Service';Service='Spooler';Expected='Disabled/Stopped'},
 @{Id='R5';Name='BitLocker C: XTS-AES256';Type='BitLocker';Expected='On/XtsAes256'},
 @{Id='R6';Name='SMBv1 désactivé et signature obligatoire';Type='SMB';Expected='False/True'},
 @{Id='R7';Name='RDP NLA';Type='Registry';Path='HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp';Value='UserAuthentication';Expected=1},
 @{Id='R8a';Name='TLS 1.0 serveur désactivé';Type='Registry';Path='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server';Value='Enabled';Expected=0},
 @{Id='R8b';Name='TLS 1.1 serveur désactivé';Type='Registry';Path='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server';Value='Enabled';Expected=0},
 @{Id='R16';Name='IPv6 DisabledComponents (conditionnel)';Type='Registry';Path='HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters';Value='DisabledComponents';Expected=4294967295},
 @{Id='R27';Name='Politique PowerShell AllSigned';Type='ExecutionPolicy';Expected='AllSigned'},
 @{Id='R30';Name='Citrix Telemetry désactivée';Type='Registry';Path='HKLM:\SOFTWARE\Citrix\UniversalTelemetry';Value='EnableTelemetry';Expected=0},
 @{Id='R35';Name='Journal Security >= 1 Go';Type='EventLog';Expected=1073741824},
 @{Id='R37';Name='Ligne de commande création processus';Type='Registry';Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit';Value='ProcessCreationIncludeCmdLine_Enabled';Expected=1},
 @{Id='R39';Name='PowerShell Script Block Logging';Type='Registry';Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging';Value='EnableScriptBlockLogging';Expected=1},
 @{Id='R41';Name='LSASS RunAsPPL';Type='Registry';Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';Value='RunAsPPL';Expected=2},
 @{Id='R43';Name='ASR blocage vol identifiants';Type='ASR';Expected='Enabled'},
 @{Id='R38';Name='Audit logon succès/échec';Type='Audit';Expected='Success and Failure'}
)
$manual = @{
 R2='Pare-feu RPC/SMB : plages IP autorisées à fournir';R4='Windows Update : politique et calendrier à préciser';R9='TLS 1.2/1.3 : suites et compatibilité OS à préciser';R10='Segmentation réseau : audit firewall externe';R11='Citrix XML HTTPS : contrôle du listener et certificat';R12='Citrix Broker SSL : validation SDK Citrix';R13='Liste VDA autorisés : référence attendue nécessaire';R14='Chaîne SQL : validation Citrix et SQL';R15='DNSSEC : namespace réel nécessaire';R17='gMSA : comptes cibles nécessaires';R18='Domain Admins : comptes Citrix cibles nécessaires';R19='Droit accès réseau : groupes autorisés nécessaires';R20='Administrateurs locaux : liste approuvée nécessaire';R21='RBAC Citrix : rôles autorisés nécessaires';R22='Comptes génériques / MFA : contrôle IAM';R23='NTLM : stratégie et exceptions à préciser';R24='SQL sysadmin : accès SQL nécessaire';R25='SQL Express LHC : configuration instance';R26='AppLocker Studio : règles attendues nécessaires';R28='Compte hébergement : droits vCenter/Azure';R29='Certificat hyperviseur : empreinte attendue nécessaire';R31='XML trust : exception StoreFront à valider';R32='Applications anonymes : interrogation Citrix SDK';R33='Quotas Citrix : seuils attendus nécessaires';R34='Configuration Logging Citrix : interrogation SDK';R36='WEF : URL collecteur attendue nécessaire';R40='Antivirus Citrix : exclusions validées nécessaires';R42='Credential Guard : état VBS et exigences matériel';R44='AppLocker : règles de référence nécessaires'
}
$remote = {
 param($checks,$manual)
 $results = [System.Collections.Generic.List[object]]::new()
 function Add-Result($id,$name,$status,$expected,$actual,$detail) {
  $results.Add([pscustomobject]@{Serveur=$env:COMPUTERNAME;ID=$id;Controle=$name;Statut=$status;Attendu=[string]$expected;Observe=[string]$actual;Detail=[string]$detail})
 }
 foreach($c in $checks) {
  $actual='';$status='À vérifier';$detail=''
  try {
   switch($c.Type) {
    'Registry' {
     if(-not (Test-Path -LiteralPath $c.Path)) { $actual='Clé absente';$status='Non conforme';break }
     $p=Get-ItemProperty -LiteralPath $c.Path -Name $c.Value -ErrorAction Stop
     $actual=[string]$p.($c.Value)
     $status=if([uint64]$p.($c.Value) -eq [uint64]$c.Expected){'Conforme'}else{'Non conforme'}
    }
    'Service' { $s=Get-CimInstance Win32_Service -Filter "Name='$($c.Service)'" -ErrorAction Stop; $actual="$($s.StartMode)/$($s.State)"; $status=if($s.StartMode -eq 'Disabled' -and $s.State -eq 'Stopped'){'Conforme'}else{'Non conforme'} }
    'Feature' { $f=Get-WindowsFeature -Name $c.Feature -ErrorAction Stop; $actual=[string]$f.InstallState; $status=if(-not $f.Installed){'Conforme'}else{'Non conforme'}; $detail='Condition : IIS non co-localisé' }
    'SMB' { $s=Get-SmbServerConfiguration -ErrorAction Stop; $actual="$($s.EnableSMB1Protocol)/$($s.RequireSecuritySignature)"; $status=if(-not $s.EnableSMB1Protocol -and $s.RequireSecuritySignature){'Conforme'}else{'Non conforme'} }
    'BitLocker' { $b=Get-BitLockerVolume -MountPoint 'C:' -ErrorAction Stop; $actual="$($b.ProtectionStatus)/$($b.EncryptionMethod)"; $status=if($b.ProtectionStatus -eq 'On' -and $b.EncryptionMethod -eq 'XtsAes256'){'Conforme'}else{'Non conforme'}; $detail='Autres volumes à examiner séparément' }
    'ExecutionPolicy' { $actual=[string](Get-ExecutionPolicy -List | Where-Object Scope -in 'MachinePolicy','UserPolicy','LocalMachine' | Out-String).Trim();$effective=Get-ExecutionPolicy; $status=if($effective -eq 'AllSigned'){'Conforme'}else{'Non conforme'} }
    'EventLog' { $e=Get-WinEvent -ListLog Security -ErrorAction Stop; $actual=[string]$e.MaximumSizeInBytes;$status=if($e.MaximumSizeInBytes -ge $c.Expected){'Conforme'}else{'Non conforme'} }
    'ASR' { $p=Get-MpPreference -ErrorAction Stop; $guid='92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b';$i=[array]::IndexOf([string[]]$p.AttackSurfaceReductionRules_Ids,$guid);$actual=if($i -ge 0){[string]$p.AttackSurfaceReductionRules_Actions[$i]}else{'Non définie'};$status=if($i -ge 0 -and $actual -in @('1','Enabled')){'Conforme'}else{'Non conforme'} }
    'Audit' { $raw=& auditpol.exe /get /subcategory:'Logon' /r 2>&1; $actual=($raw | Out-String).Trim();$detail='Sortie brute : interprétation dépend de la langue du système';$status='À vérifier' }
   }
  } catch { $detail=$_.Exception.Message; $status='À vérifier'; if(-not $actual){$actual='Lecture impossible'} }
  if($c.Id -eq 'R16'){$detail='À appliquer uniquement si la désactivation IPv6 est décidée'}
  Add-Result $c.Id $c.Name $status $c.Expected $actual $detail
 }
 foreach($id in ($manual.Keys | Sort-Object { [int]($_ -replace '\D','') })) {Add-Result $id $manual[$id] 'À vérifier' 'Référence/contrôle complémentaire' '' 'Pas de verdict automatique fiable'}
 return $results
}
$all = foreach($server in $ComputerName) {
 try {
  $params=@{ComputerName=$server;ScriptBlock=$remote;ArgumentList=@($checks,$manual);ErrorAction='Stop'}
  if($Credential){$params.Credential=$Credential}
  Invoke-Command @params
 } catch {
  [pscustomobject]@{Serveur=$server;ID='CONNEXION';Controle='Connexion WinRM';Statut='Erreur';Attendu='Accessible';Observe='Inaccessible';Detail=$_.Exception.Message}
 }
}
$all | Sort-Object Serveur,ID | Export-Csv -LiteralPath $OutputPath -Delimiter ';' -NoTypeInformation -Encoding UTF8
$all | Group-Object Serveur,Statut | Select-Object Name,Count | Format-Table -AutoSize
Write-Host "Rapport : $((Resolve-Path $OutputPath).Path)"
