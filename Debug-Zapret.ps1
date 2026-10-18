<#
  Debug-Zapret.ps1 v3 — изоляция причины: почему МИНИМАЛЬНЫЙ конфиг работает,
  а ПОЛНЫЙ (тот, что генерирует Fix-Zapret) ломает TLS.

  Берём РЕАЛЬНУЮ командную строку из Fix-Zapret (dot-source его функций)
  и проверяем её варианты, выключая подозрительные части по одной.
#>

$ErrorActionPreference = 'Continue'

$Src        = 'C:\Users\karachunn\Documents\deepseek-harness\default-workspace\zapret-fix\Fix-Zapret.ps1'
$ResultFile = 'C:\Users\karachunn\Documents\deepseek-harness\default-workspace\zapret-fix\debug2-result.txt'
$Bin        = 'C:\ProgramData\ZapretFix\bin'
$Lists      = 'C:\ProgramData\ZapretFix\lists'
$Winws      = Join-Path $Bin 'winws.exe'
$Tls        = Join-Path $Bin 'tls_clienthello_www_google_com.bin'

function Emit($s) { Write-Host $s; try { Add-Content -LiteralPath $ResultFile -Value $s -Encoding UTF8 } catch { } }

$isAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    try {
        $p = Start-Process -FilePath (Get-Process -Id $PID).Path -Verb RunAs -PassThru `
             -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $PSCommandPath + '"'))
        $p.WaitForExit()
    } catch { Write-Host "ОТКАЗ: $($_.Exception.Message)" -ForegroundColor Red }
    exit
}

Set-Content -LiteralPath $ResultFile -Value '=== DEBUG v3: изоляция конфига ===' -Encoding UTF8
Emit ("Время: {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))

# ---- подтягиваем функции Fix-Zapret без запуска его основной части ----
$text = [IO.File]::ReadAllText($Src, [Text.UTF8Encoding]::new($true))
$idx = $text.IndexOf('#  ТОЧКА ВХОДА')
if ($idx -lt 0) { Emit 'НЕ НАЙДЕН маркер точки входа'; exit }
$body = $text.Substring(0, $text.LastIndexOf('# ====', $idx))
$tmp = Join-Path $env:TEMP ('zf_' + [guid]::NewGuid().ToString('N') + '.ps1')
[IO.File]::WriteAllText($tmp, $body, [Text.UTF8Encoding]::new($true))
. $tmp -Mode Diagnose -NoElevate
Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
Emit 'Функции Fix-Zapret загружены'

$general = Join-Path $Lists 'list-general.txt'
$google  = Join-Path $Lists 'list-google.txt'
$excl    = Join-Path $Lists 'list-exclude.txt'
$ipexcl  = Join-Path $Lists 'ipset-exclude.txt'
$ipset   = Join-Path $Lists 'ipset-all.txt'

function Stop-W {
    Get-Process winws -ErrorAction SilentlyContinue | ForEach-Object { try { Stop-Process -Id $_.Id -Force } catch {} }
    Start-Sleep -Milliseconds 600
    foreach ($d in @('WinDivert','WinDivert1.4','WinDivert14')) {
        $q = (& sc.exe query $d 2>&1) -join ' '
        if ($q -match 'RUNNING') { & sc.exe stop $d 2>&1 | Out-Null }
    }
    Start-Sleep -Milliseconds 1200
}

function Probe1($label, $hostName, $path) {
    $r = Invoke-HttpRaw -Url "https://$hostName$path" -TimeoutMs 9000
    if ($r.Ok) { Emit ("      {0,-18} -> HTTP {1}  (TCP {2}ms, TLS {3}ms, {4})" -f $label, $r.Status, $r.TcpMs, $r.TlsMs, $r.Proto) }
    else       { Emit ("      {0,-18} -> ПРОВАЛ на '{1}': {2}" -f $label, $r.Stage, $r.Error) }
}

$TCPCORE = "--dpi-desync=fake,fakedsplit --dpi-desync-repeats=6 --dpi-desync-fooling=ts --dpi-desync-fakedsplit-pattern=0x00 --dpi-desync-fake-tls=$Tls"

# Реальный полный конфиг, который генерирует Fix-Zapret
$full = (New-WinwsCommandLine -Strategy ($Script:Strategies[0])).Args
Emit ""
Emit ("ПОЛНЫЙ конфиг Fix-Zapret ({0} символов):" -f $full.Length)
Emit ("   " + $full.Substring(0, [Math]::Min(240, $full.Length)) + ' ...')

$variants = @(
    @{ Name = 'A. МИНИМАЛЬНЫЙ (работал в отладке)'
       Args = "--wf-tcp=80,443 --filter-tcp=80,443 $TCPCORE" }

    @{ Name = 'B. МИНИМАЛЬНЫЙ + --ip-id=zero'
       Args = "--wf-tcp=80,443 --filter-tcp=80,443 --ip-id=zero $TCPCORE" }

    @{ Name = 'C. ПОЛНЫЙ КОНФИГ Fix-Zapret (как есть)'
       Args = $full }

    @{ Name = 'D. ПОЛНЫЙ, но без --ip-id=zero'
       Args = ($full -replace ' --ip-id=zero','') }

    @{ Name = 'E. ПОЛНЫЙ, но UDP выключен (--wf-udp=65000)'
       Args = ($full -replace '--wf-udp=[^ ]+','--wf-udp=65000') }

    @{ Name = 'F. ПОЛНЫЙ, но TCP только 80,443'
       Args = ($full -replace '--wf-tcp=[^ ]+','--wf-tcp=80,443') }

    @{ Name = 'G. ТОЛЬКО TCP-правила из полного (UDP-правила убраны)'
       Args = "--wf-tcp=80,443 --new --filter-tcp=443 --hostlist=$google --ip-id=zero $TCPCORE --new --filter-tcp=80,443 --hostlist=$general --hostlist-exclude=$excl --ipset-exclude=$ipexcl $TCPCORE" }
)

foreach ($v in $variants) {
    Emit ""
    Emit ("===== {0} =====" -f $v.Name)
    Stop-W
    try {
        $psi = New-Object Diagnostics.ProcessStartInfo
        $psi.FileName = $Winws; $psi.Arguments = $v.Args; $psi.WorkingDirectory = $Bin
        $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
        $p = [Diagnostics.Process]::Start($psi)
        Start-Sleep -Seconds 3
        if ($p.HasExited) { Emit ("   winws УПАЛ, код {0}" -f $p.ExitCode) }
    } catch { Emit ("   не запустился: $($_.Exception.Message)") }

    Probe1 'www.youtube.com' 'www.youtube.com' '/generate_204'
    Probe1 'discord.com'     'discord.com'     '/api/v9/gateway'
    Probe1 '1.1.1.1'         '1.1.1.1'         '/'
}

Stop-W
Emit ""
Emit '=== ГОТОВО ==='
