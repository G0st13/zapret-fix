#Requires -Version 5.1
<#
.SYNOPSIS
    ZapretFix - диагностика и починка обхода DPI для YouTube / Discord / Telegram без VPN.

.DESCRIPTION
    Скрипт делает то же, что winws из zapret, но:
      * сам находит рабочий комплект zapret на диске (bin/winws.exe + WinDivert);
      * копирует его в стабильный путь C:\ProgramData\ZapretFix (без пробелов и кириллицы);
      * восстанавливает испорченные списки (ipset-all.txt и т.п.);
      * добавляет в списки домены YouTube / Discord / Telegram / DoH;
      * поднимает DNS-over-HTTPS (обход подмены DNS провайдером);
      * вычищает мусор из hosts (фейковые домены, редиректы на мёртвые IP);
      * перебирает стратегии десинхронизации и автоматически выбирает рабочую;
      * ставит winws службой Windows с автозапуском;
      * отдельно диагностирует Telegram (IP-блок десинком не лечится) и предлагает MTProto/ WARP.

.PARAMETER Mode
    All        - диагностика + починка + подбор стратегии + запуск (по умолчанию)
    Diagnose   - только диагностика, ничего не меняет
    Repair     - копирование комплекта, hosts, DNS, списки (без запуска)
    Strategy   - перебор стратегий и запись лучшей в конфиг
    Start      - запустить службу
    Stop       - остановить службу
    Status     - показать состояние
    Restore    - откатить всё (hosts, DNS, служба, файлы)
    Telegram   - отдельная диагностика Telegram + список MTProto-прокси

.PARAMETER ZapretDir
    Каталог, откуда брать winws.exe (если автопоиск не нашёл нужное).

.PARAMETER SkipDns
    Не трогать настройки DNS.

.PARAMETER SkipHosts
    Не трогать файл hosts.

.PARAMETER DnsDesync
    Дополнительно десинхронизировать UDP/53 (если провайдер подменяет DNS напрямую).

.PARAMETER NoElevate
    Не перезапускаться с правами администратора (для проверки синтаксиса).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Fix-Zapret.ps1
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Fix-Zapret.ps1 -Mode Diagnose
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Fix-Zapret.ps1 -Mode Restore
#>

[CmdletBinding()]
param(
    [ValidateSet('All','Diagnose','Repair','Strategy','Start','Stop','Status','Restore','Telegram')]
    [string]$Mode = 'All',
    [string]$ZapretDir,
    [string]$ForceStrategy,
    [switch]$SkipDns,
    [switch]$SkipHosts,
    [switch]$DnsDesync,
    [switch]$NoElevate
)
$ErrorActionPreference = 'Continue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11

# =====================================================================================
#  ГЛОБАЛЬНЫЕ КОНСТАНТЫ
# =====================================================================================

$Script:Root      = Join-Path $env:ProgramData 'ZapretFix'
$Script:BinDir    = Join-Path $Script:Root 'bin'
$Script:ListsDir  = Join-Path $Script:Root 'lists'
$Script:LogDir    = Join-Path $Script:Root 'logs'
$Script:BakDir    = Join-Path $Script:Root 'backup'
$Script:ConfFile  = Join-Path $Script:Root 'active-strategy.txt'
$Script:ReportFile= Join-Path $Script:Root 'diagnose-report.txt'
$Script:ServiceName = 'zapret'
$Script:HostsFile = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'

$Script:LogFile = $null
$Script:Report  = New-Object System.Collections.Generic.List[string]

# Домены, которые обязательно должны быть в списках
$Script:ExtraGeneral = @(
    'youtube.com','www.youtube.com','m.youtube.com','youtu.be','youtube-nocookie.com',
    'googlevideo.com','ytimg.com','ggpht.com','googleusercontent.com','yt3.ggpht.com',
    'youtubei.googleapis.com','youtube-ui.l.google.com','wide-youtube.l.google.com',
    'discord.com','discord.gg','discordapp.com','discordapp.net','discord.media','discordcdn.com',
    'gateway.discord.gg','discordstatus.com','dis.gd',
    'telegram.org','telegram.me','telegram.dog','t.me','telegra.ph','telesco.pe',
    'cdn-telegram.org','tg.dev','graph.org','comments.app','contest.com','quiz.directory',
    'cloudflare-dns.com','mozilla.cloudflare-dns.com','dns.google','one.one.one.one'
)

$Script:ExtraGoogle = @(
    'youtube.com','www.youtube.com','m.youtube.com','youtu.be','ytimg.com','i.ytimg.com',
    'googlevideo.com','ggpht.com','gstatic.com','youtube-nocookie.com','yt3.ggpht.com',
    'youtubei.googleapis.com','youtube-ui.l.google.com'
)

# -------------------------------------------------------------------------------------
#  Стратегии десинхронизации (то, что подставляется в TCP-правила)
# -------------------------------------------------------------------------------------
$Script:Strategies = @(
    # --- ГЛАВНЫЕ: без хостлистов, десинкается весь TCP 80/443 ---
    # Проверено на этой сети: конфиги с --hostlist не матчатся вообще (ни одна
    # запись списка не срабатывает), а правило "весь TCP 80/443" работает.
    [pscustomobject]@{
        Name   = 'simple+ipid0'
        Desc   = 'ВЕСЬ TCP 80/443, fake+fakedsplit, ip-id=zero (проверено рабочим)'
        Tcp    = '--dpi-desync=fake,fakedsplit --dpi-desync-repeats=6 --dpi-desync-fooling=ts --dpi-desync-fakedsplit-pattern=0x00 --dpi-desync-fake-tls={TLS}'
        Simple = $true
        NoIpIdZero = $false
        NoUdp  = $false
        NoIpsetExclude = $true
    },
    [pscustomobject]@{
        Name   = 'simple'
        Desc   = 'ВЕСЬ TCP 80/443, fake+fakedsplit (без ip-id=zero)'
        Tcp    = '--dpi-desync=fake,fakedsplit --dpi-desync-repeats=6 --dpi-desync-fooling=ts --dpi-desync-fakedsplit-pattern=0x00 --dpi-desync-fake-tls={TLS}'
        Simple = $true
        NoIpIdZero = $true
        NoUdp  = $false
        NoIpsetExclude = $true
    },
    [pscustomobject]@{
        Name   = 'simple+tcp-only'
        Desc   = 'ВЕСЬ TCP 80/443, без правил для UDP (если ломается Discord-голос)'
        Tcp    = '--dpi-desync=fake,fakedsplit --dpi-desync-repeats=6 --dpi-desync-fooling=ts --dpi-desync-fakedsplit-pattern=0x00 --dpi-desync-fake-tls={TLS}'
        Simple = $true
        NoIpIdZero = $false
        NoUdp  = $true
        NoIpsetExclude = $true
    },
    [pscustomobject]@{
        Name   = 'simple+excl'
        Desc   = 'ВЕСЬ TCP 80/443 + защита локальных сетей через ipset-exclude'
        Tcp    = '--dpi-desync=fake,fakedsplit --dpi-desync-repeats=6 --dpi-desync-fooling=ts --dpi-desync-fakedsplit-pattern=0x00 --dpi-desync-fake-tls={TLS}'
        Simple = $true
        NoIpIdZero = $false
        NoUdp  = $false
        NoIpsetExclude = $false
    },

    # --- ЗАПАСНЫЕ: через хостлисты (на этой сети не сработали, но пусть будут) ---
    [pscustomobject]@{
        Name = 'fake+fakedsplit'
        Desc = 'FAKE + FAKEDSPLIT, fooling=ts (самая совместимая для РФ)'
        Tcp  = '--dpi-desync=fake,fakedsplit --dpi-desync-repeats=6 --dpi-desync-fooling=ts --dpi-desync-fakedsplit-pattern=0x00 --dpi-desync-fake-tls={TLS}'
        Simple = $false
    },
    [pscustomobject]@{
        Name = 'fake+multidisorder'
        Desc = 'FAKE TLS AUTO + MULTIDISORDER, fooling=badseq (обход с SNI-подменой)'
        Tcp  = '--dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,midsld --dpi-desync-repeats=11 --dpi-desync-fooling=badseq --dpi-desync-fake-tls=0x00000000 --dpi-desync-fake-tls=! --dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com'
        Simple = $false
    },
    [pscustomobject]@{
        Name = 'multisplit+seqovl'
        Desc = 'MULTISPLIT с перекрытием последовательности (split-seqovl=652)'
        Tcp  = '--dpi-desync=multisplit --dpi-desync-split-seqovl=652 --dpi-desync-split-pos=2 --dpi-desync-split-seqovl-pattern={TLS}'
        Simple = $false
    },
    [pscustomobject]@{
        Name = 'disorder2'
        Desc = 'DISORDER2 - разворот двух первых сегментов'
        Tcp  = '--dpi-desync=disorder2 --dpi-desync-split-pos=1'
        Simple = $false
    },
    [pscustomobject]@{
        Name = 'split2'
        Desc = 'SPLIT2 - разрез ClientHello на втором байте'
        Tcp  = '--dpi-desync=split2 --dpi-desync-split-pos=2'
        Simple = $false
    },
    [pscustomobject]@{
        Name = 'fake-only'
        Desc = 'Только FAKE с фейковым ClientHello'
        Tcp  = '--dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-tls={TLS}'
        Simple = $false
    },
    [pscustomobject]@{
        Name = 'multidisorder'
        Desc = 'MULTIDISORDER без фейка'
        Tcp  = '--dpi-desync=multidisorder --dpi-desync-split-pos=1,midsld'
        Simple = $false
    },
    [pscustomobject]@{
        Name = 'fake+split2+ttl'
        Desc = 'FAKE + SPLIT2 с малым TTL (фейк не доходит до сервера)'
        Tcp  = '--dpi-desync=fake,split2 --dpi-desync-ttl=2 --dpi-desync-repeats=6 --dpi-desync-fake-tls={TLS}'
        Simple = $false
    }
)

# =====================================================================================
#  БЛОК 1. СЛУЖЕБНЫЕ ФУНКЦИИ
# =====================================================================================

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','OK','WARN','ERR','STEP')][string]$Level = 'INFO'
    )
    $stamp = Get-Date -Format 'HH:mm:ss'
    $color = switch ($Level) {
        'OK'   { 'Green' }
        'WARN' { 'Yellow' }
        'ERR'  { 'Red' }
        'STEP' { 'Cyan' }
        default{ 'Gray' }
    }
    $prefix = switch ($Level) {
        'OK'   { '[ + ]' }
        'WARN' { '[ ! ]' }
        'ERR'  { '[ x ]' }
        'STEP' { '[ > ]' }
        default{ '[ . ]' }
    }
    Write-Host "$prefix $Message" -ForegroundColor $color
    $line = "$stamp $Level $Message"
    $Script:Report.Add($line) | Out-Null
    if ($Script:LogFile) { Add-Content -LiteralPath $Script:LogFile -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue }
}

function Write-Head {
    param([string]$Text)
    $bar = '=' * 74
    Write-Host ""
    Write-Host $bar -ForegroundColor DarkCyan
    Write-Host "  $Text" -ForegroundColor White
    Write-Host $bar -ForegroundColor DarkCyan
    $Script:Report.Add("") | Out-Null
    $Script:Report.Add("=== $Text ===") | Out-Null
}

function Test-Admin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $pr = New-Object Security.Principal.WindowsPrincipal($id)
        return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Invoke-SelfElevate {
    <# Перезапускает скрипт от администратора, передавая те же параметры #>
    $exe = (Get-Process -Id $PID).Path
    if (-not $exe) { $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe' }

    $argList = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $PSCommandPath + '"'),'-Mode',$Mode)
    if ($ZapretDir)  { $argList += @('-ZapretDir', ('"' + $ZapretDir + '"')) }
    if ($ForceStrategy) { $argList += @('-ForceStrategy', $ForceStrategy) }
    if ($SkipDns)    { $argList += '-SkipDns' }
    if ($SkipHosts)  { $argList += '-SkipHosts' }
    if ($DnsDesync)  { $argList += '-DnsDesync' }

    Write-Host "[ > ] Требуются права администратора, запрашиваю UAC..." -ForegroundColor Cyan
    try {
        $p = Start-Process -FilePath $exe -ArgumentList $argList -Verb RunAs -PassThru
        $p.WaitForExit()
        exit $p.ExitCode
    } catch {
        Write-Host "[ x ] Не удалось получить права администратора: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "      Запусти PowerShell от имени администратора и повтори." -ForegroundColor Yellow
        exit 1
    }
}

function New-Backup {
    param([string]$Tag)
    $dir = Join-Path $Script:BakDir ((Get-Date -Format 'yyyy-MM-dd_HH-mm-ss') + "_$Tag")
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    return $dir
}

function Backup-File {
    param([string]$Path, [string]$DestDir)
    if (Test-Path -LiteralPath $Path) {
        Copy-Item -LiteralPath $Path -Destination (Join-Path $DestDir ([IO.Path]::GetFileName($Path))) -Force -ErrorAction SilentlyContinue
        return $true
    }
    return $false
}

function Ensure-Dirs {
    foreach ($d in @($Script:Root,$Script:BinDir,$Script:ListsDir,$Script:LogDir,$Script:BakDir)) {
        if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    }
    if (-not $Script:LogFile) {
        $Script:LogFile = Join-Path $Script:LogDir ("zapretfix_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    }
}

# -------------------------------------------------------------------------------------
#  Сетевые проверки
# -------------------------------------------------------------------------------------

function Test-TcpPort {
    param([string]$Target, [int]$Port, [int]$TimeoutMs = 4000)
    $client = New-Object Net.Sockets.TcpClient
    try {
        $task = $client.ConnectAsync($Target, $Port)
        $done = $task.Wait($TimeoutMs)
        if (-not $done) { return 'timeout' }
        if ($client.Connected) { return 'ok' }
        return 'timeout'
    } catch {
        return 'reset'
    } finally {
        try { $client.Close() } catch {}
    }
}

function Invoke-HttpRaw {
    <#
      HTTP-запрос через СЫРЫЕ сокеты: TcpClient + SslStream, своё соединение на каждый вызов.

      ПОЧЕМУ НЕ HttpWebRequest: он держит пул соединений (ServicePoint). Если запрос к
      хосту однажды упал по таймауту, .NET помечает соединение и все последующие
      запросы к тому же хосту падают МГНОВЕННО, даже когда канал уже работает.
      Именно из-за этого автоподбор стратегий показывал score 0 на рабочей стратегии.

      Возвращает: Ok, Status, Stage (dns|tcp|tls|http), Error, Ms, TcpMs, TlsMs, Bytes, Kbps, Proto, Ip
    #>
    param(
        [Parameter(Mandatory)][string]$Url,
        [int]$TimeoutMs = 10000,
        [int]$MaxBytes  = 0,
        [string]$ExtraHeaders = 'Accept: */*'
    )

    $r = [pscustomobject]@{
        Ok=$false; Status=0; Stage=''; Error=''; Ms=0
        TcpMs=0; TlsMs=0; Bytes=0; Kbps=0; Proto=''; Ip=''
    }
    $swTotal = [Diagnostics.Stopwatch]::StartNew()

    # --- разбор URL ---
    if ($Url -notmatch '^(https?)://([^/:]+)(?::(\d+))?(/.*)?$') {
        $r.Stage='url'; $r.Error='не удалось разобрать URL'; return $r
    }
    $scheme = $Matches[1]
    $hostName = $Matches[2]
    $port = if ($Matches[3]) { [int]$Matches[3] } else { if ($scheme -eq 'https') { 443 } else { 80 } }
    $path = if ($Matches[4]) { $Matches[4] } else { '/' }

    # --- DNS ---
    $ip = $hostName
    if ($hostName -notmatch '^\d+\.\d+\.\d+\.\d+$') {
        try {
            $ips = @(Resolve-DnsName -Name $hostName -Type A -ErrorAction Stop |
                     Where-Object { $_.IPAddress } | ForEach-Object { $_.IPAddress })
            if ($ips.Count -eq 0) { $r.Stage='dns'; $r.Error='имя не разрешается'; return $r }
            $ip = $ips[0]
        } catch {
            $r.Stage='dns'; $r.Error="DNS: $($_.Exception.Message)"; return $r
        }
    }
    $r.Ip = $ip

    # --- TCP ---
    $client = New-Object Net.Sockets.TcpClient
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        if (-not $client.ConnectAsync($ip, $port).Wait($TimeoutMs)) {
            $sw.Stop(); $r.TcpMs=$sw.ElapsedMilliseconds; $r.Stage='tcp'; $r.Error='таймаут подключения'; return $r
        }
    } catch {
        $sw.Stop(); $r.TcpMs=$sw.ElapsedMilliseconds; $r.Stage='tcp'
        $r.Error = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
        try { $client.Close() } catch {}
        return $r
    }
    $sw.Stop(); $r.TcpMs = $sw.ElapsedMilliseconds

    # --- TLS ---
    $stream = $null
    if ($scheme -eq 'https') {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        try {
            $ssl = New-Object Net.Security.SslStream($client.GetStream(), $false, ({ param($a,$b,$cc,$d) $true }))
            $ssl.ReadTimeout = $TimeoutMs
            $ssl.WriteTimeout = $TimeoutMs
            $ssl.AuthenticateAsClient($hostName)
            $stream = $ssl
            $r.Proto = "$($ssl.SslProtocol)"
        } catch {
            $sw.Stop(); $r.TlsMs=$sw.ElapsedMilliseconds; $r.Stage='tls'
            $r.Error = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
            try { $client.Close() } catch {}
            return $r
        }
        $sw.Stop(); $r.TlsMs = $sw.ElapsedMilliseconds
    } else {
        $stream = $client.GetStream()
    }

    # --- HTTP ---
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        $stream.ReadTimeout = $TimeoutMs
        $stream.WriteTimeout = $TimeoutMs
        $head = "GET $path HTTP/1.0`r`nHost: $hostName`r`nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)`r`n$ExtraHeaders`r`nConnection: close`r`n`r`n"
        $b = [Text.Encoding]::ASCII.GetBytes($head)
        $stream.Write($b, 0, $b.Length)
        $stream.Flush()

        $buf = New-Object byte[] 16384
        $total = 0
        $headerText = ''
        $bodyStart = -1
        $deadline = $TimeoutMs

        while ($true) {
            if ($sw.ElapsedMilliseconds -gt $deadline) { break }
            $n = 0
            try { $n = $stream.Read($buf, 0, $buf.Length) } catch { break }
            if ($n -le 0) { break }
            $total += $n
            if ($bodyStart -lt 0) {
                $headerText += [Text.Encoding]::ASCII.GetString($buf, 0, $n)
                $idx = $headerText.IndexOf("`r`n`r`n")
                if ($idx -ge 0) { $bodyStart = $idx + 4 }
            }
            if ($MaxBytes -gt 0 -and $total -ge $MaxBytes) { break }
        }

        $r.Bytes = $total
        if ($headerText -match '^HTTP/\d\.\d\s+(\d{3})') {
            $r.Status = [int]$Matches[1]
            $r.Ok = ($r.Status -ge 200 -and $r.Status -lt 400)
        } else {
            $r.Stage='http'; $r.Error='сервер не ответил (пусто)'
        }
    } catch {
        $r.Stage='http'
        $r.Error = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
    } finally {
        $sw.Stop()
        try { if ($stream) { $stream.Close() } } catch {}
        try { $client.Close() } catch {}
        $swTotal.Stop()
        $r.Ms = $swTotal.ElapsedMilliseconds
        if ($r.Ms -gt 0 -and $r.Bytes -gt 0) {
            $r.Kbps = [math]::Round(($r.Bytes / 1024) / ($r.Ms / 1000), 0)
        }
    }
    return $r
}

function Test-Https {
    <# Тонкая обёртка над Invoke-HttpRaw для обратной совместимости #>
    param([string]$Url, [int]$TimeoutMs = 12000, [switch]$Download)
    $max = if ($Download) { 400000 } else { 0 }
    $r = Invoke-HttpRaw -Url $Url -TimeoutMs $TimeoutMs -MaxBytes $max
    return [pscustomobject]@{ Ok=$r.Ok; Status=$r.Status; Ms=$r.Ms; Bytes=$r.Bytes; Error=$r.Error }
}

function Resolve-ViaDoh {
    <# Разрешает имя через Cloudflare DoH (сырыми сокетами). Возвращает массив IP или $null #>
    param([string]$Name, [int]$TimeoutMs = 8000)
    foreach ($ep in @('https://1.1.1.1/dns-query', 'https://cloudflare-dns.com/dns-query')) {
        $obj = Get-DohBody -Url "$ep`?name=$Name&type=A" -TimeoutMs $TimeoutMs
        if (-not $obj) { continue }
        $ips = @($obj.Answer | Where-Object { $_.type -eq 1 } | ForEach-Object { $_.data })
        if ($ips.Count -gt 0) { return $ips }
    }
    return $null
}

function Get-UrlText {
    <# Забирает ТЕЛО https-ответа строкой (сырые сокеты, без пулинга). Для DoH и JSON-API. #>
    param([Parameter(Mandatory)][string]$Url, [int]$TimeoutMs = 8000, [string]$Accept = 'application/json')

    try {
        $uri = [Uri]$Url
        $client = New-Object Net.Sockets.TcpClient
        if (-not $client.ConnectAsync($uri.Host, $uri.Port).Wait($TimeoutMs)) { $client.Close(); return $null }
        $ssl = New-Object Net.Security.SslStream($client.GetStream(), $false, ({ param($a,$b,$c,$d) $true }))
        $ssl.ReadTimeout = $TimeoutMs; $ssl.WriteTimeout = $TimeoutMs
        $ssl.AuthenticateAsClient($uri.Host)
        $head = "GET $($uri.PathAndQuery) HTTP/1.1`r`nHost: $($uri.Host)`r`nAccept: $Accept`r`nUser-Agent: Mozilla/5.0 (ZapretFix)`r`nConnection: close`r`n`r`n"
        $b = [Text.Encoding]::ASCII.GetBytes($head)
        $ssl.Write($b, 0, $b.Length); $ssl.Flush()
        $sr = New-Object IO.StreamReader($ssl)
        $all = $sr.ReadToEnd()
        $sr.Close(); $ssl.Close(); $client.Close()

        $i = $all.IndexOf("`r`n`r`n")
        if ($i -lt 0) { return $null }
        $body = $all.Substring($i + 4)
        if ($all -match 'Transfer-Encoding:\s*chunked') {
            $sb = New-Object Text.StringBuilder
            $pos = 0
            while ($pos -lt $body.Length) {
                $nl = $body.IndexOf("`r`n", $pos)
                if ($nl -lt 0) { break }
                $lenHex = $body.Substring($pos, $nl - $pos).Trim()
                $len = 0
                if (-not [int]::TryParse($lenHex, [Globalization.NumberStyles]::HexNumber, $null, [ref]$len)) { break }
                if ($len -eq 0) { break }
                $start = $nl + 2
                if ($start + $len -gt $body.Length) { break }
                [void]$sb.Append($body.Substring($start, $len))
                $pos = $start + $len + 2
            }
            $body = $sb.ToString()
        }
        return $body
    } catch { return $null }
}

function Get-DohBody {
    <# Тело DoH-ответа в виде разобранного JSON #>
    param([string]$Url, [int]$TimeoutMs = 8000)
    $body = Get-UrlText -Url $Url -TimeoutMs $TimeoutMs -Accept 'application/dns-json'
    if (-not $body) { return $null }
    try { return ($body | ConvertFrom-Json) } catch { return $null }
}

function Get-LocalAdapters {
    <#
      Список активных адаптеров с IPv4-адресом, шлюзом и DNS.
      Три уровня отказоустойчивости: NetTCPIP-командлеты -> .NET -> CIM.
    #>
    $out = New-Object System.Collections.Generic.List[object]

    # --- уровень 1: командлеты NetTCPIP ---
    try {
        $cfgs = Get-NetIPConfiguration -ErrorAction Stop
        foreach ($c in $cfgs) {
            if ($c.NetAdapter -and $c.NetAdapter.Status -eq 'Up' -and $c.IPv4Address) {
                $out.Add([pscustomobject]@{
                    Alias   = $c.InterfaceAlias
                    Index   = [int]$c.InterfaceIndex
                    IPv4    = ($c.IPv4Address | Select-Object -First 1).IPAddress
                    Gateway = ($c.IPv4DefaultGateway | Select-Object -First 1).NextHop
                    Dns     = @($c.DNSServer | Where-Object { $_.AddressFamily -eq 2 } |
                                ForEach-Object { $_.ServerAddresses } | ForEach-Object { $_ })
                }) | Out-Null
            }
        }
    } catch { }

    # --- уровень 2: чистый .NET (работает всегда, зависимостей нет) ---
    if ($out.Count -eq 0) {
        try {
            $nics = [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()
            foreach ($nic in $nics) {
                if ($nic.OperationalStatus -ne 'Up') { continue }
                if ($nic.NetworkInterfaceType -eq 'Loopback') { continue }
                $props = $nic.GetIPProperties()
                $v4 = @($props.UnicastAddresses | Where-Object { $_.Address.AddressFamily -eq 'InterNetwork' })
                if ($v4.Count -eq 0) { continue }
                $idx = 0
                try { $idx = [int]$props.GetIPv4Properties().Index } catch { $idx = 0 }
                $gw = ($props.GatewayAddresses | Where-Object { $_.Address.AddressFamily -eq 'InterNetwork' } |
                       Select-Object -First 1)
                $out.Add([pscustomobject]@{
                    Alias   = $nic.Name
                    Index   = $idx
                    IPv4    = $v4[0].Address.IPAddressToString
                    Gateway = if ($gw) { $gw.Address.IPAddressToString } else { '' }
                    Dns     = @($props.DnsAddresses | Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
                                ForEach-Object { $_.IPAddressToString })
                }) | Out-Null
            }
        } catch { }
    }

    # --- уровень 3: CIM (последний шанс) ---
    if ($out.Count -eq 0) {
        try {
            $cim = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop
            foreach ($c in $cim) {
                $out.Add([pscustomobject]@{
                    Alias   = $c.Description
                    Index   = [int]$c.InterfaceIndex
                    IPv4    = @($c.IPAddress | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }) | Select-Object -First 1
                    Gateway = @($c.DefaultIPGateway) | Select-Object -First 1
                    Dns     = @($c.DNSServerSearchOrder)
                }) | Out-Null
            }
        } catch { }
    }

    if ($out.Count -eq 0) {
        Write-Log 'Не удалось перечислить сетевые адаптеры (все три способа не сработали)' 'WARN'
    }
    return $out
}

# -------------------------------------------------------------------------------------
#  Поиск и подготовка комплекта zapret
# -------------------------------------------------------------------------------------

function Find-ZapretToolchain {
    <# Ищет каталог, в котором лежат winws.exe + WinDivert.dll + WinDivert64.sys #>
    $candidates = New-Object System.Collections.Generic.List[string]

    if ($ZapretDir) {
        $candidates.Add($ZapretDir) | Out-Null
        $candidates.Add((Join-Path $ZapretDir 'bin')) | Out-Null
    }
    # наш собственный стабильный каталог
    $candidates.Add($Script:BinDir) | Out-Null

    # типовые места
    # ВАЖНО: каждый элемент - ОДНА строка. Внутри @() нельзя писать "a" + "b":
    # запятая в PowerShell связывает крепче плюса, и весь список склеится в одну строку.
    $seeds = @(
        "$env:ProgramData\ZapretTwo\exe",
        "$env:ProgramData\ZapretTwo\bin",
        "$env:ProgramData\ZapretTwo",
        "$env:ProgramData\zapret\bin",
        "$env:ProgramData\zapret",
        'C:\zapret\bin',
        'C:\zapret',
        'C:\GoodbyeDPI',
        'C:\tools',
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\Documents"
    )
    foreach ($s in $seeds) {
        if (-not (Test-Path -LiteralPath $s)) { continue }
        $candidates.Add($s) | Out-Null
        $candidates.Add((Join-Path $s 'bin')) | Out-Null
        # один уровень вглубь
        try {
            Get-ChildItem -LiteralPath $s -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $candidates.Add($_.FullName) | Out-Null
                $candidates.Add((Join-Path $_.FullName 'bin')) | Out-Null
            }
        } catch { }
    }

    $found = New-Object System.Collections.Generic.List[object]
    foreach ($c in $candidates) {
        if (-not $c) { continue }
        if (-not (Test-Path -LiteralPath $c)) { continue }
        $winws  = Join-Path $c 'winws.exe'
        $wddll  = Join-Path $c 'WinDivert.dll'
        if ((Test-Path -LiteralPath $winws) -and (Test-Path -LiteralPath $wddll)) {
            $sys = @(Get-ChildItem -LiteralPath $c -Filter 'WinDivert*.sys' -ErrorAction SilentlyContinue).Count
            $obj = [pscustomobject]@{
                Path    = $c
                Winws   = $winws
                HasSys  = ($sys -gt 0)
                Size    = (Get-Item -LiteralPath $winws).Length
                Score   = 0
            }
            $obj.Score = 0
            if ($obj.HasSys) { $obj.Score += 10 }
            if ($c -like '*ProgramData*') { $obj.Score += 3 }
            if ($c -notmatch '[^\x00-\x7F]') { $obj.Score += 5 }   # путь без кириллицы
            if ($c -notmatch '\s') { $obj.Score += 3 }             # путь без пробелов
            if (Test-Path -LiteralPath (Join-Path $c 'tls_clienthello_www_google_com.bin')) { $obj.Score += 5 }
            if (Test-Path -LiteralPath (Join-Path $c 'quic_initial_www_google_com.bin')) { $obj.Score += 5 }

            # НАШ СОБСТВЕННЫЙ КАТАЛОГ - это ПРИЁМНИК, а не источник.
            # Если выбрать его, Install-Lists начнёт копировать списки сам в себя
            # и резервный ipset-all.txt.backup никогда не будет найден.
            # Оставляем его только как самый последний вариант (если оригинала уже нет).
            if ($c -eq $Script:BinDir -or $c -eq $Script:Root -or $c -like "$Script:Root*") {
                $obj.Score -= 100
            }
            $found.Add($obj) | Out-Null
        }
    }

    # убрать дубликаты и отсортировать по пригодности
    $uniq = $found | Sort-Object Path -Unique | Sort-Object Score -Descending
    return $uniq
}

function Install-Toolchain {
    <# Копирует найденный комплект в C:\ProgramData\ZapretFix\bin (стабильный путь) #>
    param([Parameter(Mandatory)]$Source)

    Ensure-Dirs
    $need = @('winws.exe','WinDivert.dll','cygwin1.dll',
              'tls_clienthello_www_google_com.bin','quic_initial_www_google_com.bin')
    $copied = 0
    foreach ($f in $need) {
        $src = Join-Path $Source.Path $f
        if (Test-Path -LiteralPath $src) {
            Copy-Item -LiteralPath $src -Destination (Join-Path $Script:BinDir $f) -Force -ErrorAction SilentlyContinue
            $copied++
        }
    }
    # WinDivert64.sys может называться иначе (Monkey64.sys, aaaaaaaaa1 и т.п.)
    $sysFile = Get-ChildItem -LiteralPath $Source.Path -Filter '*.sys' -ErrorAction SilentlyContinue |
               Sort-Object Length -Descending | Select-Object -First 1
    if ($sysFile) {
        Copy-Item -LiteralPath $sysFile.FullName -Destination (Join-Path $Script:BinDir 'WinDivert64.sys') -Force -ErrorAction SilentlyContinue
        $copied++
    }
    # остальные .bin-пейлоады
    Get-ChildItem -LiteralPath $Source.Path -Filter '*.bin' -ErrorAction SilentlyContinue | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $Script:BinDir $_.Name) -Force -ErrorAction SilentlyContinue
        $copied++
    }
    return $copied
}

function Install-Lists {
    <# Копирует и лечит списки. Возвращает статистику #>
    param($Source)

    Ensure-Dirs
    $srcLists = Join-Path $Source.Path 'lists'
    if (-not (Test-Path -LiteralPath $srcLists)) {
        # списки могут лежать на уровень выше bin
        $srcLists = Join-Path (Split-Path $Source.Path -Parent) 'lists'
    }
    # ЗАЩИТА ОТ САМОКОПИРОВАНИЯ: если источник совпал с приёмником,
    # копирование бессмысленно и .backup не найдётся никогда.
    if ($srcLists -eq $Script:ListsDir) {
        Write-Log "Источник списков совпал с приёмником ($srcLists) - копирование пропущено" 'WARN'
        $srcLists = $null
    }

    $stat = [pscustomobject]@{ Copied=0; IpsetRestored=$false; IpsetLines=0 }

    if ($srcLists -and (Test-Path -LiteralPath $srcLists)) {
        # ВАЖНО: берём и *.txt, и *.backup. Резервная копия ipset-all.txt.backup
        # (210 КБ реальных подсетей) - единственный источник восстановления,
        # если основной файл затёрт заглушкой.
        Get-ChildItem -LiteralPath $srcLists -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like '*.txt' -or $_.Name -like '*.backup' } | ForEach-Object {
                Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $Script:ListsDir $_.Name) -Force -ErrorAction SilentlyContinue
                if (Test-Path -LiteralPath (Join-Path $Script:ListsDir $_.Name)) { $stat.Copied++ }
                else { Write-Log ("  не удалось скопировать: {0}" -f $_.Name) 'WARN' }
            }
        Write-Log ("Списки взяты из: {0} (файлов: {1})" -f $srcLists, $stat.Copied) 'INFO'
    }

    if (-not (Test-Path -LiteralPath $Script:ListsDir)) { New-Item -ItemType Directory -Path $Script:ListsDir -Force | Out-Null }

    # --- восстановление ipset-all.txt из .backup, если он «пустой» ---
    $ipset = Join-Path $Script:ListsDir 'ipset-all.txt'
    $ipsetBak = Join-Path $Script:ListsDir 'ipset-all.txt.backup'
    $needRestore = $true
    if (Test-Path -LiteralPath $ipset) {
        $len = (Get-Item -LiteralPath $ipset).Length
        if ($len -gt 5000) { $needRestore = $false }
    }
    if ($needRestore -and (Test-Path -LiteralPath $ipsetBak)) {
        Copy-Item -LiteralPath $ipsetBak -Destination $ipset -Force
        $stat.IpsetRestored = $true
        Write-Log "ipset-all.txt восстановлен из .backup" 'OK'
    }
    if (-not (Test-Path -LiteralPath $ipset)) {
        # создаём минимальный осмысленный ipset
        @(
            '# ZapretFix: базовый ipset (дополняется при необходимости)'
            '142.250.0.0/15'
            '172.217.0.0/16'
            '216.58.0.0/16'
            '173.194.0.0/16'
            '74.125.0.0/16'
            '64.233.0.0/16'
            '162.159.0.0/16'
            '104.16.0.0/13'
        ) | Set-Content -LiteralPath $ipset -Encoding ASCII
    }
    $stat.IpsetLines = @(Get-Content -LiteralPath $ipset -ErrorAction SilentlyContinue).Count

    # --- обязательные списки, если их нет ---
    $general = Join-Path $Script:ListsDir 'list-general.txt'
    if (-not (Test-Path -LiteralPath $general)) { New-Item -ItemType File -Path $general -Force | Out-Null }
    $google = Join-Path $Script:ListsDir 'list-google.txt'
    if (-not (Test-Path -LiteralPath $google)) { New-Item -ItemType File -Path $google -Force | Out-Null }
    $excl = Join-Path $Script:ListsDir 'list-exclude.txt'
    if (-not (Test-Path -LiteralPath $excl)) { New-Item -ItemType File -Path $excl -Force | Out-Null }
    $ipexcl = Join-Path $Script:ListsDir 'ipset-exclude.txt'
    if (-not (Test-Path -LiteralPath $ipexcl)) {
        @('0.0.0.0/8','10.0.0.0/8','127.0.0.0/8','172.16.0.0/12','192.168.0.0/16',
          '169.254.0.0/16','224.0.0.0/4','100.64.0.0/10','::1','fc00::/7','fe80::/10') |
            Set-Content -LiteralPath $ipexcl -Encoding ASCII
    }

    return $stat
}

function Convert-ListsToLf {
    <#
      Приводит переводы строк в списках к LF.

      zapret родом из Linux, и его парсер hostlist ожидает LF. Файлы, дописанные
      через Add-Content, получают CRLF; при смешивании часть строк может не
      сопоставляться. Нормализация безвредна и снимает этот класс проблем.
    #>
    if (-not (Test-Path -LiteralPath $Script:ListsDir)) { return 0 }
    $n = 0
    Get-ChildItem -LiteralPath $Script:ListsDir -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like '*.txt' } | ForEach-Object {
            try {
                $c = [IO.File]::ReadAllText($_.FullName)
                if ($c -match "`r`n") {
                    $c = $c -replace "`r`n", "`n"
                    [IO.File]::WriteAllText($_.FullName, $c, [Text.Encoding]::ASCII)
                    $n++
                }
            } catch { }
        }
    return $n
}

function Add-DomainsToList {
    <# Дописывает домены в список, если их там нет #>
    param([string]$File, [string[]]$Domains)
    if (-not (Test-Path -LiteralPath $File)) { New-Item -ItemType File -Path $File -Force | Out-Null }
    $existing = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    Get-Content -LiteralPath $File -ErrorAction SilentlyContinue | ForEach-Object {
        $l = $_.Trim()
        if ($l -and -not $l.StartsWith('#')) { [void]$existing.Add($l) }
    }
    $added = 0
    foreach ($d in $Domains) {
        if (-not $existing.Contains($d)) {
            Add-Content -LiteralPath $File -Value $d -Encoding ASCII
            [void]$existing.Add($d)
            $added++
        }
    }
    return $added
}

# =====================================================================================
#  БЛОК 2. HOSTS
# =====================================================================================

function Repair-Hosts {
    <#
      Чистит подозрительные записи и делает бэкап.
      ВАЖНО: hosts — ASCII-файл, поэтому все служебные комментарии пишем
      ЛАТИНИЦЕЙ, иначе кириллица превратится в "????".
    #>
    param([switch]$RemoveYoutubePins)

    if (-not (Test-Path -LiteralPath $Script:HostsFile)) {
        Write-Log "hosts не найден: $Script:HostsFile" 'WARN'
        return
    }
    $bak = New-Backup 'hosts'
    Backup-File -Path $Script:HostsFile -DestDir $bak | Out-Null
    Write-Log "Бэкап hosts -> $bak" 'INFO'

    $lines = Get-Content -LiteralPath $Script:HostsFile -ErrorAction SilentlyContinue
    if (-not $lines) { $lines = @() }

    # IP-заглушки, на которые перенаправляют трафик «оптимизаторы» и кряки
    $badIps = @('74.119.194.9','0.0.0.0','127.0.0.1')
    $removed = New-Object System.Collections.Generic.List[string]
    $kept    = New-Object System.Collections.Generic.List[string]
    $seen    = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

    foreach ($line in $lines) {
        $trim = $line.Trim()
        if (-not $trim)            { continue }
        if ($trim.StartsWith('#')) { continue }   # старые комментарии не тащим: пишем свой заголовок
        $parts = $trim -split '\s+'
        if ($parts.Count -lt 2) { $kept.Add($trim); continue }
        $ip = $parts[0]
        $hosts = $parts[1..($parts.Count-1)] | Where-Object { -not $_.StartsWith('#') }

        $isBad = $false
        $why = ''
        if ($badIps -contains $ip) { $isBad = $true; $why = 'stub-ip' }
        foreach ($h in $hosts) {
            if ($h -match 'fitgirl|repack|torrent' -and $ip -eq '109.94.209.70') { $isBad = $true; $why = 'fake-piracy-site' }
            if ($h -match '(^|\.)youtube\.com$') {
                if ($ip -notmatch '^(142\.250\.|172\.217\.|216\.58\.|74\.125\.|173\.194\.|64\.233\.|209\.85\.)') {
                    $isBad = $true; $why = 'youtube-hijack'
                } elseif ($RemoveYoutubePins) {
                    # DNS уже починен через DoH - жёсткий пин только вредит: CDN выбирается по DNS
                    $isBad = $true; $why = 'youtube-pin'
                }
            }
        }
        if ($isBad) {
            $removed.Add("$why : $trim") | Out-Null
        } elseif ($seen.Add($trim)) {
            $kept.Add($trim)
        } else {
            $removed.Add("duplicate : $trim") | Out-Null
        }
    }

    if ($removed.Count -eq 0) {
        Write-Log 'hosts: подозрительных записей не найдено' 'OK'
        return 0
    }

    $hdr = @(
        '# ZapretFix: hosts cleaned ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        ('# Removed entries: {0} (full list in backup and log)' -f $removed.Count)
        '#'
        '# --- active entries ---'
    )
    $out = $hdr + $kept
    Set-Content -LiteralPath $Script:HostsFile -Value $out -Encoding ASCII
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    Write-Log ("hosts: удалено подозрительных записей: {0}" -f $removed.Count) 'OK'
    foreach ($r in $removed) { Write-Log ("  - " + $r) 'INFO' }
    return $removed.Count
}

# =====================================================================================
#  БЛОК 3. DNS / DoH
# =====================================================================================

function Get-DefaultRouteInterface {
    <#
      Возвращает интерфейс, через который реально идёт интернет:
      наименьшая суммарная метрика среди маршрутов 0.0.0.0/0.
      Это важно, когда в системе есть Radmin VPN / WSL / другие туннели -
      DNS нельзя менять им всем подряд.
    #>
    # способ 1: командлеты NetTCPIP
    try {
        $r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
             Sort-Object { [int]$_.RouteMetric + [int]$_.InterfaceMetric } |
             Select-Object -First 1
        if ($r) {
            return [pscustomobject]@{
                Index    = [int]$r.ifIndex
                Gateway  = $r.NextHop
                Alias    = $r.InterfaceAlias
                SourceIP = $null
                Metric   = [int]$r.RouteMetric + [int]$r.InterfaceMetric
            }
        }
    } catch { }

    # способ 2: разбор вывода route.exe (работает всегда)
    try {
        $cands = @()
        foreach ($l in @(& route.exe print -4 2>$null)) {
            if ($l -match '^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\S+)\s+(\S+)\s+(\d+)') {
                $cands += [pscustomobject]@{
                    Gateway  = $Matches[1]
                    SourceIP = $Matches[2]
                    Metric   = [int]$Matches[3]
                }
            }
        }
        if ($cands.Count -gt 0) {
            $b = $cands | Sort-Object Metric | Select-Object -First 1
            return [pscustomobject]@{
                Index    = 0
                Gateway  = $b.Gateway
                Alias    = $null
                SourceIP = $b.SourceIP
                Metric   = $b.Metric
            }
        }
    } catch { }

    return $null
}

function Set-DohDns {
    <# Настраивает DoH на активных адаптерах + переводит их на 1.1.1.1/8.8.8.8 #>
    $bak = New-Backup 'dns'
    $adapters = Get-LocalAdapters
    $saved = @()
    foreach ($a in $adapters) {
        if ($a.Index -gt 0 -or $a.Alias) {
            $saved += [pscustomobject]@{ Index=$a.Index; Alias=$a.Alias; Dns=$a.Dns }
        }
    }
    $saved | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $bak 'dns-backup.json') -Encoding UTF8

    # --- ПРЕДВАРИТЕЛЬНАЯ ПРОВЕРКА: работает ли DoH вообще ---
    # Если переключить DNS на 1.1.1.1 с udpfallback=no, а DoH не поднимется,
    # пользователь останется БЕЗ разрешения имён вообще. Поэтому сначала пробуем.
    $pre = $null
    foreach ($n in @('youtube.com','discord.com','cloudflare.com')) {
        $pre = Resolve-ViaDoh -Name $n
        if ($pre -and $pre.Count -gt 0) {
            Write-Log ("DoH доступен: {0} -> {1}" -f $n, ($pre -join ',')) 'OK'
            break
        }
    }
    if (-not $pre) {
        Write-Log 'DoH НЕ работает (ни 1.1.1.1, ни cloudflare-dns.com не отвечают)' 'WARN'
        Write-Log 'DNS не меняю — иначе останешься без интернета вообще.' 'WARN'
        Write-Log 'Сначала подними обход, потом повтори -Mode Repair: после десинка DoH обычно оживает.' 'INFO'
        return $bak
    }

    # --- выбираем ТОЛЬКО адаптер, через который реально идёт интернет ---
    $def = Get-DefaultRouteInterface
    $targets = New-Object System.Collections.Generic.List[object]
    if ($def) {
        Write-Log ("Основной шлюз: {0} (интерфейс {1}, IP {2})" -f $def.Gateway, $def.Index, $def.SourceIP) 'INFO'
        foreach ($a in $adapters) {
            $isDefault = $false
            if ($def.Index -gt 0 -and $a.Index -eq $def.Index) { $isDefault = $true }
            elseif ($def.SourceIP -and $a.IPv4 -eq $def.SourceIP) { $isDefault = $true }
            if ($isDefault) { $targets.Add($a) | Out-Null }
        }
    }
    if ($targets.Count -eq 0) {
        # резерв: адаптеры со шлюзом, но без явных признаков туннеля/VPN
        foreach ($a in $adapters) {
            if (-not $a.Gateway) { continue }
            if ($a.Alias -match 'Radmin|VPN|Hyper-V|vEthernet|Teredo|Tunnel|Loopback|WSL') { continue }
            $targets.Add($a) | Out-Null
        }
        if ($targets.Count -gt 0) { Write-Log 'Основной маршрут не определён, беру адаптеры со шлюзом' 'WARN' }
    }
    foreach ($a in $adapters) {
        if (-not ($targets | Where-Object { $_.Alias -eq $a.Alias })) {
            Write-Log ("DNS пропущен на «{0}» (не маршрут по умолчанию)" -f $a.Alias) 'INFO'
        }
    }

    # шаблоны шифрования DNS (Windows 11 22H2+). На старых сборках команда просто не сработает.
    Write-Log 'Регистрирую DoH-шаблоны (netsh dns add encryption)...' 'STEP'
    & netsh dns add encryption server=1.1.1.1 dohtemplate=https://cloudflare-dns.com/dns-query autoupgrade=yes udpfallback=no 2>&1 | Out-Null
    & netsh dns add encryption server=1.0.0.1 dohtemplate=https://cloudflare-dns.com/dns-query autoupgrade=yes udpfallback=no 2>&1 | Out-Null
    & netsh dns add encryption server=8.8.8.8 dohtemplate=https://dns.google/dns-query autoupgrade=yes udpfallback=no 2>&1 | Out-Null
    & netsh dns add encryption server=8.8.4.4 dohtemplate=https://dns.google/dns-query autoupgrade=yes udpfallback=no 2>&1 | Out-Null

    $done = 0
    foreach ($a in $targets) {
        $ok = $false

        # способ 1: командлет
        if ($a.Index -gt 0) {
            try {
                Set-DnsClientServerAddress -InterfaceIndex $a.Index -ServerAddresses @('1.1.1.1','8.8.8.8') -ErrorAction Stop
                $ok = $true
            } catch { }
        }

        # способ 2: netsh по имени интерфейса
        if (-not $ok -and $a.Alias) {
            $r = & netsh interface ipv4 set dnsservers name="$($a.Alias)" static 1.1.1.1 primary validate=no 2>&1
            if ($LASTEXITCODE -eq 0) {
                & netsh interface ipv4 add dnsservers name="$($a.Alias)" 8.8.8.8 index=2 validate=no 2>&1 | Out-Null
                $ok = $true
            } else {
                Write-Log ("  netsh «{0}»: {1}" -f $a.Alias, (($r | Out-String).Trim())) 'WARN'
            }
        }

        if ($ok) {
            Write-Log ("DNS -> 1.1.1.1, 8.8.8.8 на «{0}» ({1})" -f $a.Alias, $a.IPv4) 'OK'
            $done++
        } else {
            Write-Log ("Не удалось сменить DNS на «{0}»" -f $a.Alias) 'WARN'
        }
    }
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    ipconfig /flushdns | Out-Null

    if ($done -eq 0) { Write-Log 'DNS не изменён — задай 1.1.1.1 вручную в свойствах адаптера' 'WARN' }
    return $bak
}

function Restore-DnsFromBackup {
    <# Возвращает DNS-серверы адаптеров из бэкапа (аварийный откат) #>
    param([Parameter(Mandatory)][string]$BackupDir)

    $file = Join-Path $BackupDir 'dns-backup.json'
    if (-not (Test-Path -LiteralPath $file)) { Write-Log 'Бэкап DNS не найден — откат невозможен' 'ERR'; return $false }

    $saved = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json
    $restored = 0
    foreach ($s in $saved) {
        $addrs = @($s.Dns) | Where-Object { $_ }
        if ($addrs.Count -eq 0) { continue }
        $ok = $false
        if ($s.Index -gt 0) {
            try {
                Set-DnsClientServerAddress -InterfaceIndex $s.Index -ServerAddresses $addrs -ErrorAction Stop
                $ok = $true
            } catch { }
        }
        if (-not $ok -and $s.Alias) {
            & netsh interface ipv4 set dnsservers name="$($s.Alias)" static $addrs[0] primary validate=no 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                for ($i = 1; $i -lt $addrs.Count; $i++) {
                    & netsh interface ipv4 add dnsservers name="$($s.Alias)" $addrs[$i] index=$($i+1) validate=no 2>&1 | Out-Null
                }
                $ok = $true
            }
        }
        if ($ok) {
            Write-Log ("DNS откачен на «{0}» -> {1}" -f $s.Alias, ($addrs -join ',')) 'OK'
            $restored++
        } else {
            Write-Log ("Не удалось откатить DNS на «{0}»" -f $s.Alias) 'ERR'
        }
    }
    if ($restored -gt 0) { Clear-DnsClientCache -ErrorAction SilentlyContinue; ipconfig /flushdns | Out-Null }
    return ($restored -gt 0)
}

function Test-DnsHealth {
    <# Проверяет, подменяет ли провайдер DNS #>
    $result = [pscustomobject]@{ Spoofed=@(); Ok=@(); DohWorks=$false; DohIp=$null }
    $test = @('youtube.com','googlevideo.com','discord.com','telegram.org','rutracker.org')
    foreach ($d in $test) {
        $addrs = @()
        try {
            $addrs = @(Resolve-DnsName -Name $d -Type A -ErrorAction Stop | Where-Object { $_.IPAddress } | ForEach-Object { $_.IPAddress })
        } catch { $addrs = @() }
        if ($addrs.Count -eq 0) { $result.Spoofed += $d } else { $result.Ok += $d }
    }
    $ips = Resolve-ViaDoh -Name 'youtube.com'
    if ($ips -and $ips.Count -gt 0) { $result.DohWorks = $true; $result.DohIp = $ips[0] }
    return $result
}

# =====================================================================================
#  БЛОК 4. СБОРКА КОМАНДНОЙ СТРОКИ winws
# =====================================================================================

function New-WinwsCommandLineSimple {
    <#
      Конфиг БЕЗ хостлистов: правило применяется ко всему TCP 80/443.

      Почему так: на этой сети winws не сопоставляет ни одну запись из
      list-google.txt / list-general.txt (проверено изоляцией - все конфиги
      с --hostlist дают ровно то же, что и полное отсутствие обхода),
      а правило "десинкать весь TCP 80/443" работает: YouTube отдаёт 204,
      Discord - 200.
    #>
    param([Parameter(Mandatory)]$Strategy)

    $bin   = $Script:BinDir
    $lists = $Script:ListsDir
    $winws = Join-Path $bin 'winws.exe'
    $tls   = Join-Path $bin 'tls_clienthello_www_google_com.bin'
    $quic  = Join-Path $bin 'quic_initial_www_google_com.bin'
    $ipexcl = Join-Path $lists 'ipset-exclude.txt'

    $tcp = $Strategy.Tcp.Replace('{TLS}', $tls)

    $parts = @()
    $parts += '--wf-tcp=80,443'
    if (-not $Strategy.NoUdp) { $parts += '--wf-udp=443,19294-19344,50000-50100' }

    # ВАЖНО: у ПЕРВОГО фильтра НЕ должно быть ведущего --new.
    # В zapret --new разделяет фильтры; --new перед первым создаёт пустой фильтр,
    # который перехватывает трафик и ничего с ним не делает - обход перестаёт работать.
    # Именно так оформлены штатные .bat из комплекта zapret.
    $rule = '--filter-tcp=80,443'
    if (-not $Strategy.NoIpsetExclude) { $rule += " --ipset-exclude=$ipexcl" }
    if (-not $Strategy.NoIpIdZero)     { $rule += ' --ip-id=zero' }
    $rule += " $tcp"
    $parts += $rule

    if (-not $Strategy.NoUdp) {
        # Голос Discord
        $parts += "--new --filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-fake-discord=$quic --dpi-desync-fake-stun=$quic --dpi-desync-repeats=6"
        # QUIC (YouTube по UDP 443)
        $q = '--new --filter-udp=443'
        if (-not $Strategy.NoIpsetExclude) { $q += " --ipset-exclude=$ipexcl" }
        $q += " --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=$quic"
        $parts += $q
    }

    $line = ($parts -join ' ') -replace '\s+', ' '
    return [pscustomobject]@{
        Exe    = $winws
        Args   = $line
        Tokens = @($line -split ' ' | Where-Object { $_ })
        Full   = ('"' + $winws + '" ' + $line)
    }
}

function New-WinwsCommandLineByStrategy {
    <# Единая точка входа: выбирает simple- или hostlist-конфиг #>
    param([Parameter(Mandatory)]$Strategy, [switch]$WithDnsDesync)
    if ($Strategy.PSObject.Properties['Simple'] -and $Strategy.Simple) {
        return New-WinwsCommandLineSimple -Strategy $Strategy
    }
    return New-WinwsCommandLine -Strategy $Strategy -WithDnsDesync:$WithDnsDesync
}

function New-WinwsCommandLine {
    <# Возвращает ПОЛНУЮ командную строку для winws под выбранную стратегию #>
    param([Parameter(Mandatory)]$Strategy, [switch]$WithDnsDesync)

    $bin   = $Script:BinDir
    $lists = $Script:ListsDir
    $winws = Join-Path $bin 'winws.exe'
    $tls   = Join-Path $bin 'tls_clienthello_www_google_com.bin'
    $quic  = Join-Path $bin 'quic_initial_www_google_com.bin'

    $tcp = $Strategy.Tcp.Replace('{TLS}', $tls)

    $general = Join-Path $lists 'list-general.txt'
    $google  = Join-Path $lists 'list-google.txt'
    $excl    = Join-Path $lists 'list-exclude.txt'
    $ipexcl  = Join-Path $lists 'ipset-exclude.txt'
    $ipset   = Join-Path $lists 'ipset-all.txt'

    $wfUdp = '443,19294-19344,50000-50100'
    if ($WithDnsDesync) { $wfUdp += ',53' }

    # Пути НЕ заключаются в кавычки: $Script:Root = C:\ProgramData\ZapretFix,
    # там нет ни пробелов, ни кириллицы, поэтому каждый аргумент - один чистый токен.
    # Это критично: именно такую строку мы отдаём службе Windows.
    $parts = @()
    $parts += "--wf-tcp=80,443,2053,2083,2087,2096,8443,12"
    $parts += "--wf-udp=$wfUdp"

    # 1. QUIC (UDP 443) по hostlist.
    # У ПЕРВОГО фильтра ведущего --new быть не должно (см. комментарий в New-WinwsCommandLineSimple).
    $parts += "--filter-udp=443 --hostlist=$general --hostlist-exclude=$excl --ipset-exclude=$ipexcl --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=$quic"

    # 2. Голос Discord (UDP)
    $parts += "--new --filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-fake-discord=$quic --dpi-desync-fake-stun=$quic --dpi-desync-repeats=6"

    # 3. Discord media по нестандартным портам
    $parts += "--new --filter-tcp=2053,2083,2087,2096,8443 --hostlist-domains=discord.media $tcp"

    # 4. TCP 443 для google/youtube
    $parts += "--new --filter-tcp=443 --hostlist=$google --ip-id=zero $tcp"

    # 5. TCP 80/443 по общему списку
    $parts += "--new --filter-tcp=80,443,12 --hostlist=$general --hostlist-exclude=$excl --ipset-exclude=$ipexcl $tcp"

    # 6. QUIC по ipset
    $parts += "--new --filter-udp=443 --ipset=$ipset --hostlist-exclude=$excl --ipset-exclude=$ipexcl --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=$quic"

    # 7. TCP по ipset
    $parts += "--new --filter-tcp=80,443 --ipset=$ipset --hostlist-exclude=$excl --ipset-exclude=$ipexcl $tcp"

    # 8. DNS-десинк (опционально)
    if ($WithDnsDesync) {
        $parts += "--new --filter-udp=53 --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=$quic"
    }

    # 9. Всё остальное UDP (игры и прочее) - в конце, как в zapret
    $parts += "--new --filter-udp=12 --ipset=$ipset --ipset-exclude=$ipexcl --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=12 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=$quic --dpi-desync-cutoff=n3"

    $line = ($parts -join ' ') -replace '\s+', ' '
    $tokens = @($line -split ' ' | Where-Object { $_ })
    return [pscustomobject]@{
        Exe    = $winws
        Args   = $line
        Tokens = $tokens
        Full   = ('"' + $winws + '" ' + $line)
    }
}

# =====================================================================================
#  БЛОК 5. ПРОВЕРКА ДОСТУПНОСТИ СЕРВИСОВ
# =====================================================================================

function Test-Youtube {
    $r = [pscustomobject]@{ Ok=$false; Detail=''; Speed=0; Stage='' }
    $h = Invoke-HttpRaw -Url 'https://www.youtube.com/generate_204' -TimeoutMs 9000
    if ($h.Ok -and ($h.Status -eq 204 -or $h.Status -eq 200)) {
        $r.Ok = $true
        $r.Detail = "HTTP $($h.Status), TCP $($h.TcpMs)ms, TLS $($h.TlsMs)ms"
    } else {
        $r.Stage = $h.Stage
        $r.Detail = "сбой на этапе '$($h.Stage)': $($h.Error)"
    }

    if ($r.Ok) {
        $d = Invoke-HttpRaw -Url 'https://i.ytimg.com/vi/dQw4w9WgXcQ/maxresdefault.jpg' -TimeoutMs 10000 -MaxBytes 400000
        if ($d.Ok -and $d.Ms -gt 0) {
            $r.Speed = $d.Kbps
            if ($r.Speed -lt 30 -and $d.Bytes -gt 10240) {
                $r.Ok = $false
                $r.Detail += " | скачивание задушено: $($r.Speed) КБ/с"
            } else {
                $r.Detail += " | $($r.Speed) КБ/с"
            }
        }
    }
    return $r
}

function Test-Discord {
    $r = [pscustomobject]@{ Ok=$false; Detail=''; Stage='' }
    $h = Invoke-HttpRaw -Url 'https://discord.com/api/v9/gateway' -TimeoutMs 9000
    if ($h.Ok -and $h.Status -eq 200) {
        $r.Ok = $true
        $r.Detail = "HTTP 200, TCP $($h.TcpMs)ms, TLS $($h.TlsMs)ms"
    } else {
        $r.Stage = $h.Stage
        $r.Detail = "сбой на этапе '$($h.Stage)': $($h.Error)"
    }
    return $r
}

function Test-Telegram {
    $r = [pscustomobject]@{ Ok=$false; Detail=''; Open=0; Total=0 }
    $dcs = @(
        @{ip='149.154.167.99'; port=443},
        @{ip='149.154.175.50'; port=443},
        @{ip='149.154.167.51'; port=443},
        @{ip='91.108.56.130';  port=443}
    )
    $open = 0
    foreach ($d in $dcs) {
        if ((Test-TcpPort -Target $d.ip -Port $d.port -TimeoutMs 3000) -eq 'ok') { $open++ }
    }
    $r.Open = $open; $r.Total = $dcs.Count
    if ($open -gt 0) { $r.Ok = $true; $r.Detail = "открыто DC: $open из $($dcs.Count)" }
    else { $r.Detail = 'ни один DC Telegram не отвечает (блок по IP)' }
    return $r
}

function Get-ServiceState {
    $svc = Get-Service -Name $Script:ServiceName -ErrorAction SilentlyContinue
    if (-not $svc) { return 'not-installed' }
    return $svc.Status.ToString()
}

function Stop-AllWinws {
    <#
      Гасит winws и ОБЯЗАТЕЛЬНО снимает драйвер WinDivert.

      Зачем: Stop-Process -Force убивает winws, не закрыв хендл WinDivert.
      Драйвер остаётся загруженным с «залипшим» фильтром и начинает резать
      трафик - приложения получают WSAEACCES ("доступ к сокету запрещён")
      или мгновенный RST. Именно это ломало замеры стратегий.
    #>
    param([switch]$ResetDriver)

    Get-Process -Name 'winws' -ErrorAction SilentlyContinue | ForEach-Object {
        try { Stop-Process -Id $_.Id -Force -ErrorAction Stop } catch { }
    }
    Start-Sleep -Milliseconds 700

    if ($ResetDriver) {
        foreach ($drv in @('WinDivert', 'WinDivert1.4', 'WinDivert14')) {
            $q = (& sc.exe query $drv 2>&1) -join ' '
            if ($q -match 'RUNNING') {
                & sc.exe stop $drv 2>&1 | Out-Null
            }
        }
        Start-Sleep -Milliseconds 1200
    }
}

# =====================================================================================
#  БЛОК 6. ДИАГНОСТИКА
# =====================================================================================

function Invoke-Diagnose {
    Write-Head 'ДИАГНОСТИКА СЕТИ И БЛОКИРОВОК'

    # --- ОС ---
    Write-Log 'Операционная система и права' 'STEP'
    $os = $null
    try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch { }
    if ($os) { Write-Log ("ОС: {0} (build {1})" -f $os.Caption, $os.BuildNumber) 'INFO' }
    else {
        $v = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue)
        if ($v) { Write-Log ("ОС: {0} (build {1})" -f $v.ProductName, $v.CurrentBuildNumber) 'INFO' }
    }
    Write-Log ("PowerShell: {0}" -f $PSVersionTable.PSVersion) 'INFO'
    Write-Log ("Права администратора: {0}" -f (Test-Admin)) 'INFO'

    # --- Адаптеры ---
    Write-Log 'Сетевые адаптеры' 'STEP'
    $adapters = Get-LocalAdapters
    foreach ($a in $adapters) {
        Write-Log ("  {0} | IP {1} | шлюз {2} | DNS {3}" -f $a.Alias, $a.IPv4, $a.Gateway, ($a.Dns -join ',')) 'INFO'
    }
    $defaultRoutes = @()
    try {
        $defaultRoutes = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
            Select-Object ifIndex, NextHop, RouteMetric, InterfaceAlias
    } catch { }
    foreach ($r in $defaultRoutes) {
        Write-Log ("  маршрут по умолчанию: {0} через {1} (метрика {2})" -f $r.InterfaceAlias, $r.NextHop, $r.RouteMetric) 'INFO'
    }
    if ($defaultRoutes.Count -gt 1) {
        Write-Log "Обнаружено несколько маршрутов по умолчанию (VPN-адаптеры). Убедись, что физический адаптер имеет меньшую метрику." 'WARN'
    }

    # --- hosts ---
    Write-Log 'Файл hosts' 'STEP'
    $bad = @()
    Get-Content -LiteralPath $Script:HostsFile -ErrorAction SilentlyContinue | ForEach-Object {
        $t = $_.Trim()
        if ($t -and -not $t.StartsWith('#') -and $t -match '^(74\.119\.194\.9|0\.0\.0\.0|127\.0\.0\.1)\s') { $bad += $t }
    }
    if ($bad.Count -gt 0) {
        Write-Log ("hosts: найдено {0} записей-заглушек (ломают ChatGPT/Claude/Spotify/YouTube)" -f $bad.Count) 'WARN'
        $bad | Select-Object -First 5 | ForEach-Object { Write-Log ("  ! $_") 'WARN' }
    } else { Write-Log 'hosts: заглушек не найдено' 'OK' }

    # --- DNS ---
    Write-Log 'DNS: проверка подмены провайдером' 'STEP'
    $dns = Test-DnsHealth
    if ($dns.Spoofed.Count -gt 0) {
        Write-Log ("DNS подменяется! Не разрешаются: {0}" -f ($dns.Spoofed -join ', ')) 'ERR'
    } else { Write-Log 'DNS: имена разрешаются нормально' 'OK' }
    if ($dns.DohWorks) { Write-Log ("DoH работает, youtube.com -> {0}" -f $dns.DohIp) 'OK' }
    else { Write-Log 'DoH недоступен (порт 443 к 1.1.1.1 закрыт?)' 'WARN' }

    # --- TCP ---
    Write-Log 'TCP-доступность ключевых узлов' 'STEP'
    $tcpTargets = @(
        @{n='YouTube (google)'; ip='142.251.1.198'; p=443},
        @{n='YouTube (google2)';ip='74.125.205.100'; p=443},
        @{n='YouTube (frontend)';ip='216.58.210.14'; p=443},
        @{n='Discord (cloudflare)';ip='162.159.136.232'; p=443},
        @{n='Discord gateway'; ip='162.159.135.234'; p=443},
        @{n='Telegram DC2';   ip='149.154.167.51'; p=443},
        @{n='Telegram DC4';   ip='149.154.167.99'; p=443},
        @{n='Telegram DC5';   ip='91.108.56.130';  p=443},
        @{n='Cloudflare (контроль)'; ip='1.1.1.1'; p=443},
        @{n='Google DNS (контроль)'; ip='8.8.8.8'; p=443}
    )
    $telegramBlocked = $true
    foreach ($t in $tcpTargets) {
        $state = Test-TcpPort -Target $t.ip -Port $t.p -TimeoutMs 3500
        $lvl = if ($state -eq 'ok') { 'OK' } else { 'ERR' }
        Write-Log ("  {0,-24} {1,-16} -> {2}" -f $t.n, $t.ip, $state.ToUpper()) $lvl
        if ($t.n -like 'Telegram*' -and $state -eq 'ok') { $telegramBlocked = $false }
    }

    # --- HTTPS ---
    Write-Log 'Проверка HTTPS/TLS' 'STEP'
    $schannel = Test-Https -Url 'https://1.1.1.1/' -TimeoutMs 8000
    if (-not $schannel.Ok -and $schannel.Error -match 'credentials|credential|Schannel|SEC_E') {
        Write-Log ('TLS в системе сломан: ' + $schannel.Error) 'ERR'
        Write-Log '  Это НЕ блокировка провайдера. Проверь службу "Криптография" и права на C:\ProgramData\Microsoft\Crypto' 'WARN'
    } elseif ($schannel.Ok) {
        Write-Log ("TLS работает (HTTP {0}, {1} ms)" -f $schannel.Status, $schannel.Ms) 'OK'
    } else {
        Write-Log ('TLS: ' + $schannel.Error) 'WARN'
    }

    $yt = Test-Youtube; $dc = Test-Discord; $tg = Test-Telegram
    Write-Log ("YouTube: {0} - {1}" -f $(if($yt.Ok){'РАБОТАЕТ'}else{'НЕ РАБОТАЕТ'}), $yt.Detail) $(if($yt.Ok){'OK'}else{'ERR'})
    Write-Log ("Discord: {0} - {1}" -f $(if($dc.Ok){'РАБОТАЕТ'}else{'НЕ РАБОТАЕТ'}), $dc.Detail) $(if($dc.Ok){'OK'}else{'ERR'})
    Write-Log ("Telegram: {0} - {1}" -f $(if($tg.Ok){'РАБОТАЕТ'}else{'НЕ РАБОТАЕТ'}), $tg.Detail) $(if($tg.Ok){'OK'}else{'ERR'})

    # --- Комплект zapret ---
    Write-Log 'Поиск комплекта zapret на диске' 'STEP'
    $found = Find-ZapretToolchain
    if ($found.Count -eq 0) {
        Write-Log 'winws.exe + WinDivert не найдены' 'ERR'
        Write-Log '  Скачай zapret: https://github.com/bol-van/zapret/releases (windows-файлы)' 'WARN'
    } else {
        foreach ($f in $found) {
            Write-Log ("  {0}  (score {1}, .sys: {2})" -f $f.Path, $f.Score, $f.HasSys) 'INFO'
        }
    }

    Write-Log 'Состояние службы zapret' 'STEP'
    $svcState = Get-ServiceState
    Write-Log ("служба '{0}': {1}" -f $Script:ServiceName, $svcState) $(if($svcState -eq 'Running'){'OK'}else{'WARN'})
    try {
        $svc = Get-CimInstance Win32_Service -Filter "Name='$Script:ServiceName'" -ErrorAction Stop
        if ($svc) {
            Write-Log ("  путь: {0}" -f $svc.PathName) 'INFO'
            $exePath = ($svc.PathName -replace '^"([^"]+)".*$','$1') -replace '^([^\s]+)\s.*$','$1'
            if (-not (Test-Path -LiteralPath $exePath)) {
                Write-Log "  ФАЙЛ winws.exe ПО ЭТОМУ ПУТИ ОТСУТСТВУЕТ - служба нерабочая!" 'ERR'
            }
        }
    } catch {
        $qc = (& sc.exe qc $Script:ServiceName 2>&1) -join "`n"
        if ($qc -match 'BINARY_PATH_NAME\s*:\s*(.+)') {
            Write-Log ("  путь: {0}" -f $Matches[1].Trim()) 'INFO'
        }
    }

    # --- Итог ---
    Write-Head 'ВЫВОДЫ'
    if ($dns.Spoofed.Count -gt 0) { Write-Log 'Провайдер подменяет DNS (NXDOMAIN на youtube.com) -> включаем DoH.' 'WARN' }
    if ($telegramBlocked) {
        Write-Log 'Telegram заблокирован на уровне IP (все DC молчат).' 'ERR'
        Write-Log 'Десинхронизация DPI тут НЕ поможет. Нужен MTProto-прокси внутри Telegram или WARP.' 'WARN'
        Write-Log 'Запусти: Fix-Zapret.ps1 -Mode Telegram' 'INFO'
    }
    if ($yt.Ok -and $dc.Ok -and -not $telegramBlocked) { Write-Log 'Блокировок не обнаружено.' 'OK' }

    return [pscustomobject]@{
        YoutubeBroken = (-not $yt.Ok)
        DiscordBroken = (-not $dc.Ok)
        TelegramBlocked = $telegramBlocked
        DnsSpoofed = ($dns.Spoofed.Count -gt 0)
        DohWorks = $dns.DohWorks
        Toolchain = $found
        ServiceState = $svcState
    }
}

# =====================================================================================
#  БЛОК 7. ПОЧИНКА
# =====================================================================================

function Invoke-Repair {
    param($Diag)

    Write-Head 'ПОЧИНКА'

    Ensure-Dirs
    Write-Log "Рабочий каталог: $Script:Root" 'INFO'

    # 1. hosts
    if (-not $SkipHosts) {
        Write-Log 'Шаг 1/5. Чистка hosts' 'STEP'
        Repair-Hosts
    } else { Write-Log 'Шаг 1/5. hosts пропущен (-SkipHosts)' 'WARN' }

    # 2. комплект
    Write-Log 'Шаг 2/5. Установка комплекта winws в стабильный путь' 'STEP'
    $src = $null
    if ($Diag -and $Diag.Toolchain -and $Diag.Toolchain.Count -gt 0) { $src = $Diag.Toolchain[0] }
    if (-not $src) { $src = (Find-ZapretToolchain | Select-Object -First 1) }
    if (-not $src) {
        Write-Log 'Комплект zapret не найден. Скачай его вручную и повтори с -ZapretDir <путь>' 'ERR'
        return $null
    }
    Write-Log ("Источник: {0}" -f $src.Path) 'INFO'
    $copied = Install-Toolchain -Source $src
    Write-Log ("Скопировано файлов: {0} -> {1}" -f $copied, $Script:BinDir) 'OK'

    if (-not (Test-Path -LiteralPath (Join-Path $Script:BinDir 'winws.exe'))) {
        Write-Log 'winws.exe не скопирован - прерываю' 'ERR'; return $null
    }
    if (-not (Test-Path -LiteralPath (Join-Path $Script:BinDir 'WinDivert64.sys'))) {
        Write-Log 'WinDivert64.sys не найден рядом с winws.exe - драйвер не загрузится' 'ERR'
    }

    # 3. списки
    Write-Log 'Шаг 3/5. Подготовка списков' 'STEP'
    $stat = Install-Lists -Source $src
    $ng = Add-DomainsToList -File (Join-Path $Script:ListsDir 'list-general.txt') -Domains $Script:ExtraGeneral
    $ngo= Add-DomainsToList -File (Join-Path $Script:ListsDir 'list-google.txt')  -Domains $Script:ExtraGoogle
    Write-Log ("list-general.txt: +{0} доменов, list-google.txt: +{1} доменов" -f $ng, $ngo) 'OK'
    $lfFixed = Convert-ListsToLf
    if ($lfFixed -gt 0) { Write-Log ("Списки нормализованы к LF: {0} файлов" -f $lfFixed) 'OK' }
    Write-Log ("ipset-all.txt: строк {0} (восстановлен: {1})" -f $stat.IpsetLines, $stat.IpsetRestored) 'INFO'
    if ($stat.IpsetLines -lt 100) {
        Write-Log 'ipset-all.txt подозрительно мал - правила по ipset будут почти неэффективны' 'WARN'
    }

    # 4. DNS
    if (-not $SkipDns) {
        Write-Log 'Шаг 4/5. Настройка DNS-over-HTTPS' 'STEP'
        $dnsBak = Set-DohDns
        Start-Sleep -Seconds 2
        $h = Test-DnsHealth
        if ($h.Spoofed.Count -gt 0) {
            Write-Log ("DNS всё ещё подменяется для: {0}" -f ($h.Spoofed -join ', ')) 'WARN'
        } else {
            Write-Log 'DNS в порядке' 'OK'
        }
        # АВАРИЙНЫЙ ОТКАТ: если после смены DNS не разрешается вообще ничего,
        # значит DoH не поднялся - возвращаем прежние серверы, чтобы не остаться без интернета.
        if ($h.Ok.Count -eq 0) {
            Write-Log 'После смены DNS не разрешается НИ ОДНО имя — откатываю DNS!' 'ERR'
            if ($dnsBak) { Restore-DnsFromBackup -BackupDir $dnsBak | Out-Null }
        }
        elseif ($h.Spoofed.Count -gt 0) {
            Write-Log 'Часть имён подменяется, но интернет работает. Добавь -DnsDesync при следующем запуске.' 'WARN'
        }
        # DoH заработал -> убираем жёсткий пин youtube.com в hosts, он мешает выбору CDN
        if ($h.Spoofed.Count -eq 0 -and -not $SkipHosts) {
            $rm = Repair-Hosts -RemoveYoutubePins
            if ($rm -gt 0) { Write-Log ("hosts: дочищено записей: {0}" -f $rm) 'OK' }
        }
    } else { Write-Log 'Шаг 4/5. DNS пропущен (-SkipDns)' 'WARN' }

    # 5. служба будет поставлена после подбора стратегии
    Write-Log 'Шаг 5/5. Служба будет настроена после подбора стратегии' 'INFO'

    return $src
}

# =====================================================================================
#  БЛОК 8. ПОДБОР СТРАТЕГИИ
# =====================================================================================

function Wait-HealthyNetwork {
    <#
      Ждёт, пока сеть придёт в норму после снятия winws.

      Нужно потому, что драйвер WinDivert после жёсткого убийства процесса
      какое-то время режет трафик (симптом - WSAEACCES "доступ к сокету
      запрещён" или мгновенный RST). Если начать замер в этот момент,
      рабочая стратегия получит score 0.
    #>
    param([int]$MaxTries = 8, [int]$DelaySec = 2)
    for ($i = 1; $i -le $MaxTries; $i++) {
        $c = Invoke-HttpRaw -Url 'https://1.1.1.1/' -TimeoutMs 5000
        if ($c.Ok) { return $true }
        Start-Sleep -Seconds $DelaySec
    }
    return $false
}

function Restore-NetworkHealth {
    <#
      Приводит сеть в рабочее состояние и гарантирует, что можно мерить.

      Порядок важен: сначала просто ждём. Остановка драйвера WinDivert сама по
      себе на несколько секунд ломает TCP (WSAEACCES "доступ к сокету запрещён"),
      поэтому снимать драйвер нужно только если ожидание не помогло.
    #>
    param([int]$MaxTries = 8, [int]$DelaySec = 2)

    if (Wait-HealthyNetwork -MaxTries $MaxTries -DelaySec $DelaySec) { return $true }

    Write-Log '  сеть не отвечает - снимаю драйвер WinDivert принудительно' 'WARN'
    foreach ($drv in @('WinDivert', 'WinDivert1.4', 'WinDivert14')) {
        $q = (& sc.exe query $drv 2>&1) -join ' '
        if ($q -match 'RUNNING') { & sc.exe stop $drv 2>&1 | Out-Null }
    }
    # выгрузка драйвера не мгновенная - даём сети прийти в себя
    Start-Sleep -Seconds 5
    return (Wait-HealthyNetwork -MaxTries 10 -DelaySec 3)
}

function Start-WinwsProcess {
    param([Parameter(Mandatory)]$Command)
    # Просто гасим winws. Драйвер НЕ трогаем: его остановка сама ломает TCP на несколько секунд.
    Stop-AllWinws
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $Command.Exe
    $psi.Arguments = $Command.Args
    $psi.WorkingDirectory = $Script:BinDir
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardError = $false
    try {
        $p = [Diagnostics.Process]::Start($psi)
        Start-Sleep -Seconds 3
        if ($p.HasExited) {
            return [pscustomobject]@{ Ok=$false; Process=$null; Code=$p.ExitCode }
        }
        return [pscustomobject]@{ Ok=$true; Process=$p; Code=0 }
    } catch {
        return [pscustomobject]@{ Ok=$false; Process=$null; Code=-1; Error=$_.Exception.Message }
    }
}

function Get-NamedStrategy {
    <# Берёт стратегию по имени, без автоподбора (для -ForceStrategy) #>
    param([Parameter(Mandatory)][string]$Name)
    $s = $Script:Strategies | Where-Object { $_.Name -eq $Name } | Select-Object -First 1
    if (-not $s) {
        Write-Log ("Стратегия '{0}' не найдена." -f $Name) 'ERR'
        Write-Log ("Доступные: {0}" -f (($Script:Strategies | ForEach-Object { $_.Name }) -join ', ')) 'INFO'
        return $null
    }
    Write-Log ("Принудительно выбрана стратегия: {0} ({1})" -f $s.Name, $s.Desc) 'OK'
    return $s
}

function Invoke-StrategyTest {
    <# Перебирает стратегии, возвращает лучшую #>
    Write-Head 'АВТОПОДБОР СТРАТЕГИИ ДЕСИНХРОНИЗАЦИИ'

    if (-not (Test-Path -LiteralPath (Join-Path $Script:BinDir 'winws.exe'))) {
        Write-Log 'winws.exe нет - сначала выполни -Mode Repair' 'ERR'
        return $null
    }

    # Автоподбор несовместим с уже запущенной службой: Stop-AllWinws убивает
    # winws службы, а nssm его тут же перезапускает - получается гонка,
    # и замеры становятся мусорными. Поэтому службу гасим заранее.
    if ((Get-ServiceState) -eq 'Running') {
        Write-Log 'Служба zapret запущена - останавливаю её на время подбора стратегии' 'STEP'
        & sc.exe stop $Script:ServiceName 2>&1 | Out-Null
        Start-Sleep -Seconds 3
    }

    Write-Log 'Замер "до" (без обхода) и проверка, что сеть вообще жива...' 'STEP'
    Stop-AllWinws
    $healthy = Restore-NetworkHealth -MaxTries 8 -DelaySec 2
    $ctrl = Invoke-HttpRaw -Url 'https://1.1.1.1/' -TimeoutMs 8000

    if (-not $ctrl.Ok) {
        Write-Log ("КОНТРОЛЬНАЯ ПРОВЕРКА ПРОВАЛЕНА (1.1.1.1, этап '$($ctrl.Stage)': $($ctrl.Error))") 'ERR'
        Write-Log 'Сеть в целом недоступна - замеры стратегий не имеют смысла.' 'ERR'
        Write-Log 'Перезагрузка снимает залипший драйвер WinDivert за один раз.' 'WARN'
        return $null
    }
    Write-Log ("Контроль 1.1.1.1: HTTP {0}, TCP {1}ms, TLS {2}ms - сеть в порядке" -f $ctrl.Status, $ctrl.TcpMs, $ctrl.TlsMs) 'OK'

    $baseYt = Test-Youtube; $baseDc = Test-Discord; $baseTg = Test-Telegram
    Write-Log ("  без обхода: YouTube={0} ({1})" -f $baseYt.Ok, $baseYt.Stage) 'INFO'
    Write-Log ("  без обхода: Discord={0} ({1})" -f $baseDc.Ok, $baseDc.Stage) 'INFO'
    Write-Log ("  без обхода: Telegram DC {0}/{1}" -f $baseTg.Open, $baseTg.Total) 'INFO'

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($s in $Script:Strategies) {
        Write-Log ("Пробую: {0} ({1})" -f $s.Name, $s.Desc) 'STEP'

        # приводим сеть в норму перед замером
        Stop-AllWinws
        if (-not (Restore-NetworkHealth -MaxTries 6 -DelaySec 2)) {
            Write-Log '  сеть не пришла в норму - пропускаю замер' 'WARN'
            $results.Add([pscustomobject]@{ Strategy=$s; Score=0; Yt=$false; Dc=$false; Tg=0; Note='сеть нездорова' }) | Out-Null
            continue
        }

        $cmd = New-WinwsCommandLineByStrategy -Strategy $s -WithDnsDesync:$DnsDesync
        $proc = Start-WinwsProcess -Command $cmd

        if (-not $proc.Ok) {
            Write-Log ("  winws не стартовал (код {0})" -f $proc.Code) 'ERR'
            $results.Add([pscustomobject]@{ Strategy=$s; Score=0; Yt=$false; Dc=$false; Tg=0; Note='winws не запустился' }) | Out-Null
            continue
        }

        Start-Sleep -Seconds 2

        # Контроль: если 1.1.1.1 (который не входит ни в один список) не открывается,
        # значит проблема в состоянии драйвера, а не в стратегии. Замер был бы ложным.
        $ctrlOk = $false
        for ($attempt = 1; $attempt -le 2; $attempt++) {
            $c2 = Invoke-HttpRaw -Url 'https://1.1.1.1/' -TimeoutMs 6000
            if ($c2.Ok) { $ctrlOk = $true; break }
            Write-Log ("  контроль 1.1.1.1 не прошёл (попытка {0}, этап '{1}') - перезапускаю winws" -f $attempt, $c2.Stage) 'WARN'
            if ($proc.Process -and -not $proc.Process.HasExited) { try { $proc.Process.Kill() } catch { } }
            Stop-AllWinws
            if (-not (Restore-NetworkHealth -MaxTries 6 -DelaySec 2)) { break }
            $proc = Start-WinwsProcess -Command $cmd
            if (-not $proc.Ok) { break }
            Start-Sleep -Seconds 2
        }
        if (-not $ctrlOk) {
            Write-Log '  сеть нестабильна, замер недостоверен - пропускаю' 'WARN'
            $results.Add([pscustomobject]@{ Strategy=$s; Score=0; Yt=$false; Dc=$false; Tg=0; Note='сеть нестабильна' }) | Out-Null
            if ($proc.Process -and -not $proc.Process.HasExited) { try { $proc.Process.Kill() } catch { } }
            Stop-AllWinws
            continue
        }

        $yt = Test-Youtube
        $dc = Test-Discord
        $tg = Test-Telegram

        $score = 0
        if ($yt.Ok) { $score += 45 }
        if ($dc.Ok) { $score += 25 }
        $score += ($tg.Open * 7)
        if ($yt.Speed -gt 200) { $score += 10 }

        Write-Log ("  YouTube : {0} - {1}" -f $yt.Ok, $yt.Detail) $(if($yt.Ok){'OK'}else{'ERR'})
        Write-Log ("  Discord : {0} - {1}" -f $dc.Ok, $dc.Detail) $(if($dc.Ok){'OK'}else{'ERR'})
        Write-Log ("  Telegram: {0}/{1}" -f $tg.Open, $tg.Total) $(if($tg.Open -gt 0){'OK'}else{'WARN'})
        Write-Log ("  score = {0}" -f $score) $(if($score -gt 40){'OK'}elseif($score -gt 0){'WARN'}else{'ERR'})

        $note = "YT={0} DC={1} TG={2}/{3}" -f $yt.Ok, $dc.Ok, $tg.Open, $tg.Total
        $results.Add([pscustomobject]@{ Strategy=$s; Score=$score; Yt=$yt.Ok; Dc=$dc.Ok; Tg=$tg.Open; Note=$note; Speed=$yt.Speed }) | Out-Null

        if ($proc.Process -and -not $proc.Process.HasExited) {
            try { $proc.Process.Kill() } catch { }
        }
        Stop-AllWinws
        Start-Sleep -Milliseconds 800

        # Хорошая стратегия найдена - дальше перебирать нет смысла, только рвём интернет
        if ($yt.Ok -and $dc.Ok) {
            Write-Log 'Найдена стратегия, где работают и YouTube, и Discord - остальные не проверяю' 'OK'
            break
        }
    }

    # --- выбор ---
    Write-Head 'РЕЗУЛЬТАТЫ ПОДБОРА'
    $results | Sort-Object Score -Descending | ForEach-Object {
        $lvl = if ($_.Score -gt 40) { 'OK' } elseif ($_.Score -gt 0) { 'WARN' } else { 'ERR' }
        Write-Log ("{0,-22} score={1,-4} {2}" -f $_.Strategy.Name, $_.Score, $_.Note) $lvl
    }

    $ranked = @($results | Sort-Object Score -Descending)
    $best = $null

    # ПОДТВЕРЖДЕНИЕ: победителя проверяем ещё раз (замер бывает шумным из-за WinDivert)
    foreach ($cand in $ranked) {
        if ($cand.Score -eq 0) { break }
        Write-Log ("Подтверждаю стратегию '{0}' повторным замером..." -f $cand.Strategy.Name) 'STEP'
        Stop-AllWinws
        if (-not (Restore-NetworkHealth -MaxTries 6 -DelaySec 2)) { continue }
        $cmd = New-WinwsCommandLineByStrategy -Strategy $cand.Strategy -WithDnsDesync:$DnsDesync
        $proc = Start-WinwsProcess -Command $cmd
        if (-not $proc.Ok) { Write-Log '  не запустилась повторно' 'WARN'; continue }
        Start-Sleep -Seconds 2
        $yt2 = Test-Youtube
        $dc2 = Test-Discord
        Write-Log ("  повтор: YouTube={0}, Discord={1}" -f $yt2.Ok, $dc2.Ok) $(if($yt2.Ok -and $dc2.Ok){'OK'}else{'WARN'})
        if ($proc.Process -and -not $proc.Process.HasExited) { try { $proc.Process.Kill() } catch { } }
        Stop-AllWinws
        if ($yt2.Ok -and $dc2.Ok) { $best = $cand; break }
        Write-Log '  подтверждение не прошло, пробую следующую' 'WARN'
    }

    if (-not $best) {
        Write-Log 'Ни одна стратегия не подтвердилась.' 'ERR'
        Write-Log 'Варианты: 1) повторить с -DnsDesync; 2) перезагрузить ПК (снимает залипший WinDivert);' 'WARN'
        Write-Log '          3) если Telegram нужен - только MTProto-прокси, это блок по IP.' 'WARN'
        return $null
    }

    Write-Log ("Лучшая стратегия: {0} (score {1})" -f $best.Strategy.Name, $best.Score) 'OK'
    Set-Content -LiteralPath $Script:ConfFile -Value $best.Strategy.Name -Encoding ASCII
    return $best.Strategy
}

# =====================================================================================
#  БЛОК 9. СЛУЖБА
# =====================================================================================

function Write-RunScript {
    <# Пишет run.cmd - ручной запуск winws без службы (для отладки) #>
    param([Parameter(Mandatory)]$Command)
    $runCmd = Join-Path $Script:Root 'run.cmd'
    $content = @(
        '@echo off'
        'setlocal DisableDelayedExpansion'
        'chcp 65001 > nul'
        'cd /d "%~dp0bin"'
        'echo Запуск winws (закрой окно для остановки)...'
        ('"{0}" {1}' -f $Command.Exe, $Command.Args)
        'echo.'
        'echo winws завершился с кодом %ERRORLEVEL%'
        'pause'
    ) -join "`r`n"
    Set-Content -LiteralPath $runCmd -Value $content -Encoding OEM
    return $runCmd
}

function Install-ZapretService {
    param([Parameter(Mandatory)]$Strategy)

    Write-Head 'УСТАНОВКА СЛУЖБЫ'

    $exe = Join-Path $Script:BinDir 'winws.exe'
    if (-not (Test-Path -LiteralPath $exe)) { Write-Log "Нет $exe" 'ERR'; return $false }

    $cmd = New-WinwsCommandLineByStrategy -Strategy $Strategy -WithDnsDesync:$DnsDesync
    $runCmd = Write-RunScript -Command $cmd
    Write-Log ("Скрипт ручного запуска: {0}" -f $runCmd) 'INFO'

    # сохраняем старую службу
    $bak = New-Backup 'service'
    (& sc.exe qc $Script:ServiceName 2>&1) | Set-Content -LiteralPath (Join-Path $bak 'old-service.txt') -Encoding UTF8 -ErrorAction SilentlyContinue

    Write-Log 'Останавливаю и удаляю старую службу...' 'STEP'
    if (Get-Service -Name $Script:ServiceName -ErrorAction SilentlyContinue) {
        & sc.exe stop $Script:ServiceName 2>&1 | Out-Null
        Start-Sleep -Seconds 2
        & sc.exe delete $Script:ServiceName 2>&1 | Out-Null
        Start-Sleep -Seconds 1
    }
    Stop-AllWinws

    # --- ищем nssm: он корректно задаёт рабочий каталог и убивает дочерние процессы ---
    $nssm = $null
    foreach ($cand in @(
        (Join-Path $Script:BinDir 'nssm.exe'),
        "$env:ProgramData\ZapretTwo\exe\nssm.exe",
        'C:\nssm\nssm.exe',
        'C:\tools\nssm\nssm.exe'
    )) {
        if (Test-Path -LiteralPath $cand) { $nssm = $cand; break }
    }
    if (-not $nssm) {
        $f = Find-ZapretToolchain | ForEach-Object {
            $n = Join-Path (Split-Path $_.Path -Parent) 'nssm.exe'
            if (Test-Path -LiteralPath $n) { $n }
            $n2 = Join-Path $_.Path 'nssm.exe'
            if (Test-Path -LiteralPath $n2) { $n2 }
        } | Select-Object -First 1
        if ($f) { $nssm = $f }
    }

    $created = $false

    if ($nssm) {
        Write-Log ("Создаю службу через nssm: {0}" -f $nssm) 'STEP'
        $nsArgs = @('install', $Script:ServiceName, $cmd.Exe) + $cmd.Tokens
        $out = & $nssm @nsArgs 2>&1
        $out | ForEach-Object { Write-Log ("  nssm: " + $_) 'INFO' }
        & $nssm set $Script:ServiceName AppDirectory $Script:BinDir        2>&1 | Out-Null
        & $nssm set $Script:ServiceName Start SERVICE_AUTO_START           2>&1 | Out-Null
        & $nssm set $Script:ServiceName DisplayName 'zapret (DPI bypass)'  2>&1 | Out-Null
        & $nssm set $Script:ServiceName Description 'ZapretFix: обход DPI для YouTube / Discord / Telegram' 2>&1 | Out-Null
        & $nssm set $Script:ServiceName AppStdout (Join-Path $Script:LogDir 'winws.out.log') 2>&1 | Out-Null
        & $nssm set $Script:ServiceName AppStderr (Join-Path $Script:LogDir 'winws.err.log') 2>&1 | Out-Null
        & $nssm set $Script:ServiceName AppStopMethodConsole 3000            2>&1 | Out-Null
        $created = ((Get-ServiceState) -ne 'not-installed')
    }

    if (-not $created) {
        Write-Log 'nssm не найден, создаю службу напрямую через sc.exe' 'STEP'
        # Пути в аргументах без пробелов, поэтому вложенные кавычки не нужны.
        $binPath = '"{0}" {1}' -f $exe, $cmd.Args
        $out = & sc.exe create $Script:ServiceName "binPath= $binPath" 'start= auto' 'DisplayName= zapret (DPI bypass)' 2>&1
        $out | ForEach-Object { Write-Log ("  sc: " + $_) 'INFO' }
        & sc.exe description $Script:ServiceName 'ZapretFix: обход DPI для YouTube / Discord / Telegram (WinDivert)' 2>&1 | Out-Null
        & sc.exe failure $Script:ServiceName 'reset= 86400' 'actions= restart/5000/restart/10000/restart/30000' 2>&1 | Out-Null
        $created = ((Get-ServiceState) -ne 'not-installed')
    }

    if (-not $created) {
        Write-Log 'Служба не создалась.' 'ERR'
        Write-Log ("Запусти вручную: {0}" -f $runCmd) 'WARN'
        return $false
    }
    Write-Log 'Служба создана' 'OK'

    return (Start-ZapretService)
}

function Start-ZapretService {
    Write-Log 'Запускаю службу...' 'STEP'
    & sc.exe start $Script:ServiceName 2>&1 | ForEach-Object { Write-Log ("  sc: " + $_) 'INFO' }
    Start-Sleep -Seconds 4

    $state = Get-ServiceState
    if ($state -ne 'Running') {
        Write-Log ("Служба в состоянии '{0}' - не запустилась" -f $state) 'ERR'
        $log = (& sc.exe queryex $Script:ServiceName 2>&1) -join "`n"
        Write-Log $log 'INFO'
        Write-Log 'Проверь: подпись драйвера WinDivert, антивирус, конфликт с другим winws.exe' 'WARN'
        return $false
    }
    Write-Log 'Служба запущена' 'OK'

    # проверка, что трафик реально идёт через winws
    Start-Sleep -Seconds 2
    $yt = Test-Youtube; $dc = Test-Discord; $tg = Test-Telegram
    Write-Log ("После запуска -> YouTube: {0} | Discord: {1} | Telegram: {2}/{3}" -f $yt.Ok, $dc.Ok, $tg.Open, $tg.Total) 'INFO'
    return $true
}

function Stop-ZapretService {
    Write-Head 'ОСТАНОВКА'
    if (Get-Service -Name $Script:ServiceName -ErrorAction SilentlyContinue) {
        & sc.exe stop $Script:ServiceName 2>&1 | Out-Null
        Start-Sleep -Seconds 2
        Write-Log 'Служба остановлена' 'OK'
    }
    Stop-AllWinws
    Write-Log 'Процессы winws завершены' 'OK'
}

function Show-Status {
    Write-Head 'СОСТОЯНИЕ'
    $state = Get-ServiceState
    Write-Log ("Служба '{0}': {1}" -f $Script:ServiceName, $state) $(if($state -eq 'Running'){'OK'}else{'WARN'})
    $procs = @(Get-Process -Name 'winws' -ErrorAction SilentlyContinue)
    Write-Log ("Процессов winws: {0}" -f $procs.Count) 'INFO'
    if (Test-Path -LiteralPath $Script:ConfFile) {
        Write-Log ("Стратегия: {0}" -f (Get-Content -LiteralPath $Script:ConfFile -Raw).Trim()) 'INFO'
    }
    $yt = Test-Youtube; $dc = Test-Discord; $tg = Test-Telegram
    Write-Log ("YouTube : {0} - {1}" -f $(if($yt.Ok){'OK'}else{'FAIL'}), $yt.Detail) $(if($yt.Ok){'OK'}else{'ERR'})
    Write-Log ("Discord : {0} - {1}" -f $(if($dc.Ok){'OK'}else{'FAIL'}), $dc.Detail) $(if($dc.Ok){'OK'}else{'ERR'})
    Write-Log ("Telegram: {0} - {1}" -f $(if($tg.Ok){'OK'}else{'FAIL'}), $tg.Detail) $(if($tg.Ok){'OK'}else{'ERR'})
}

# =====================================================================================
#  БЛОК 10. TELEGRAM (IP-блок)
# =====================================================================================

function Invoke-TelegramHelp {
    Write-Head 'TELEGRAM: ОТДЕЛЬНАЯ ДИАГНОСТИКА'

    $tg = Test-Telegram
    Write-Log ("TCP до дата-центров: {0}/{1}" -f $tg.Open, $tg.Total) $(if($tg.Ok){'OK'}else{'ERR'})

    if ($tg.Ok) {
        Write-Log 'Telegram доступен по TCP - десинхронизации достаточно.' 'OK'
        Write-Log 'Если приложение всё равно не работает, включи в Telegram: Настройки -> Продвинутые -> Тип соединения -> TCP.' 'INFO'
        return
    }

    Write-Log 'Все DC Telegram недоступны на TCP 443/80/5222.' 'ERR'
    Write-Log 'Это блокировка на уровне IP-адресов. WinDivert/desync такие блоки не обходит:' 'WARN'
    Write-Log '  SYN-пакеты просто уничтожаются по адресу назначения до всякого DPI.' 'WARN'
    Write-Log '' 'INFO'
    Write-Log 'Рабочие варианты без VPN:' 'STEP'
    Write-Log '  1) MTProto-прокси внутри Telegram (Настройки -> Данные и память -> Прокси).' 'INFO'
    Write-Log '     Это не VPN: проксируется только трафик Telegram, системный трафик идёт напрямую.' 'INFO'
    Write-Log '  2) Cloudflare WARP в режиме SOCKS5 - тоже не полноценный VPN, а локальный прокси.' 'INFO'
    Write-Log '  3) telegram.org в браузере не заработает всё равно - Web-версия ходит на те же DC.' 'INFO'

    Write-Log '' 'INFO'
    Write-Log 'Пробую получить список публичных MTProto-прокси...' 'STEP'
    $sources = @(
        'https://raw.githubusercontent.com/hookzof/socks5_list/master/tg/mtproto.json',
        'https://mtpro.xyz/api/?type=mtproto'
    )
    $proxies = @()
    foreach ($u in $sources) {
        try {
            $raw = Get-UrlText -Url $u -TimeoutMs 10000
            if (-not $raw) { continue }
            $data = $raw | ConvertFrom-Json
            foreach ($p in $data) {
                if ($p.host -and $p.port -and $p.secret) {
                    $proxies += [pscustomobject]@{ Host=$p.host; Port=$p.port; Secret=$p.secret }
                }
            }
            if ($proxies.Count -gt 0) { break }
        } catch { }
    }

    if ($proxies.Count -eq 0) {
        Write-Log 'Не удалось скачать список (нет доступа к GitHub/mtpro).' 'WARN'
        Write-Log 'Возьми прокси вручную: https://t.me/MTProtoProxies  или  https://mtpro.xyz' 'INFO'
        return
    }

    Write-Log ("Получено прокси: {0}. Проверяю доступность..." -f $proxies.Count) 'INFO'
    $good = @()
    foreach ($p in $proxies) {
        if ($good.Count -ge 5) { break }
        if ((Test-TcpPort -Target $p.Host -Port ([int]$p.Port) -TimeoutMs 3000) -eq 'ok') {
            $good += $p
            $link = 'tg://proxy?server={0}&port={1}&secret={2}' -f $p.Host, $p.Port, $p.Secret
            Write-Log ("  {0}:{1}" -f $p.Host, $p.Port) 'OK'
            Write-Log ("     $link") 'INFO'
        }
    }

    if ($good.Count -eq 0) {
        Write-Log 'Живых прокси не найдено - обнови список вручную.' 'WARN'
    } else {
        Write-Log '' 'INFO'
        Write-Log 'Скопируй tg:// ссылку выше и вставь в браузер - Telegram сам предложит подключить прокси.' 'STEP'
    }
}

# =====================================================================================
#  БЛОК 11. ОТКАТ
# =====================================================================================

function Invoke-Restore {
    Write-Head 'ОТКАТ ИЗМЕНЕНИЙ'

    Stop-ZapretService

    if (Get-Service -Name $Script:ServiceName -ErrorAction SilentlyContinue) {
        & sc.exe delete $Script:ServiceName 2>&1 | ForEach-Object { Write-Log ("  sc: " + $_) 'INFO' }
        Write-Log 'Служба zapret удалена' 'OK'
    }

    # hosts
    $hostsBak = Get-ChildItem -LiteralPath $Script:BakDir -Directory -ErrorAction SilentlyContinue |
                Sort-Object Name -Descending |
                Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'hosts') } |
                Select-Object -First 1
    if ($hostsBak) {
        Copy-Item -LiteralPath (Join-Path $hostsBak.FullName 'hosts') -Destination $Script:HostsFile -Force
        Clear-DnsClientCache -ErrorAction SilentlyContinue
        Write-Log ("hosts восстановлен из {0}" -f $hostsBak.Name) 'OK'
    } else { Write-Log 'Бэкап hosts не найден' 'WARN' }

    # DNS
    $dnsBak = Get-ChildItem -LiteralPath $Script:BakDir -Directory -ErrorAction SilentlyContinue |
              Sort-Object Name -Descending |
              Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'dns-backup.json') } |
              Select-Object -First 1
    if ($dnsBak) {
        $saved = Get-Content -LiteralPath (Join-Path $dnsBak.FullName 'dns-backup.json') -Raw | ConvertFrom-Json
        foreach ($s in $saved) {
            if ($s.Index -gt 0 -and $s.Dns -and @($s.Dns).Count -gt 0) {
                try {
                    Set-DnsClientServerAddress -InterfaceIndex $s.Index -ServerAddresses @($s.Dns) -ErrorAction Stop
                    Write-Log ("DNS на «{0}» -> {1}" -f $s.Alias, (@($s.Dns) -join ',')) 'OK'
                } catch { Write-Log ("DNS «{0}»: {1}" -f $s.Alias, $_.Exception.Message) 'WARN' }
            }
        }
    } else { Write-Log 'Бэкап DNS не найден' 'WARN' }
    ipconfig /flushdns | Out-Null

    Write-Log 'Файлы в C:\ProgramData\ZapretFix оставлены (там же бэкапы и логи).' 'INFO'
    Write-Log 'Удалить вручную: Remove-Item -Recurse -Force C:\ProgramData\ZapretFix' 'INFO'
}

# =====================================================================================
#  ТОЧКА ВХОДА
# =====================================================================================

Write-Host ''
Write-Host '  ####################################################################' -ForegroundColor DarkCyan
Write-Host '  #  ZapretFix - обход DPI для YouTube / Discord / Telegram           #' -ForegroundColor Cyan
Write-Host '  #  без VPN. Режим:' -NoNewline -ForegroundColor Cyan
Write-Host (" {0,-48}#" -f $Mode) -ForegroundColor Yellow
Write-Host '  ####################################################################' -ForegroundColor DarkCyan

if (-not (Test-Admin) -and -not $NoElevate) {
    Invoke-SelfElevate
}

if (-not (Test-Admin)) {
    Write-Host '[ ! ] Работа без прав администратора: часть операций будет пропущена.' -ForegroundColor Yellow
}

# --- защита от параллельного запуска ---
# Два экземпляра будут драться за winws: один гасит процесс, nssm его поднимает,
# замеры превращаются в мусор. Держим именованный мьютекс на всё время работы.
$Script:SingleInstance = $null
try {
    $Script:SingleInstance = New-Object Threading.Mutex($false, 'Global\ZapretFix_SingleInstance')
    if (-not $Script:SingleInstance.WaitOne(0)) {
        Write-Host ''
        Write-Host '[ ! ] Другой экземпляр ZapretFix уже работает.' -ForegroundColor Yellow
        Write-Host '      Дождись его завершения: параллельный запуск ломает замеры.' -ForegroundColor Yellow
        Write-Host '      Если это зависший процесс: Get-Process powershell | Stop-Process -Force' -ForegroundColor Gray
        exit 1
    }
} catch {
    Write-Host '[ ! ] Не удалось создать мьютекс единственного экземпляра, продолжаю без защиты.' -ForegroundColor Yellow
}

Ensure-Dirs
Write-Log ("Старт. Режим={0}, админ={1}" -f $Mode, (Test-Admin)) 'INFO'

$Diag = $null

switch ($Mode) {

    'Diagnose' {
        $Diag = Invoke-Diagnose
    }

    'All' {
        $Diag = Invoke-Diagnose
        $src = Invoke-Repair -Diag $Diag
        if ($src) {
            $best = if ($ForceStrategy) { Get-NamedStrategy -Name $ForceStrategy } else { Invoke-StrategyTest }
            if ($best) {
                if (-not (Install-ZapretService -Strategy $best)) {
                    Write-Log 'Служба не поднялась. Запусти вручную для отладки:' 'WARN'
                    $cmd = New-WinwsCommandLineByStrategy -Strategy $best -WithDnsDesync:$DnsDesync
                    Write-Log ("  cd `"{0}`"" -f $Script:BinDir) 'INFO'
                    Write-Log ("  {0}" -f $cmd.Full) 'INFO'
                }
            } else {
                Write-Log 'Стратегия не подобрана - служба не установлена.' 'WARN'
            }
        }
    }

    'Repair' {
        $Diag = Invoke-Diagnose
        Invoke-Repair -Diag $Diag | Out-Null
    }

    'Strategy' {
        $best = if ($ForceStrategy) { Get-NamedStrategy -Name $ForceStrategy } else { Invoke-StrategyTest }
        if ($best) {
            Install-ZapretService -Strategy $best | Out-Null
        }
    }

    'Start'  { Start-ZapretService | Out-Null }
    'Stop'   { Stop-ZapretService }
    'Status' { Show-Status }
    'Telegram' { Invoke-TelegramHelp }
    'Restore' { Invoke-Restore }
}

Write-Head 'ГОТОВО'
Write-Log ("Отчёт: {0}" -f $Script:ReportFile) 'INFO'
try { $Script:Report -join "`r`n" | Set-Content -LiteralPath $Script:ReportFile -Encoding UTF8 } catch { }
Write-Log ("Лог: {0}" -f $Script:LogFile) 'INFO'

# отпускаем мьютекс единственного экземпляра
if ($Script:SingleInstance) {
    try { $Script:SingleInstance.ReleaseMutex() } catch { }
    try { $Script:SingleInstance.Dispose() } catch { }
}

if ($Mode -in @('All','Repair','Strategy','Start','Status')) {
    Write-Host ''
    Write-Host '  Полезные команды:' -ForegroundColor Cyan
    Write-Host '    .\Fix-Zapret.ps1 -Mode Status      # проверить, что всё работает'
    Write-Host '    .\Fix-Zapret.ps1 -Mode Stop        # выключить обход'
    Write-Host '    .\Fix-Zapret.ps1 -Mode Start       # включить обратно'
    Write-Host '    .\Fix-Zapret.ps1 -Mode Telegram    # если Telegram не открывается'
    Write-Host '    .\Fix-Zapret.ps1 -Mode Restore     # полный откат'
    Write-Host '    .\Fix-Zapret.ps1 -DnsDesync        # если провайдер режет UDP/53'
    Write-Host ''
}
