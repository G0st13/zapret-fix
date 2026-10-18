# Тестовый стенд: выполняет функции Fix-Zapret.ps1 без записи за пределы workspace
$ErrorActionPreference = 'Continue'
$src = 'C:\Users\karachunn\Documents\deepseek-harness\default-workspace\zapret-fix\Fix-Zapret.ps1'
$ws  = 'C:\Users\karachunn\Documents\deepseek-harness\default-workspace\zapret-fix\_testroot'
Remove-Item -LiteralPath $ws -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $ws -Force | Out-Null

$text = [IO.File]::ReadAllText($src, [Text.UTF8Encoding]::new($true))
$marker = '#  ТОЧКА ВХОДА'
$idx = $text.IndexOf($marker)
if ($idx -lt 0) { throw 'Маркер точки входа не найден' }
$body = $text.Substring(0, $text.LastIndexOf('# ====', $idx))

$tmp = Join-Path $env:TEMP ('zf_' + [guid]::NewGuid().ToString('N') + '.ps1')
[IO.File]::WriteAllText($tmp, $body, [Text.UTF8Encoding]::new($true))
. $tmp -Mode Diagnose -NoElevate

# --- полная изоляция: всё пишем только в workspace ---
$Script:Root       = $ws
$Script:BinDir     = Join-Path $ws 'bin'
$Script:ListsDir   = Join-Path $ws 'lists'
$Script:LogDir     = Join-Path $ws 'logs'
$Script:BakDir     = Join-Path $ws 'backup'
$Script:ConfFile   = Join-Path $ws 'active-strategy.txt'
$Script:ReportFile = Join-Path $ws 'report.txt'
$Script:LogFile    = Join-Path $ws 'logs\test.log'
foreach ($d in @($Script:BinDir,$Script:ListsDir,$Script:LogDir,$Script:BakDir)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }

$script:fail = 0
function Check($name, $cond, $extra) {
  if ($cond) { Write-Host ("  [PASS] {0} {1}" -f $name, $extra) -ForegroundColor Green }
  else       { Write-Host ("  [FAIL] {0} {1}" -f $name, $extra) -ForegroundColor Red; $script:fail++ }
}

Write-Host "`n===== ТЕСТ 1: Get-LocalAdapters =====" -ForegroundColor Cyan
$ad = @(Get-LocalAdapters)
Check 'адаптеры найдены' ($ad.Count -gt 0) ("count=" + $ad.Count)
$ad | ForEach-Object { "    {0,-28} idx={1,-4} {2,-16} gw={3,-14} dns={4}" -f $_.Alias,$_.Index,$_.IPv4,$_.Gateway,($_.Dns -join ',') }
Check 'есть IPv4' (@($ad | Where-Object { $_.IPv4 }).Count -gt 0) ''
Check 'есть DNS'  (@($ad | Where-Object { @($_.Dns).Count -gt 0 }).Count -gt 0) ''

Write-Host "`n===== ТЕСТ 2: Find-ZapretToolchain =====" -ForegroundColor Cyan
$found = @(Find-ZapretToolchain)
Check 'комплект найден' ($found.Count -gt 0) ("count=" + $found.Count)
$found | ForEach-Object { "    score={0,-3} sys={1,-6} {2}" -f $_.Score,$_.HasSys,$_.Path }
if ($found.Count -gt 0) {
  Check 'лучший содержит .sys'      ($found[0].HasSys) ''
  Check 'лучший содержит .bin TLS'  (Test-Path (Join-Path $found[0].Path 'tls_clienthello_www_google_com.bin')) ''
}

Write-Host "`n===== ТЕСТ 3: Test-TcpPort =====" -ForegroundColor Cyan
$t1 = Test-TcpPort -Target '1.1.1.1' -Port 443 -TimeoutMs 3000
$t2 = Test-TcpPort -Target '149.154.167.99' -Port 443 -TimeoutMs 3000
Check 'контроль 1.1.1.1:443 открыт' ($t1 -eq 'ok')      ("-> $t1")
Check 'Telegram DC закрыт'          ($t2 -eq 'timeout') ("-> $t2")

Write-Host "`n===== ТЕСТ 4: Тесты сервисов =====" -ForegroundColor Cyan
$yt = Test-Youtube; $dc = Test-Discord; $tg = Test-Telegram
"    YouTube : ok={0} | {1}" -f $yt.Ok, $yt.Detail
"    Discord : ok={0} | {1}" -f $dc.Ok, $dc.Detail
"    Telegram: ok={0} | {1}" -f $tg.Ok, $tg.Detail
Check 'Test-Telegram вернул объект' ($null -ne $tg.Detail) ''
Check 'Test-Telegram видит блок'    ($tg.Open -eq 0) ''

Write-Host "`n===== ТЕСТ 5: Test-DnsHealth =====" -ForegroundColor Cyan
$h = Test-DnsHealth
"    подменяется : {0}" -f $(if($h.Spoofed.Count){$h.Spoofed -join ','}else{'нет'})
"    разрешается : {0}" -f ($h.Ok -join ', ')
"    DoH работает: {0}" -f $h.DohWorks
Check 'Test-DnsHealth вернул объект' ($null -ne $h) ''
Check 'либо подмена найдена, либо всё разрешается' (($h.Spoofed.Count -gt 0) -or ($h.Ok.Count -ge 4)) ("spoofed={0} ok={1}" -f $h.Spoofed.Count,$h.Ok.Count)

Write-Host "`n===== ТЕСТ 6: New-WinwsCommandLine =====" -ForegroundColor Cyan
foreach ($name in @('fake+fakedsplit','multisplit+seqovl','fake+multidisorder')) {
  $s = $Script:Strategies | Where-Object { $_.Name -eq $name }
  if (-not $s) { continue }
  $c = New-WinwsCommandLine -Strategy $s
  "    --- {0} ---" -f $name
  "      токенов={0}  правил(--new)={1}  длина={2}" -f $c.Tokens.Count, ([regex]::Matches($c.Args,'--new')).Count, $c.Args.Length
  Check "$name : нет кавычек"          (($c.Args -notmatch '"')) ''
  Check "$name : 8 разделителей --new" (([regex]::Matches($c.Args,'--new')).Count -eq 8) ''
  Check "$name : нет двойных пробелов" (($c.Args -notmatch '  ')) ''
  Check "$name : {TLS} подставлен"     (($c.Args -notmatch '\{TLS\}')) ''
}
$c0 = New-WinwsCommandLine -Strategy ($Script:Strategies | Where-Object { $_.Name -eq 'fake+fakedsplit' })
$cd = New-WinwsCommandLine -Strategy ($Script:Strategies | Where-Object { $_.Name -eq 'fake+fakedsplit' }) -WithDnsDesync
Check 'DnsDesync добавляет udp/53' (($cd.Args -split ' ')[1] -match ',53$') (($cd.Args -split ' ')[1])
Check 'без DnsDesync udp/53 нет'   (($c0.Args -split ' ')[1] -notmatch '53') (($c0.Args -split ' ')[1])

Write-Host "`n===== ТЕСТ 6b: simple-конфиг (без хостлистов) =====" -ForegroundColor Cyan
$s1 = $Script:Strategies | Where-Object { $_.Name -eq 'simple+ipid0' }
Check 'стратегия simple+ipid0 есть' ($null -ne $s1) ''
$cs = New-WinwsCommandLineByStrategy -Strategy $s1
"      токенов={0} длина={1}" -f $cs.Tokens.Count, $cs.Args.Length
"      {0}" -f $cs.Args.Substring(0,[Math]::Min(200,$cs.Args.Length))
Check 'simple: нет --hostlist'          ($cs.Args -notmatch '--hostlist') ''
Check 'simple: нет --ipset='            ($cs.Args -notmatch '--ipset=') ''
Check 'simple: есть --ip-id=zero'       ($cs.Args -match '--ip-id=zero') ''
Check 'simple: есть --filter-tcp=80,443' ($cs.Args -match '--filter-tcp=80,443') ''
Check 'simple: есть правило Discord-голоса' ($cs.Args -match 'filter-l7=discord,stun') ''
Check 'simple: есть правило QUIC'       ($cs.Args -match 'dpi-desync-fake-quic') ''
Check 'simple: нет кавычек'             ($cs.Args -notmatch '"') ''
$s3 = $Script:Strategies | Where-Object { $_.Name -eq 'simple+tcp-only' }
$cs3 = New-WinwsCommandLineByStrategy -Strategy $s3
Check 'tcp-only: UDP-правил нет'        ($cs3.Args -notmatch '--wf-udp') ''
$s4 = $Script:Strategies | Where-Object { $_.Name -eq 'simple+excl' }
$cs4 = New-WinwsCommandLineByStrategy -Strategy $s4
Check 'excl: есть --ipset-exclude'      ($cs4.Args -match '--ipset-exclude') ''
Check 'всего стратегий'                 ($Script:Strategies.Count -ge 12) ("count=" + $Script:Strategies.Count)

# round-trip: аргументы должны доехать до процесса без искажений
$dump = Join-Path $ws 'dump.ps1'
Set-Content -LiteralPath $dump -Value '$args | ForEach-Object { "[" + $_ + "]" }' -Encoding UTF8
$rt = @(& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $dump $c0.Tokens)
Check 'round-trip аргументов 1:1' ($rt.Count -eq $c0.Tokens.Count) ("получено {0} из {1}" -f $rt.Count, $c0.Tokens.Count)
$mismatch = 0
for ($i=0; $i -lt [Math]::Min($rt.Count, $c0.Tokens.Count); $i++) {
  if ($rt[$i] -ne ('[' + $c0.Tokens[$i] + ']')) { $mismatch++; "      отличие[{0}]: send=[{1}] recv={2}" -f $i,$c0.Tokens[$i],$rt[$i] }
}
Check 'нет искажённых аргументов' ($mismatch -eq 0) ("расхождений: $mismatch")

Write-Host "`n===== ТЕСТ 7: Add-DomainsToList (идемпотентность) =====" -ForegroundColor Cyan
$gen = Join-Path $Script:ListsDir 'list-general.txt'
Set-Content -LiteralPath $gen -Value "discord.com`nyoutube.com" -Encoding ASCII
$a1 = Add-DomainsToList -File $gen -Domains $Script:ExtraGeneral
$a2 = Add-DomainsToList -File $gen -Domains $Script:ExtraGeneral
Check 'первый вызов добавляет'   ($a1 -gt 0) ("+$a1")
Check 'второй вызов добавляет 0' ($a2 -eq 0) ("+$a2")
Check 'telegram.org в списке' (Select-String -Path $gen -Pattern '^telegram\.org$' -Quiet) ''
Check 't.me в списке'         (Select-String -Path $gen -Pattern '^t\.me$' -Quiet) ''
$dups = @(Get-Content $gen | Where-Object { $_.Trim() } | Group-Object | Where-Object { $_.Count -gt 1 }).Count
Check 'нет дубликатов строк' ($dups -eq 0) ("дублей: $dups")

Write-Host "`n===== ТЕСТ 8: Install-Lists + восстановление ipset =====" -ForegroundColor Cyan
$srcFake = [pscustomobject]@{ Path = 'C:\Users\karachunn\Desktop\Новая папка\bin' }
Set-Content -LiteralPath (Join-Path $Script:ListsDir 'ipset-all.txt')        -Value '203.0.113.113/32' -Encoding ASCII
Set-Content -LiteralPath (Join-Path $Script:ListsDir 'ipset-all.txt.backup') -Value (1..5000 | ForEach-Object { "10.$([math]::Floor($_/256)).$($_ % 256).0/24" }) -Encoding ASCII
$stat = Install-Lists -Source $srcFake
"    скопировано={0} ipsetRestored={1} строк={2}" -f $stat.Copied,$stat.IpsetRestored,$stat.IpsetLines
Check 'списки скопированы'       ($stat.Copied -ge 5) ''
Check 'ipset восстановлен'       ($stat.IpsetRestored) ''
Check 'ipset стал большим'       ($stat.IpsetLines -gt 1000) ("строк: " + $stat.IpsetLines)
Check 'list-exclude.txt создан'  (Test-Path (Join-Path $Script:ListsDir 'list-exclude.txt')) ''
Check 'ipset-exclude.txt создан' (Test-Path (Join-Path $Script:ListsDir 'ipset-exclude.txt')) ''

Write-Host "`n===== ТЕСТ 9: Write-RunScript =====" -ForegroundColor Cyan
$rc = Write-RunScript -Command $c0
Check 'run.cmd создан' (Test-Path $rc) $rc
$rcText = Get-Content -LiteralPath $rc -Raw
Check 'run.cmd содержит winws.exe'   ($rcText -match 'winws\.exe') ''
Check 'run.cmd отключает delayedexp' ($rcText -match 'DisableDelayedExpansion') ''
Check 'run.cmd содержит --wf-tcp'    ($rcText -match '--wf-tcp') ''

Write-Host "`n===== ТЕСТ 10: Repair-Hosts на копии =====" -ForegroundColor Cyan
$fakeHosts = Join-Path $ws 'hosts-test'
@(
  '# тестовый hosts'
  '74.119.194.9 chatgpt.com'
  '74.119.194.9 claude.ai'
  '109.94.209.70 fitgirlrepacks.in'
  '142.250.117.93 www.youtube.com'
  '192.168.0.1 router.local'
) | Set-Content -LiteralPath $fakeHosts -Encoding ASCII
$Script:HostsFile = $fakeHosts
Repair-Hosts
$after = @(Get-Content -LiteralPath $fakeHosts)
"    осталось строк: {0}" -f $after.Count
$after | ForEach-Object { "      $_" }
Check 'заглушка chatgpt удалена'  (-not ($after -match '^74\.119\.194\.9\s+chatgpt\.com')) ''
Check 'фейковый fitgirl удалён'   (-not ($after -match '^\s*\d+\.\d+\.\d+\.\d+\s+fitgirlrepacks\.in')) ''
Check 'легитимная запись осталась' (@($after -match 'router\.local').Count -gt 0) ''
Check 'комментарии без ??????'     (-not ($after -match '\?\?\?\?')) ''
Check 'заголовок латиницей'        (@($after -match 'ZapretFix: hosts cleaned').Count -gt 0) ''

Write-Host "`n===== ТЕСТ 11: RemoveYoutubePins =====" -ForegroundColor Cyan
@(
  '142.250.117.93 www.youtube.com'
  '192.168.0.1 router.local'
) | Set-Content -LiteralPath $fakeHosts -Encoding ASCII
$rm = Repair-Hosts -RemoveYoutubePins
$after2 = @(Get-Content -LiteralPath $fakeHosts)
"    удалено={0}, осталось={1}" -f $rm, $after2.Count
Check 'пин youtube снят'  (-not ($after2 -match '^\s*\d+\.\d+\.\d+\.\d+\s+www\.youtube\.com')) ''
Check 'router.local на месте' (@($after2 -match 'router\.local').Count -gt 0) ''

Write-Host "`n===== ТЕСТ 12: Get-DefaultRouteInterface =====" -ForegroundColor Cyan
$def = Get-DefaultRouteInterface
if ($def) {
  "    шлюз={0} index={1} sourceIP={2} metric={3}" -f $def.Gateway,$def.Index,$def.SourceIP,$def.Metric
  Check 'основной шлюз определён' ($def.Gateway) ''
  Check 'это Wi-Fi (192.168.0.x), а не Radmin 26.x' ($def.Gateway -notmatch '^26\.') ("-> " + $def.Gateway)
} else { Check 'основной шлюз определён' $false 'вернулся $null' }

Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
Write-Host ""
if ($fail -eq 0) { Write-Host "########## ВСЕ ТЕСТЫ ПРОЙДЕНЫ ##########" -ForegroundColor Green }
else             { Write-Host "########## ПРОВАЛЕНО ТЕСТОВ: $fail ##########" -ForegroundColor Red; exit 1 }
