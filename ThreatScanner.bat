@echo off
setlocal
title Threat Scanner - Bulk PDF Report Generator
set "SELF=%~f0"
set "BASE=%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$c=[IO.File]::ReadAllText($env:SELF); $c=$c -replace '(?s)^.*#PSSTART',''; & ([ScriptBlock]::Create($c))"
echo.
pause
exit /b

#PSSTART
# ---------------------------------------------------------------------------
# Threat Scanner - one PDF report per CAN ID
# Input : CAN_Merged.xlsx (same folder)  columns: CAN ID | URL | App name | Request id
# Output: Reports\<AppName>_<CANID>_ThreatScanner.pdf   (+ Reports\ThreatScanner_Summary_<time>.csv)
# Rows with App name or Request id = NOT FOUND are skipped.
# ---------------------------------------------------------------------------
$ErrorActionPreference = 'Continue'

# ===== Report branding - edit here =====
$BankName   = 'ICICI Bank'
$ReportName = 'Application Security Health Check Report'
$ColorMain  = '#B02A30'
$ColorAccent= '#F37E20'
$Classification = 'CONFIDENTIAL - FOR INTERNAL USE ONLY'
# =======================================

$base      = $env:BASE
$inputFile = Join-Path $base 'CAN_Merged.xlsx'
$outDir    = Join-Path $base 'Reports'
$timeoutMs = 20000
$threads   = 10
$stamp     = Get-Date -Format 'yyyyMMdd_HHmmss'
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$logFile = Join-Path $outDir "ThreatScanner_$stamp.log"
function Log($m) { try { Add-Content -Path $logFile -Value ("{0} {1}" -f (Get-Date -Format 'HH:mm:ss'), $m) } catch {} }

# ---- read xlsx without Excel (zip + xml) ----
function Read-Xlsx($path) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $tmp = Join-Path $env:TEMP ("tsx_" + [Guid]::NewGuid().ToString('N') + '.xlsx')
    Copy-Item -LiteralPath $path -Destination $tmp -Force     # works even if the file is open in Excel
    $zip = [IO.Compression.ZipFile]::OpenRead($tmp)
    try {
        $readEntry = {
            param($name)
            $en = $zip.GetEntry($name); if (-not $en) { return $null }
            $sr = New-Object IO.StreamReader($en.Open(), [Text.Encoding]::UTF8)
            try { $sr.ReadToEnd() } finally { $sr.Close() }
        }
        $shared = @()
        $ssXml = & $readEntry 'xl/sharedStrings.xml'
        if ($ssXml) {
            $d = New-Object Xml.XmlDocument; $d.LoadXml($ssXml)
            foreach ($si in $d.SelectNodes("//*[local-name()='si']")) {
                $shared += (($si.SelectNodes(".//*[local-name()='t']") | ForEach-Object { $_.InnerText }) -join '')
            }
        }
        $sheetXml = & $readEntry 'xl/worksheets/sheet1.xml'
        if (-not $sheetXml) { throw 'Sheet1 not found in workbook' }
        $d = New-Object Xml.XmlDocument; $d.LoadXml($sheetXml)
        $rows = @()
        foreach ($row in $d.SelectNodes("//*[local-name()='row']")) {
            $vals = @{}
            foreach ($c in $row.SelectNodes("*[local-name()='c']")) {
                $col = ($c.GetAttribute('r') -replace '\d', '')
                $t = $c.GetAttribute('t')
                $v = $c.SelectSingleNode("*[local-name()='v']")
                if ($t -eq 's' -and $v) { $val = $shared[[int]$v.InnerText] }
                elseif ($t -eq 'inlineStr') { $val = (($c.SelectNodes(".//*[local-name()='t']") | ForEach-Object { $_.InnerText }) -join '') }
                elseif ($v) { $val = $v.InnerText } else { $val = '' }
                $vals[$col] = $val
            }
            $rows += , $vals
        }
        return $rows
    } finally { $zip.Dispose(); Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
}

Clear-Host
Write-Host "=== $BankName - Threat Scanner ===" -ForegroundColor Cyan
if (-not (Test-Path $inputFile)) { Write-Host "CAN_Merged.xlsx not found next to this script:`n  $inputFile" -ForegroundColor Red; return }
try { $raw = Read-Xlsx $inputFile } catch { Write-Host "Could not read Excel file: $($_.Exception.Message)" -ForegroundColor Red; return }
if ($raw.Count -lt 2) { Write-Host 'Excel file has no data rows.' -ForegroundColor Red; return }

$colOf = @{}
foreach ($k in $raw[0].Keys) { $colOf[([string]$raw[0][$k]).Trim().ToLower()] = $k }
foreach ($need in 'can id', 'url', 'app name', 'request id') {
    if (-not $colOf.ContainsKey($need)) { Write-Host "Column '$need' missing in Excel header." -ForegroundColor Red; return }
}
$records = @(); $skipped = 0
for ($i = 1; $i -lt $raw.Count; $i++) {
    $r = $raw[$i]
    $g = { param($n) $c = $colOf[$n]; if ($r.ContainsKey($c)) { ([string]$r[$c]).Trim() } else { '' } }
    $can = & $g 'can id'; $app = & $g 'app name'; $req = & $g 'request id'; $url = & $g 'url'
    if (-not $can) { continue }
    if (-not $app -or $app -match '^(?i)NOT FOUND$' -or -not $req -or $req -match '^(?i)NOT FOUND$' -or -not $url) { $skipped++; Log "SKIPPED CAN $can (app='$app' req='$req')"; continue }
    $records += [PSCustomObject]@{ CAN = $can; App = $app; Req = $req; Urls = $url }
}
Write-Host "Loaded $($records.Count) CAN ID(s) to scan, $skipped skipped (NOT FOUND / empty)." -ForegroundColor Green
$only = (Read-Host 'Enter a single CAN ID to run only that one (or press Enter for ALL)').Trim()
if ($only) { $records = @($records | Where-Object { $_.CAN -eq $only }); if (-not $records.Count) { Write-Host "CAN $only not found / skipped." -ForegroundColor Red; return } }

# ---- TLS: accept any certificate (Zscaler etc.) but record it ----
try {
    Add-Type -TypeDefinition @"
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public static class CertCap {
    [ThreadStatic] public static X509Certificate2 Cert;
    public static bool Cb(object s, X509Certificate c, X509Chain ch, SslPolicyErrors e) {
        if (c != null) { try { Cert = new X509Certificate2(c); } catch {} }
        return true;
    }
    public static void Enable() {
        ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(Cb);
    }
}
"@ -ErrorAction Stop
} catch { if ($_.Exception.Message -notmatch 'already exists') { Log "Add-Type: $($_.Exception.Message)" } }
[CertCap]::Enable()
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]'Tls12,Tls11,Tls' } catch {}
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 12288 } catch {}
[Net.ServicePointManager]::Expect100Continue = $false
[Net.ServicePointManager]::DefaultConnectionLimit = 100
try {
    $px = [Net.WebRequest]::GetSystemWebProxy()
    $px.Credentials = [Net.CredentialCache]::DefaultCredentials
    [Net.WebRequest]::DefaultWebProxy = $px
} catch {}

$secHeaders = [ordered]@{
    'Strict-Transport-Security' = 'HSTS'
    'Content-Security-Policy'   = 'CSP'
    'X-Frame-Options'           = 'X-Frame-Options'
    'X-Content-Type-Options'    = 'X-Content-Type-Options'
    'Referrer-Policy'           = 'Referrer-Policy'
}

# ---- per-URL check (runs inside runspace threads) ----
$checkScript = {
    param($url, $timeoutMs, $secHeaders, $wild)
    function Check-One($url) {
    $r = [ordered]@{
        URL=$url; Status='FAIL'; HttpCode=''; HttpText=''; FinalUrl=''; TimeMs=''; ResolvedIP=''
        Server=''; CertSubject=''; CertIssuer=''; CertFrom=''; CertExpires=''; DaysLeft=''; Interception=''
        Hdr=@{}; Findings=(New-Object System.Collections.Generic.List[string])
    }
    $f = $r.Findings
    $uri = $null
    try { $uri = [Uri]$url } catch { $f.Add('Invalid URL'); return $r }
    try {
        $ips = @([Net.Dns]::GetHostAddresses($uri.Host) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.ToString() })
        $r.ResolvedIP = $ips -join ', '
    } catch { $f.Add('DNS resolution failed') }

    [CertCap]::Cert = $null
    $resp = $null
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        $req = [Net.HttpWebRequest]::Create($uri)
        $req.Method = 'GET'; $req.Timeout = $timeoutMs; $req.ReadWriteTimeout = $timeoutMs
        $req.KeepAlive = $false
        $req.ConnectionGroupName = [Guid]::NewGuid().ToString()
        $req.AllowAutoRedirect = $true; $req.MaximumAutomaticRedirections = 10
        $req.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppHealthCheck/1.0'
        $req.UseDefaultCredentials = $true
        try { $req.AutomaticDecompression = [Net.DecompressionMethods]'GZip,Deflate' } catch {}
        $resp = $req.GetResponse()
    } catch [Net.WebException] {
        $resp = $_.Exception.Response
        if (-not $resp) {
            $msg = $_.Exception.Message
            if ($_.Exception.InnerException) { $msg = $_.Exception.InnerException.Message }
            $f.Add("No response ($($_.Exception.Status)): $msg")
        }
    } catch { $f.Add("Error: $($_.Exception.Message)") }
    $sw.Stop()
    $r.TimeMs = [int]$sw.ElapsedMilliseconds

    $cert = [CertCap]::Cert
    if ($cert) {
        $r.CertSubject = $cert.Subject; $r.CertIssuer = $cert.Issuer
        $r.CertFrom = $cert.NotBefore.ToString('dd-MMM-yyyy'); $r.CertExpires = $cert.NotAfter.ToString('dd-MMM-yyyy')
        $days = [int]($cert.NotAfter - (Get-Date)).TotalDays
        $r.DaysLeft = $days
        if ($days -lt 0)      { $f.Add("SSL certificate has EXPIRED on $($r.CertExpires)") }
        elseif ($days -lt 30) { $f.Add("SSL certificate expires in $days days") }
        if ($cert.Issuer -match '(?i)zscaler') { $r.Interception = 'Zscaler' }
    }

    if ($resp) {
        try {
            $code = [int]$resp.StatusCode
            $r.HttpCode = $code; $r.HttpText = [string]$resp.StatusDescription
            $r.FinalUrl = $resp.ResponseUri.AbsoluteUri
            $r.Server = [string]$resp.Headers['Server']
            foreach ($k in $secHeaders.Keys) {
                $has = [bool]$resp.Headers[$k]
                if (-not $has -and $k -eq 'X-Frame-Options' -and $resp.Headers['Content-Security-Policy'] -match 'frame-ancestors') { $has = $true }
                if (-not $has -and $k -eq 'Strict-Transport-Security' -and $resp.ResponseUri.Scheme -ne 'https') { $r.Hdr[$k] = 'NA'; continue }
                $r.Hdr[$k] = if ($has) { 'Yes' } else { 'No' }
                if (-not $has) { $f.Add("Missing security header: $($secHeaders[$k])") }
            }
            if ($r.Server -match '\d+\.\d+') { $f.Add("Server version disclosed ($($r.Server))") }
            if ($resp.Headers['X-Powered-By']) { $f.Add("Technology disclosed via X-Powered-By ($($resp.Headers['X-Powered-By']))") }
            $sc = [string]$resp.Headers['Set-Cookie']
            if ($sc) {
                if ($sc -notmatch '(?i)httponly')   { $f.Add('Cookie set without HttpOnly flag') }
                if ($sc -notmatch '(?i);\s*secure') { $f.Add('Cookie set without Secure flag') }
            }
            if ($resp.ResponseUri.Scheme -ne 'https') { $f.Add('Application is served over HTTP (not HTTPS)') }
            if ($code -ge 500) { $r.Status = 'FAIL' }
            elseif ($code -ge 400 -and $code -ne 401 -and $code -ne 403) { $r.Status = 'WARN' }
            else { $r.Status = 'PASS' }
            if ($code -ge 400) { $f.Add("HTTP response $code $($r.HttpText)") }
            if ($r.Status -eq 'PASS' -and $f.Count -gt 0) { $r.Status = 'WARN' }
        } catch { $f.Add("Parse error: $($_.Exception.Message)") }
        finally { try { $resp.Close() } catch {} }
    }
    return $r
    }

    $r = Check-One $url
    if ($wild) {   # wildcard entry such as *.domain.com : probe base domain, then www.<base>
        if (-not $r.HttpCode) {
            $alt = 'https://www.' + ($url -replace '^https?://', '')
            $r2 = Check-One $alt
            if ($r2.HttpCode) { $r = $r2 }
        }
        $probe = $r.URL
        $r.URL = $wild
        if ($r.HttpCode) { $r.Findings.Insert(0, "Wildcard entry - assessed using $probe") }
        else {
            $r.Status = 'N/A'; $r.Findings.Clear()
            $r.Findings.Add("Wildcard entry - base domain not directly reachable; individual sub-domains cannot be validated (informational)")
        }
        $r['Probe'] = $probe
    }
    return $r
}

$pool = [runspacefactory]::CreateRunspacePool(1, $threads)
$pool.Open()

function Scan-Urls($items) {
    $jobs = @()
    foreach ($it in $items) {
        $u = $it.Url
        $ps = [powershell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript($checkScript).AddArgument($u).AddArgument($timeoutMs).AddArgument($secHeaders).AddArgument($it.Wild)
        $jobs += [PSCustomObject]@{ PS = $ps; H = $ps.BeginInvoke(); Url = $u }
    }
    $out = @()
    foreach ($j in $jobs) {
        try {
            $res = $j.PS.EndInvoke($j.H)
            if ($res.Count -gt 0) { $out += $res[0] } else { throw 'no result' }
        } catch {
            $out += [ordered]@{ URL=$j.Url; Status='FAIL'; HttpCode=''; HttpText=''; FinalUrl=''; TimeMs=''; ResolvedIP=''; Server=''
                CertSubject=''; CertIssuer=''; CertFrom=''; CertExpires=''; DaysLeft=''; Interception=''; Hdr=@{}
                Findings=[System.Collections.Generic.List[string]]@("Scan error: $($_.Exception.Message)") }
        } finally { $j.PS.Dispose() }
    }
    return $out
}

$e = { param($s) [Net.WebUtility]::HtmlEncode([string]$s) }
$recMap = @(
    @{ P='EXPIRED|expires in'; T='Renew the SSL/TLS certificate before expiry.' },
    @{ P='Missing security header: HSTS'; T='Enable Strict-Transport-Security (HSTS) on the web server.' },
    @{ P='Missing security header: CSP'; T='Define a Content-Security-Policy header to reduce XSS risk.' },
    @{ P='Missing security header: X-Frame-Options'; T='Add X-Frame-Options (or CSP frame-ancestors) to prevent clickjacking.' },
    @{ P='Missing security header: X-Content-Type-Options'; T='Add X-Content-Type-Options: nosniff.' },
    @{ P='Missing security header: Referrer-Policy'; T='Add a Referrer-Policy header.' },
    @{ P='Server version disclosed|X-Powered-By'; T='Hide server version and technology banners.' },
    @{ P='HttpOnly|Secure flag'; T='Set HttpOnly and Secure flags on all cookies.' },
    @{ P='not HTTPS'; T='Serve the application over HTTPS only.' },
    @{ P='No response|DNS resolution|HTTP response 5|Invalid URL|Scan error'; T='Investigate availability / correctness of the listed URL(s).' }
)

$browser = @(
    "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
    "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
    "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
    "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
    "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

function Build-Html($rec, $results, $urlCount) {
    $nPass = @($results | Where-Object { $_.Status -eq 'PASS' }).Count
    $nWarn = @($results | Where-Object { $_.Status -eq 'WARN' }).Count
    $nFail = @($results | Where-Object { $_.Status -eq 'FAIL' }).Count
    $nNA   = @($results | Where-Object { $_.Status -eq 'N/A' }).Count
    if ($nFail -gt 0) { $overall = 'FAIL' } elseif ($nWarn -gt 0) { $overall = 'PASS WITH OBSERVATIONS' } else { $overall = 'PASS' }
    $ovCol = switch ($overall) { 'PASS' {'#1e8e3e'} 'FAIL' {'#c62828'} default {'#e08a00'} }
    $now = Get-Date -Format 'dd-MMM-yyyy HH:mm'
    $reportId = "SHC-$($rec.CAN)-$stamp"
    $allFind = @($results | ForEach-Object { $_.Findings } | ForEach-Object { $_ })
    $recs = @($recMap | Where-Object { $p = $_.P; @($allFind | Where-Object { $_ -match $p }).Count } | ForEach-Object { $_.T })

    $sb = New-Object System.Text.StringBuilder
    $null = $sb.AppendLine(@"
<!doctype html><html><head><meta charset="utf-8"><title>$(& $e $ReportName)</title><style>
@page { size: A4; margin: 14mm 12mm 16mm 12mm; }
* { box-sizing: border-box; }
body { font-family: Segoe UI, Arial, sans-serif; color:#222; font-size:10.5px; margin:0; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
.band { background:$ColorMain; color:#fff; padding:14px 18px; border-bottom:5px solid $ColorAccent; }
.band .bank { font-size:22px; font-weight:700; letter-spacing:.5px; }
.band .rep { font-size:14px; margin-top:2px; }
.meta { display:flex; justify-content:space-between; font-size:9.5px; color:#555; margin:6px 2px 10px; }
h2 { font-size:12.5px; color:$ColorMain; border-bottom:2px solid $ColorAccent; padding-bottom:3px; margin:16px 0 7px; }
table { border-collapse:collapse; width:100%; margin-bottom:6px; }
th, td { border:1px solid #c9c9c9; padding:4px 6px; text-align:left; vertical-align:top; word-wrap:break-word; }
th { background:#f4e3e3; color:#4a1013; font-weight:600; }
table.kv th { width:22%; }
tr { page-break-inside:avoid; }
.badge { display:inline-block; padding:1px 8px; border-radius:9px; color:#fff; font-weight:700; font-size:9.5px; }
.NA { background:#6b7280; } .PASS { background:#1e8e3e; } .WARN { background:#e08a00; } .FAIL { background:#c62828; }
.yes { color:#1e8e3e; font-weight:700; } .no { color:#c62828; font-weight:700; }
.overall { display:inline-block; padding:6px 16px; color:#fff; font-weight:700; font-size:13px; border-radius:4px; background:$ovCol; }
.cards { display:flex; gap:10px; margin:8px 0; } .card { flex:1; border:1px solid #c9c9c9; border-top:4px solid $ColorAccent; padding:6px 10px; text-align:center; }
.card b { font-size:20px; display:block; }
ul { margin:4px 0 4px 18px; padding:0; } li { margin-bottom:2px; }
.sign td { height:48px; width:50%; }
.foot { margin-top:14px; font-size:9px; color:#777; text-align:center; border-top:1px solid #ccc; padding-top:5px; }
.small { font-size:9.5px; color:#555; }
</style></head><body>
<div class="band"><div class="bank">$(& $e $BankName)</div><div class="rep">$(& $e $ReportName)</div></div>
<div class="meta"><span>Report ID: $reportId</span><span>Generated: $now</span><span>$(& $e $Classification)</span></div>

<h2>1. Application Details</h2>
<table class="kv">
<tr><th>Application Name</th><td>$(& $e $rec.App)</td><th>CAN ID</th><td>$(& $e $rec.CAN)</td></tr>
<tr><th>Request ID(s)</th><td colspan="3">$(& $e $rec.Req)</td></tr>
<tr><th>No. of URLs Assessed</th><td>$urlCount</td><th>Assessment Date</th><td>$now</td></tr>
<tr><th>Scanned From</th><td colspan="3">$(& $e $env:COMPUTERNAME) ($(& $e $env:USERNAME))</td></tr>
</table>

<h2>2. Executive Summary</h2>
<div>Overall Result: <span class="overall">$overall</span></div>
<div class="cards"><div class="card"><b>$($results.Count)</b>URLs</div><div class="card"><b style="color:#1e8e3e">$nPass</b>Pass</div><div class="card"><b style="color:#e08a00">$nWarn</b>Observations</div><div class="card"><b style="color:#c62828">$nFail</b>Fail</div><div class="card"><b style="color:#6b7280">$nNA</b>N/A (wildcard)</div></div>
<div class="small">Pass = reachable with no observations. Observations = reachable but with security/configuration gaps. Fail = unreachable or server error. N/A = wildcard entry (e.g. *.domain.com) whose base domain is not directly reachable; informational only.</div>

<h2>3. URL Assessment</h2>
<table><tr><th>#</th><th>URL</th><th>Result</th><th>HTTP</th><th>Resp. (ms)</th><th>Resolved IP</th></tr>
"@)
    $i = 0
    foreach ($r in $results) {
        $i++
        $code = if ($r.HttpCode) { "$($r.HttpCode) $($r.HttpText)" } else { '-' }
        $fu = if ($r.FinalUrl -and $r.FinalUrl.TrimEnd('/') -ne $r.URL.TrimEnd('/')) { "<br><span class='small'>Redirects to: $(& $e $r.FinalUrl)</span>" } else { '' }
        if ($r.Probe -and $r.URL -ne $r.Probe -and $r.HttpCode) { $fu = "<br><span class='small'>Wildcard - assessed using $(& $e $r.Probe)</span>" + $fu }
        $null = $sb.AppendLine("<tr><td>$i</td><td>$(& $e $r.URL)$fu</td><td><span class='badge $($r.Status -replace '/','')'>$($r.Status)</span></td><td>$(& $e $code)</td><td>$($r.TimeMs)</td><td>$(& $e $(if ($r.ResolvedIP) { $r.ResolvedIP } else { '-' }))</td></tr>")
    }
    $null = $sb.AppendLine('</table>')

    $null = $sb.AppendLine('<h2>4. SSL/TLS Certificate Details</h2><table><tr><th>#</th><th>URL</th><th>Issued To</th><th>Issuer</th><th>Valid From</th><th>Valid Till</th><th>Days Left</th></tr>')
    $i = 0
    foreach ($r in $results) {
        $i++
        $iss = & $e $r.CertIssuer
        if ($r.Interception) { $iss += "<br><span class='small'>(Certificate re-signed by $($r.Interception) proxy on this network)</span>" }
        $dl = if ($r.DaysLeft -ne '') { if ([int]$r.DaysLeft -lt 30) { "<span class='no'>$($r.DaysLeft)</span>" } else { $r.DaysLeft } } else { '-' }
        $null = $sb.AppendLine("<tr><td>$i</td><td>$(& $e $r.URL)</td><td>$(& $e $(if ($r.CertSubject) { $r.CertSubject } else { 'N/A' }))</td><td>$iss</td><td>$($r.CertFrom)</td><td>$($r.CertExpires)</td><td>$dl</td></tr>")
    }
    $null = $sb.AppendLine('</table>')

    $null = $sb.AppendLine('<h2>5. HTTP Security Headers</h2><table><tr><th>#</th><th>URL</th>' + (($secHeaders.Values | ForEach-Object { "<th>$_</th>" }) -join '') + '<th>Server Banner</th></tr>')
    $i = 0
    foreach ($r in $results) {
        $i++
        $cells = foreach ($k in $secHeaders.Keys) {
            $v = $r.Hdr[$k]
            if ($v -eq 'Yes') { '<td class="yes">Present</td>' } elseif ($v -eq 'No') { '<td class="no">Missing</td>' } else { '<td>-</td>' }
        }
        $null = $sb.AppendLine("<tr><td>$i</td><td>$(& $e $r.URL)</td>$($cells -join '')<td>$(& $e $(if ($r.Server) { $r.Server } else { '-' }))</td></tr>")
    }
    $null = $sb.AppendLine('</table>')

    $null = $sb.AppendLine('<h2>6. Observations</h2>')
    $i = 0; $any = $false
    foreach ($r in $results) {
        $i++
        if ($r.Findings.Count) {
            $any = $true
            $null = $sb.AppendLine("<b>$i. $(& $e $r.URL)</b><ul>" + (($r.Findings | ForEach-Object { "<li>$(& $e $_)</li>" }) -join '') + '</ul>')
        }
    }
    if (-not $any) { $null = $sb.AppendLine('<div>No observations noted.</div>') }

    $null = $sb.AppendLine('<h2>7. Recommendations</h2>')
    if ($recs.Count) { $null = $sb.AppendLine('<ul>' + (($recs | ForEach-Object { "<li>$(& $e $_)</li>" }) -join '') + '</ul>') }
    else { $null = $sb.AppendLine('<div>No action required.</div>') }

    $null = $sb.AppendLine(@"
<h2>8. Sign-off</h2>
<table class="sign"><tr><th>Prepared By</th><th>Reviewed / Approved By</th></tr><tr><td>Name / Date:</td><td>Name / Date:</td></tr></table>
<div class="foot">$(& $e $Classification) &bull; $(& $e $BankName) &bull; $reportId<br>
Automated, non-intrusive assessment (single HTTP GET per URL, DNS lookup). Certificate validation is bypassed for the scan; certificate details are reported above.</div>
</body></html>
"@)
    return @{ Html = $sb.ToString(); Overall = $overall; Pass = $nPass; Warn = $nWarn; Fail = $nFail; NA = $nNA }
}

function Save-Pdf($html, $pdfFile) {
    $htmlFile = [IO.Path]::ChangeExtension($pdfFile, '.html')
    [IO.File]::WriteAllText($htmlFile, $html, (New-Object Text.UTF8Encoding($true)))
    if (Test-Path $pdfFile) { Remove-Item $pdfFile -Force -ErrorAction SilentlyContinue }
    if ($browser) {
        try {
            $tmpProfile = Join-Path $env:TEMP ("shc_" + [Guid]::NewGuid().ToString('N'))
            $args = @('--headless', '--disable-gpu', '--no-first-run', '--no-pdf-header-footer',
                      "--user-data-dir=`"$tmpProfile`"", "--print-to-pdf=`"$pdfFile`"", "`"$(([Uri]$htmlFile).AbsoluteUri)`"")
            Start-Process -FilePath $browser -ArgumentList $args -WindowStyle Hidden -Wait
            for ($w = 0; $w -lt 20 -and -not (Test-Path $pdfFile); $w++) { Start-Sleep -Milliseconds 500 }
            Remove-Item $tmpProfile -Recurse -Force -ErrorAction SilentlyContinue
        } catch { Log "PDF error: $($_.Exception.Message)" }
    }
    if (Test-Path $pdfFile) { Remove-Item $htmlFile -Force -ErrorAction SilentlyContinue; return $pdfFile }
    return $htmlFile
}

# ---- main loop ----
$summary = New-Object System.Collections.Generic.List[object]
$total = $records.Count; $n = 0
Write-Host ''
Write-Host "Scanning $total CAN ID(s), $threads URLs in parallel. SSL errors are ignored (recorded in report)." -ForegroundColor Cyan
foreach ($rec in $records) {
    $n++
    try {
        $items = @(); $seen = @{}
        foreach ($tok in ($rec.Urls -split '[,;\s]+')) {
            $t = $tok.Trim()
            if (-not $t -or $t -match '^[\.\*/]+$') { continue }
            $orig = $t
            $wild = ''
            if ($t -match '\*' -or $t.StartsWith('.') -or $t -match '^(?i)https?://\.') {
                $wild = $orig
                $t = $t -replace '^(?i)(https?://)?(\*\.|\.)+', '$1'
                $t = $t -replace '\*', 'www'
                if (-not $t) { continue }
            }
            if ($t -notmatch '^(?i)https?://') { $t = 'https://' + $t }
            $key = "$t|$wild"
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = 1
            $items += [PSCustomObject]@{ Url = $t; Wild = $wild }
        }
        $urls = @($items)
        if (-not $urls.Count) { throw 'No valid URLs' }
        $results = @(Scan-Urls $items)
        $rep = Build-Html $rec $results $urls.Count
        $safeApp = ($rec.App -replace '[\\/:*?"<>|]', '') -replace '\s+', '_'
        $pdfFile = Join-Path $outDir "$($safeApp)_$($rec.CAN)_ThreatScanner.pdf"
        $saved = Save-Pdf $rep.Html $pdfFile
        $col = switch ($rep.Overall) { 'PASS' {'Green'} 'FAIL' {'Red'} default {'Yellow'} }
        Write-Host ("[{0}/{1}] CAN {2} | {3} | {4} URLs | {5}" -f $n, $total, $rec.CAN, $rec.App, $urls.Count, $rep.Overall) -ForegroundColor $col
        Log ("CAN {0} | {1} | urls={2} | {3} | pass={4} warn={5} fail={6} | {7}" -f $rec.CAN, $rec.App, $urls.Count, $rep.Overall, $rep.Pass, $rep.Warn, $rep.Fail, $saved)
        $summary.Add([PSCustomObject]@{ CAN_ID = $rec.CAN; App_Name = $rec.App; Request_ID = $rec.Req; URLs = $urls.Count
            Overall = $rep.Overall; Pass = $rep.Pass; Observations = $rep.Warn; Fail = $rep.Fail; NA_Wildcard = $rep.NA; Report = $saved })
    } catch {
        Write-Host "[$n/$total] CAN $($rec.CAN) ERROR: $($_.Exception.Message)" -ForegroundColor Red
        Log "ERROR CAN $($rec.CAN): $($_.Exception.Message)"
        $summary.Add([PSCustomObject]@{ CAN_ID = $rec.CAN; App_Name = $rec.App; Request_ID = $rec.Req; URLs = ''; Overall = 'ERROR'; Pass = ''; Observations = ''; Fail = ''; Report = $_.Exception.Message })
    }
}
$pool.Close(); $pool.Dispose()

$sumFile = Join-Path $outDir "ThreatScanner_Summary_$stamp.csv"
$summary | Export-Csv -Path $sumFile -NoTypeInformation -Encoding UTF8
Write-Host ''
Write-Host "Done. $($summary.Count) report(s) in: $outDir" -ForegroundColor Cyan
Write-Host "Summary : $sumFile"
Write-Host "Log     : $logFile"
if (-not $browser) { Write-Host 'Edge/Chrome not found - HTML reports were created instead of PDF (open and Print > Save as PDF).' -ForegroundColor Yellow }
