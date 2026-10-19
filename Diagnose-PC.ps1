<#
.SYNOPSIS
    Диагност ПК — разбор аварийных выключений и перезагрузок.

.DESCRIPTION
    Один файл, без установки и без зависимостей. Запускается мастером на клиентском
    компьютере и отвечает на главный вопрос: что к чему привело.

    Логика такая: система Windows не говорит «почему выключилось» — она пишет
    факты в журналы. Берём факты и связываем их. Например, Kernel-Power 41 с
    BugcheckCode = 0 означает, что BSOD не было вообще: питание пропало или был
    жёсткий сброс. Это совсем другой диагноз, чем 41 с кодом 0x124.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File Diagnose-PC.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File Diagnose-PC.ps1 -Days 60 -OutDir D:\Отчёт
#>
[CmdletBinding()]
param(
    # За сколько дней смотреть журналы. Если логов мало — берём все.
    [int]$Days = 30,
    # Куда положить отчёты. По умолчанию — рядом со скриптом, в папку Отчёт-<дата>.
    [string]$OutDir,
    # Не создавать HTML, только консоль и текст.
    [switch]$NoHtml
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# ---------------------------------------------------------------------------
# Каркас: находки, утилиты, сбор данных
# ---------------------------------------------------------------------------

$script:Findings = @()
$script:Chain    = @()
$script:Start    = Get-Date
$script:Admin    = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
                    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$sevIcon = @{ 'CRIT' = '[КРИТИЧНО]'; 'WARN' = '[ВНИМАНИЕ]'; 'OK' = '[норма]'; 'INFO' = '[инфо]' }

function Add-Finding {
    param(
        [ValidateSet('CRIT', 'WARN', 'OK', 'INFO')][string]$Severity,
        [string]$Area,
        [string]$Title,
        [string]$What,     # что именно найдено, с цифрами
        [string]$Why,      # почему это важно
        [string]$Action    # что делать мастеру
    )
    $script:Findings += [pscustomobject]@{
        Severity = $Severity; Area = $Area; Title = $Title
        What = $What; Why = $Why; Action = $Action
    }
}

function Add-Chain {
    param([string]$Symptom, [string]$Evidence, [string]$Cause, [string]$Check, [int]$Priority)
    $script:Chain += [pscustomobject]@{
        Symptom = $Symptom; Evidence = $Evidence; Cause = $Cause
        Check = $Check; Priority = $Priority
    }
}

function Section { param([string]$Text) Write-Host ""; Write-Host "── $Text " ('─' * [Math]::Max(0, 62 - $Text.Length)) -ForegroundColor Cyan }

function Write-Line { param($Text, $Color = 'Gray') Write-Host $Text -ForegroundColor $Color }

function Get-Since {
    param([int]$MaxDays)
    try { (Get-Date).AddDays(-$MaxDays) } catch { $null }
}

# Достаёт свойства события из XML: у Kernel-Power 41 поле Message пустое,
# код BSOD живёт только в EventData. Наивный парсер сообщения его не видит.
function Get-EventData {
    param($Event)
    $data = @{}
    try {
        [xml]$x = $Event.ToXml()
        foreach ($d in $x.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
    } catch { }
    return $data
}

# Коды BSOD, которые реально встречаются. Пустой список не мешает — но мастеру
# нужно знать, что означает число из журнала.
$Bugchecks = @(
    @{ Code = '0x0000000A'; Name = 'IRQL_NOT_LESS_OR_EQUAL';        What = 'Обычно виновата память или драйвер' }
    @{ Code = '0x0000001A'; Name = 'MEMORY_MANAGEMENT';             What = 'Повреждение памяти, чаще всего планки' }
    @{ Code = '0x0000001B'; Name = 'CONTROL_STACK_INIT_FAILURE';   What = 'Повреждение памяти' }
    @{ Code = '0x0000003B'; Name = 'SYSTEM_SERVICE_EXCEPTION';      What = 'Драйвер или память' }
    @{ Code = '0x0000007B'; Name = 'INACCESSIBLE_BOOT_DEVICE';      What = 'Диск или его контроллер, драйвер накопителя' }
    @{ Code = '0x0000007E'; Name = 'SYSTEM_THREAD_EXCEPTION';       What = 'Драйвер или нестабильная память' }
    @{ Code = '0x000000C2'; Name = 'BAD_POOL_CALLER';               What = 'Повреждение памяти или драйвер' }
    @{ Code = '0x000000D1'; Name = 'DRIVER_IRQL_NOT_LESS_OR_EQUAL'; What = 'Прямой виновник — драйвер' }
    @{ Code = '0x000000D0'; Name = 'DRIVER_CORRUPTED_EXPOOL';       What = 'Повреждение памяти или кривой драйвер' }
    @{ Code = '0x000000EF'; Name = 'CRITICAL_PROCESS_DIED';         What = 'Системный процесс, часто из-за диска' }
    @{ Code = '0x000000F4'; Name = 'CRITICAL_OBJECT_TERMINATION';   What = 'Часто указывает на железо или файл подкачки' }
    @{ Code = '0x000000FC'; Name = 'ATTEMPTED_EXEC_NOEXEC_MEMORY';  What = 'Повреждение памяти' }
    @{ Code = '0x00000101'; Name = 'CLOCK_WATCHDOG_TIMEOUT';        What = 'Процессор не отвечает: разгон или нестабильность' }
    @{ Code = '0x00000116'; Name = 'VIDEO_TDR_FAILURE';             What = 'Видеокарта: перегрев, разгон или брак' }
    @{ Code = '0x00000124'; Name = 'WHEA_UNCORRECTABLE_ERROR';      What = 'Железо: процессор, память или питание. Самая честная ошибка' }
    @{ Code = '0x00000139'; Name = 'KERNEL_SECURITY_CHECK_FAILURE'; What = 'Повреждение памяти или драйвер' }
    @{ Code = '0x000000BE'; Name = 'WRITE_TO_READONLY_MEMORY';      What = 'Повреждение памяти или драйвер' }
    @{ Code = '0x00000018'; Name = 'REFERENCE_BY_POINTER';          What = 'Повреждение памяти' }
    @{ Code = '0x00000133'; Name = 'DPC_WATCHDOG_VIOLATION';        What = 'Драйвер, реже — железо' }
)

function Get-BugcheckInfo {
    param([string]$Hex)
    if (-not $Hex) { return $null }
    $key = '0x' + ($Hex -replace '^0x', '').ToUpper().PadLeft(8, '0')
    return ($Bugchecks | Where-Object { $_.Code -eq $key }) | Select-Object -First 1
}

function Get-FirstLine {
    param($Text)
    if (-not $Text) { return '' }
    return (($Text -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -First 1).Trim()
}

function Format-Bytes {
    param([double]$Bytes)
    if ($Bytes -le 0) { return '0 Б' }
    foreach ($u in @('Б', 'КБ', 'МБ', 'ГБ', 'ТБ')) {
        if ($Bytes -lt 1024) { return ('{0:N1} {1}' -f $Bytes, $u) }
        $Bytes /= 1024
    }
    return ('{0:N1} ПБ' -f $Bytes)
}

# ---------------------------------------------------------------------------
# Сбор данных
# ---------------------------------------------------------------------------

$data = [ordered]@{}

Section 'Система'
$data.OS      = Get-CimInstance Win32_OperatingSystem 2>$null
$data.CPU     = @(Get-CimInstance Win32_Processor)
$data.Board   = Get-CimInstance Win32_BaseBoard 2>$null
$data.Bios    = Get-CimInstance Win32_BIOS 2>$null
$data.GPU     = @(Get-CimInstance Win32_VideoController)
$data.RAM     = @(Get-CimInstance Win32_PhysicalMemory)
$data.Computer= Get-CimInstance Win32_ComputerSystem 2>$null

$osName = if ($data.OS) { "$($data.OS.Caption) $($data.OS.Version)" } else { 'не определена' }
$cpuName = if ($data.CPU.Count) { $data.CPU[0].Name.Trim() } else { 'не определён' }
$ramGB = [math]::Round((($data.RAM | Measure-Object Capacity -Sum).Sum / 1GB), 1)
$boardTxt = if ($data.Board) { "$($data.Board.Manufacturer) $($data.Board.Product)" } else { '?' }
$biosTxt  = if ($data.Bios) { "$($data.Bios.SMBIOSBIOSVersion)" } else { '?' }

Write-Line "ОС        : $osName"
Write-Line "Процессор : $cpuName"
Write-Line "Плата     : $boardTxt"
Write-Line "BIOS      : $biosTxt  (от $(if ($data.Bios) { $data.Bios.ReleaseDate }) )"
Write-Line "Память    : $ramGB ГБ, планок $($data.RAM.Count)"
Write-Line "Видео     : $(($data.GPU | ForEach-Object { $_.Name }) -join ', ')"
Write-Line "Права     : $(if ($script:Admin) { 'Администратор — проверки железа доступны' } else { 'НЕ администратор — часть проверок недоступна' })"

$since = Get-Since $Days

# События собираем точечными запросами по провайдеру. Общий дамп System с
# -MaxEvents выдаёт новейшие N записей и молча теряет старые — на этом ПК так
# терялись 4 из 5 аварийных отключений.
function Get-Events {
    param([string]$Provider, [int[]]$Id)
    try {
        $h = @{ LogName = 'System'; ProviderName = $Provider; StartTime = $since }
        if ($Id) { $h['Id'] = $Id }
        @(Get-WinEvent -FilterHashtable $h -MaxEvents 500)
    } catch { @() }
}

$evKp41  = Get-Events 'Microsoft-Windows-Kernel-Power' @(41, 42, 86, 125)
$ev6008  = Get-Events 'EventLog' @(6008)
$evBsod  = Get-Events 'Microsoft-Windows-WER-SystemErrorReporting' @(1001)
$evThrot = Get-Events 'Microsoft-Windows-Kernel-Processor-Power' @(37)
$evWhea  = Get-Events 'Microsoft-Windows-WHEA-Logger' @()
$evDisk  = Get-Events 'disk' @(7, 11, 15, 51, 129, 153)
$evStor  = Get-Events 'storahci' @(129)
$evStorn = Get-Events 'stornvme' @(129)
$evNtfs  = Get-Events 'Microsoft-Windows-Ntfs' @(98, 55)
$evMemD  = Get-Events 'Microsoft-Windows-MemoryDiagnostics-Results' @(1201)

Write-Line ""
Write-Line "Журнал System за $Days дн. — собрано точечно по провайдерам (полный дамп обрезал бы старые записи)."

# ---------------------------------------------------------------------------
# 1. Аварийные выключения — главный блок по твоему кейсу
# ---------------------------------------------------------------------------

Section 'Питание и аварийные выключения'

$kp41 = @($evKp41 | Where-Object { $_.Id -eq 41 })
$ev6008 = $ev6008

$data.KernelPower = @()
foreach ($e in $kp41) {
    $d = Get-EventData $e
    $data.KernelPower += [pscustomobject]@{
        Time = $e.TimeCreated
        BugcheckCode = $d['BugcheckCode']
        PowerButton = $d['PowerButtonTimestamp']
        LongPress = $d['LongPowerButtonPressDetected']
        SleepInProgress = $d['SleepInProgress']
        WHEAErrors = $d['WHEABootErrorCount']
    }
}

# BSOD, если был: код ищется в тексте 1001 (WER-SystemErrorReporting)
$bsods = $evBsod
$data.Bsods = @()
foreach ($e in $bsods) {
    $txt = $e.Message
    $code = '0'
    if ($txt -match '(\d+)\s*\(0x[0-9a-fA-F]+\)') { $code = $Matches[1] }
    $drv = ''
    if ($txt -match '([\w\.]+\.sys)') { $drv = $Matches[1] }
    $data.Bsods += [pscustomobject]@{ Time = $e.TimeCreated; Code = $code; Driver = $drv }
}

$minidumps = @(Get-ChildItem 'C:\Windows\Minidump\*.dmp' 2>$null | Sort-Object LastWriteTime -Descending)
$memdump = Get-Item 'C:\Windows\MEMORY.DMP' 2>$null

Write-Line "Аварийных выключений (Kernel-Power 41): $($kp41.Count)"
Write-Line "Незапланированных завершений (EventLog 6008): $($ev6008.Count)"
Write-Line "Синих экранов (BSOD 1001): $($bsods.Count)"
Write-Line "Дампов в C:\Windows\Minidump: $($minidumps.Count)"
if ($memdump) { Write-Line "Полный дамп: $($memdump.FullName), $(Format-Bytes $memdump.Length), $(if ($memdump.LastWriteTime -gt $since) { 'СВЕЖИЙ — это главная улика' } else { 'старый' })" }

if ($kp41.Count -gt 0) {
    Write-Line ""
    Write-Line '  дата                 BSOD  признак'
    foreach ($k in ($data.KernelPower | Sort-Object Time -Descending | Select-Object -First 10)) {
        $hasBsod = if ($k.BugcheckCode -and $k.BugcheckCode -ne '0') { $k.BugcheckCode } else { 'нет' }
        $press = if ($k.LongPress -eq 'true' -or ($k.PowerButton -ne '0' -and $k.PowerButton)) { 'кнопка питания' } else { 'без кнопки' }
        $age = [math]::Round(((Get-Date) - $k.Time).TotalDays, 1)
        Write-Line ("  {0,-20} {1,-5} {2} ({3} дн. назад)" -f $k.Time.ToString('dd.MM.yyyy HH:mm'), $hasBsod, $press, $age)
    }
}

$hardShuts = @($data.KernelPower | Where-Object { $_.BugcheckCode -eq '0' -or [string]::IsNullOrEmpty($_.BugcheckCode) })
$softShuts = @($data.KernelPower | Where-Object { $_.BugcheckCode -and $_.BugcheckCode -ne '0' })

if ($hardShuts.Count -gt 0) {
    Add-Finding 'CRIT' 'Питание' 'Были жёсткие отключения без BSOD' `
        ("Событий Kernel-Power 41 с BugcheckCode=0: {0} (последнее {1})" -f $hardShuts.Count, ($hardShuts | Sort-Object Time -Descending | Select-Object -First 1).Time.ToString('dd.MM.yyyy HH:mm')) `
        'Питание пропало раньше, чем система успела записать код ошибки. Это не программный сбой. Так ведёт себя БП, просадка по 12 В под нагрузкой, плохой контакт, либо защита от перегрева' `
        'Проверить БП под нагрузкой, разъёмы и кабели, датчик температуры. Память — прогнать тест с XMP выключенным'
    # цепочку про питание добавляет блок корреляции: он учитывает время и потому
    # точнее. Здесь только находка, чтобы не было двух цепочек об одном и том же.
}
if ($softShuts.Count -gt 0) {
    $last = ($softShuts | Sort-Object Time -Descending)[0]
    $info = Get-BugcheckInfo $last.BugcheckCode
    Add-Finding 'CRIT' 'Питание' 'Были синие экраны (BSOD)' `
        ("{0} раз, последний код {1} {2}" -f $softShuts.Count, $last.BugcheckCode, $(if ($info) { $info.Name } else { '' })) `
        $(if ($info) { $info.What } else { 'Смотри код в таблице' }) `
        'Разобрать дамп и проверить указанную причину'
    Add-Chain 'Компьютер перезагружался сам' `
        ("BSOD с кодом {0} {1}" -f $last.BugcheckCode, $(if ($info) { $info.Name } else { '' })) `
        $(if ($info) { $info.What } else { 'Неизвестный код — разбирать дамп' }) `
        'Найти дамп, открыть в WinDbg или WhoCrashed' 2
}
if ($minidumps.Count -eq 0 -and $ps1:Dummy -ne $true -and $data.KernelPower.Count -eq 0 -and $ev6008.Count -eq 0) {
    Add-Finding 'OK' 'Питание' 'Аварийных отключений не найдено' 'За рассматриваемый период событий 41 и 6008 нет' 'Если клиент жалуется на выключения — уточнить период, проверить вручную'
}

# --- дамп памяти свежий? это лучшая улика
if ($memdump -and $memdump.LastWriteTime -gt $since) {
    Add-Finding 'CRIT' 'Питание' 'Свежий дамп BSOD — главная улика' `
        ("{0}, создан {1}" -f $memdump.FullName, $memdump.LastWriteTime.ToString('dd.MM.yyyy HH:mm')) `
        'В дампе видно точную причину синего экрана' `
        'Скопировать файл и разобрать: WinDbg или WhoCrashed'
    Add-Chain 'Компьютер выключался' 'C:\Windows\MEMORY.DMP создан недавно' 'BSOD с точным кодом внутри дампа' 'Разобрать дамп в WinDbg' 1
}

# ---------------------------------------------------------------------------
# 2. Перегрев и троттлинг
# ---------------------------------------------------------------------------

Section 'Температуры и перегрев'

# ВАЖНО: ID 37 и 55 встречаются у нескольких провайдеров (например, Time-Service).
# Фильтр только по провайдеру — иначе в перегрев попадёт синхронизация времени.
$throttle = $evThrot
$thermalCrit = @($evKp41 | Where-Object { $_.Id -in 86, 125 })

$temps = @()
try {
    $zones = @(Get-CimInstance -Namespace root\wmi -ClassName MSAcpi_ThermalZoneTemperature)
    foreach ($z in $zones) {
        $k = [double]$z.CurrentTemperature / 10 - 273.15
        $temps += [pscustomobject]@{ Source = "ACPI $($z.InstanceName)"; Temp = [math]::Round($k, 1) }
    }
} catch { }
if ($temps.Count -eq 0) {
    Write-Line 'Датчики температуры через WMI недоступны (обычная история для десктопов).'
    Write-Line 'Значения можно снять вручную: LibreHardwareMonitor, HWiNFO, или видеокарта — nvidia-smi.'
}

$gpuTemp = $null
$nvidia = @('C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe',
            'C:\Windows\System32\nvidia-smi.exe') | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($nvidia) {
    try {
        $out = & $nvidia --query-gpu=name,temperature.gpu --format=csv,noheader 2>$null
        foreach ($line in $out) {
            $p = $line -split ','
            $temps += [pscustomobject]@{ Source = $p[0].Trim(); Temp = [int]$p[1] }
            $gpuTemp = [int]$p[1]
        }
    } catch { }
}
if ($temps.Count) {
    Write-Line ""
    Write-Line '  источник                     температура'
    foreach ($t in $temps) {
        $flag = if ($t.Temp -ge 90) { '  ← ВЫШЕ НОРМЫ' } elseif ($t.Temp -ge 80) { '  ← жарко' } else { '' }
        Write-Line ("  {0,-28} {1,6} °C{2}" -f $t.Source, $t.Temp, $flag)
    }
}

if ($throttle.Count -gt 0) {
    Add-Finding 'CRIT' 'Температуры' 'Процессор уходил в троттлинг' `
        ("Событий Kernel-Processor-Power 37: {0}, последнее {1}" -f $throttle.Count, ($throttle | Sort-Object Time -Descending | Select-Object -First 1).Time.ToString('dd.MM.yyyy HH:mm')) `
        'Прошивка снижала частоты из-за нагрева или потому что система видела угрозу. Это защита, а не причина' `
        'Проверить охлаждение: термопаста, вентиляторы, радиатор, обдув корпуса. Замерить стресс-тестом'
    Add-Chain 'Компьютер выключался сам' `
        ("Перегрев зафиксирован {0} раз, ближайший к отключению — {1}" -f $throttle.Count, (($throttle | Sort-Object Time -Descending | Select-Object -First 1).Time.ToString('dd.MM.yyyy HH:mm'))) `
        'Перегрев: защита отключила систему' 'Проверить термопасту и вентиляторы, замерить под нагрузкой' 1
}
foreach ($t in $temps | Where-Object { $_.Temp -ge 90 }) {
    Add-Finding 'WARN' 'Температуры' 'Перегрев компонента' ("{0}: {1} °C" -f $t.Source, $t.Temp) 'Выше безопасного порога — ресурс падает, система может уходить в защиту' 'Обдув, замена термопасты'
}

# ---------------------------------------------------------------------------
# 3. Ошибки железа (WHEA)
# ---------------------------------------------------------------------------

Section 'Ошибки железа (WHEA)'

$whea = $evWhea
$data.Whea = @($whea | Select-Object -First 50 | ForEach-Object {
    [pscustomobject]@{ Time = $_.TimeCreated; Id = $_.Id; Text = (Get-FirstLine $_.Message) }
})
$wheaFatal = @($whea | Where-Object { $_.Id -in 18, 19, 20, 47 })
Write-Line "Событий WHEA: $($whea.Count) (из них критичных 18/19/20/47: $($wheaFatal.Count))"

if ($wheaFatal.Count -gt 0) {
    Add-Finding 'CRIT' 'Железо' 'WHEA: подтверждённая аппаратная ошибка' `
        ("{0} событий, последнее: {1}" -f $wheaFatal.Count, (Get-FirstLine ($wheaFatal | Sort-Object Time -Descending | Select-Object -First 1).Message)) `
        'Ошибка 18 — это процессор или оперативная память, и это не догадка, а сообщение самого железа' `
        'Прогнать MemTest86 или тест памяти Windows. Проверить планки по одной, разные слоты'
    Add-Chain 'Нестабильная работа' ("WHEA {0} событий — железо само сообщило об ошибке" -f $wheaFatal.Count) 'Процессор или оперативная память' 'MemTest86 4+ прохода, проверка планок по одной' 1
}
elseif ($whea.Count -eq 0) {
    Add-Finding 'OK' 'Железо' 'Аппаратных ошибок WHEA нет' 'Процессор и память не сообщали об ошибках' 'Это хорошо, но при нестабильности стоит проверить память тестом'
}

# ---------------------------------------------------------------------------
# 4. Диски и файловая система
# ---------------------------------------------------------------------------

Section 'Диски и файловая система'

$physDisks = @(Get-PhysicalDisk)
$disks = @(Get-Disk)
$data.Disks = @()

# Следы работы файловой системы. Ntfs 98 — диск помечен для проверки (не ошибка
# чтения). Реальные ошибки накопителя живут у провайдера disk: 51 (ошибка
# страничного обмена), 7, 11, 153 и у контроллера storAHCI/stornvme: 129.
$ntfs98 = @($evNtfs | Where-Object { $_.Id -eq 98 })
$diskErr = @($evDisk) + @($evStor) + @($evStorn)

foreach ($d in $physDisks) {
    $rel = $null
    try { $rel = $d | Get-StorageReliabilityCounter } catch { }
    $data.Disks += [pscustomobject]@{
        Name = $d.FriendlyName
        MediaType = $d.MediaType
        Health = $d.HealthStatus
        Operational = $d.OperationalStatus.ToString()
        Size = $d.Size
        Temperature = $(if ($rel) { $rel.Temperature } else { $null })
        PowerOnHours = $(if ($rel) { $rel.PowerOnHours } else { $null })
        Wear = $(if ($rel) { $rel.Wear } else { $null })
        ReadErrors = $(if ($rel) { $rel.ReadErrorsTotal } else { $null })
        Reallocated = $(if ($rel) { $rel.ReallocationSectorCount } else { $null })
    }
}

Write-Line '  диск                        тип      здоровье   температура  износ'
foreach ($d in $data.Disks) {
    $t = if ($d.Temperature) { "$($d.Temperature) °C" } else { 'н/д' }
    $w = if ($null -ne $d.Wear) { "$($d.Wear)%" } else { 'н/д' }
    Write-Line ("  {0,-26} {1,-8} {2,-10} {3,-12} {4}" -f $d.Name, $d.MediaType, $d.Health, $t, $w)
}
if ($script:Admin -eq $false) {
    Write-Line ''
    Write-Line '  Счётчики SMART доступны только с правами администратора. Перезапусти отчёт от админа.'
}
Write-Line "Событий Ntfs 98 (диск помечен для проверки): $($ntfs98.Count)"
# -MaxEvents в Get-Events ограничивает выборку 500. Если упираемся в потолок,
# честно пишем «не менее», иначе мастер посчитает не то.
$diskTxt = if ($diskErr.Count -ge 500) { "не менее 500 (выборка ограничена)" } else { "$($diskErr.Count)" }
Write-Line "Дисковых ошибок (disk/storAHCI): $diskTxt"
if ($diskErr.Count -ge 500) {
    Write-Line '  Выборка уперлась в потолок 500 событий — запусти с -Days 7 для точной картины.'
}

if ($ntfs98.Count -gt 0) {
    $t = ($ntfs98 | Sort-Object Time -Descending | Select-Object -First 1).Time
    Add-Finding 'WARN' 'Диски' 'Файловая система помечалась на проверку' `
        ("Событий Ntfs 98: {0}, последнее {1}" -f $ntfs98.Count, $t.ToString('dd.MM.yyyy HH:mm')) `
        'Windows решила проверить диск: обычно после сбоя питания или ошибки записи' `
        'Запустить chkdsk C: /f /r из командной строки с правами администратора'
    Add-Chain 'Нестабильная работа или выключения' ("Ntfs 98, последний {0}" -f $t.ToString('dd.MM.yyyy HH:mm')) 'Ошибки файловой системы на диске' 'chkdsk /f /r, проверить здоровье диска' 2
}
if ($diskErr.Count -gt 0) {
    $cnt = if ($diskErr.Count -ge 500) { 'не менее 500' } else { "$($diskErr.Count)" }
    Add-Finding 'CRIT' 'Диски' 'Ошибки диска или контроллера' `
        ("{0} событий: {1}" -f $cnt, (($diskErr | Select-Object -First 3 | ForEach-Object { "$($_.TimeCreated.ToString('dd.MM')) $($_.Id)" }) -join ', ')) `
        'Система теряла связь с накопителем при обмене страницами. Диск умирает или контакт с ним нестабилен' `
        'Сверить данные и заменить диск. Проверить, приходятся ли эти ошибки на те же моменты, что и отключения — блок «Связь событий по времени»'
    Add-Chain 'Нестабильная работа' ("Ошибок накопителя: $cnt, вне отключений — отдельный дефект") 'Накопитель или его контроллер' 'Проверить S.M.A.R.T., сделать образ данных' 2
}
foreach ($d in $data.Disks | Where-Object { $_.Health -and $_.Health -ne 'Healthy' }) {
    Add-Finding 'CRIT' 'Диски' 'Диск неhealthy' ("{0}: {1}" -f $d.Name, $d.Health) 'Windows считает накопитель неисправным' 'Срочно копировать данные и менять диск'
}
foreach ($d in $data.Disks | Where-Object { $_.Reallocated -and $_.Reallocated -gt 0 }) {
    Add-Finding 'WARN' 'Диски' 'Переназначенные сектора' ("{0}: {1}" -f $d.Name, $d.Reallocated) 'Диск переназначил битые сектора — процесс ускоряется' 'Следить, готовить замену'
}
if ($diskErr.Count -eq 0 -and $ntfs98.Count -eq 0) {
    Add-Finding 'OK' 'Диски' 'Ошибок накопителей не найдено' 'Журнал чист по дискам и файловой системе' 'Если компьютер выключается — причина в другом'
}

# ---------------------------------------------------------------------------
# 5. Оперативная память и разгон
# ---------------------------------------------------------------------------

Section 'Память и разгон'

$data.RamModules = $data.RAM | ForEach-Object {
    [pscustomobject]@{
        Bank = $_.BankLabel
        Slot = $_.DeviceLocator
        GB = [math]::Round($_.Capacity / 1GB)
        Speed = $_.Speed
        Configured = $_.ConfiguredClockSpeed
        PartNumber = $_.PartNumber
        Manufacturer = $_.Manufacturer
    }
}
foreach ($m in $data.RamModules) {
    $over = ''
    if ($m.Speed -and $m.Configured -and $m.Configured -gt $m.Speed) { $over = '  ← разогнано (XMP/EXPO)' }
    Write-Line ("  {0,-10} {1,-12} {2,3} ГБ  паспорт {3} МГц  работает {4} МГц{5}" -f $m.Bank, $m.Slot, $m.GB, $m.Speed, $m.Configured, $over)
}

$overclocked = @($data.RamModules | Where-Object { $_.Speed -and $_.Configured -and $_.Configured -gt $_.Speed })
if ($overclocked.Count -gt 0) {
    Add-Finding 'WARN' 'Память' 'Память работает быстрее паспортной' `
        ("Планок: {0} (например {1}: паспорт {2} МГц, работает {3} МГц)" -f $overclocked.Count, $overclocked[0].Bank, $overclocked[0].Speed, $overclocked[0].Configured) `
        'Включён XMP/EXPO или ручной разгон. Такая память часто нестабильна без явной ошибки в журнале — система просто зависает или выключается' `
        'В биосе снять разгон памяти и проверить. Если выключения прекратились — значит причина найдена'
    Add-Chain 'Компьютер выключался без BSOD' `
        ("Память разогнана: {0} МГц против паспортных {1}" -f $overclocked[0].Configured, $overclocked[0].Speed) `
        'Нестабильность разогнанной памяти — проявляется именно жёстким отключением, без кода ошибки' `
        'Снять XMP/EXPO в биосе, повторить тест' 1
}

$memDiag = $evMemD
if ($memDiag.Count -gt 0) {
    $last = $memDiag | Sort-Object Time -Descending | Select-Object -First 1
    $bad = $last.Message -match 'нет ошибок|No errors|Hardware problems detected' -eq $false
    Add-Finding $(if ($bad) { 'CRIT' } else { 'OK' }) 'Память' 'Тест памяти Windows' `
        (Get-FirstLine $last.Message) 'Аппаратный тест памяти' 'Если ошибок нет — память, скорее всего, не виновата'
} else {
    Write-Line 'Тест памяти Windows не запускался (нет результатов в журнале). Стоит прогнать.'
    Add-Finding 'INFO' 'Память' 'Тест памяти не выполнялся' 'В журнале нет результатов Windows Memory Diagnostic' 'Запустить mdsched.exe и дождаться результата — это стоит ночи'
}

# ---------------------------------------------------------------------------
# 6. Устройства и драйверы
# ---------------------------------------------------------------------------

Section 'Устройства и драйверы'

$problem = @(Get-CimInstance Win32_PnPEntity 2>$null | Where-Object { $_.ConfigManagerErrorCode -ne 0 })
$data.ProblemDevices = $problem
Write-Line "Устройств с ошибками: $($problem.Count)"
foreach ($p in ($problem | Select-Object -First 8)) {
    Write-Line ("  {0,-46} код {1}" -f $p.Name, $p.ConfigManagerErrorCode)
}

$codeNames = @{ 3 = 'драйвер не запускается'; 10 = 'устройство не запустится'; 28 = 'драйвер не установлен'; 43 = 'Windows отключил устройство' }
if ($problem.Count -gt 0) {
    Add-Finding 'WARN' 'Железо' 'Есть устройства с ошибками' `
        ("Устройств с ошибками: {0}" -f $problem.Count) `
        'Устройство без драйвера или с конфликтом' `
        'Для выключений обычно не причина, но показывает общую изношенность системы'
}
if ($data.Bsods.Count -gt 0) {
    $drv = ($data.Bsods | Where-Object { $_.Driver } | Select-Object -First 1).Driver
    if ($drv) {
        Add-Finding 'WARN' 'Драйверы' 'BSOD указывает на драйвер' ("Виновник: {0}" -f $drv) 'Драйвер уронил систему' 'Обновить или откатить драйвер'
        Add-Chain 'Компьютер перезагружался сам' ("BSOD указывает на драйвер {0}" -f $drv) 'Драйвер устройства' "Обновить/откатить {0}, убрать из автозагрузки" 2
    }
}

# ---------------------------------------------------------------------------
# 7. Прочие факторы
# ---------------------------------------------------------------------------

Section 'Прочее'

$hiber = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 42 } -MaxEvents 50)
$sleepErr = @($data.KernelPower | Where-Object { $_.SleepInProgress -eq '1' })
if ($sleepErr.Count -gt 0) {
    Add-Finding 'WARN' 'Питание' 'Выключение во время сна/гибернации' ("Событий: {0}" -f $sleepErr.Count) 'Проблема в управлении питанием или в пробуждении' 'Проверить настройки сна и быстрого запуска, драйверы чипсета'
    Add-Chain 'Выключения' 'Отключение зафиксировано во время сна' 'Проблема пробуждения из сна' 'Обновить драйверы чипсета, отключить быстрый запуск' 3
}

$updFail = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WindowsUpdateClient'; Id = 20 } -MaxEvents 20)
if ($updFail.Count -gt 0) {
    Write-Line "Ошибок обновления Windows: $($updFail.Count) (обычно не связано с выключениями)"
}

$pendingReboot = $false
try {
    $pendingReboot = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    if (-not $pendingReboot) { $pendingReboot = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' }
} catch { }
if ($pendingReboot) {
    Write-Line 'Требуется перезагрузка для установки обновлений.'
}

# ---------------------------------------------------------------------------
# Итог: цепочки «что к чему»
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Временная корреляция — главное «что к чему»
# ---------------------------------------------------------------------------

Section 'Связь событий по времени'

# Каждому отключению ищем предшественников в окне ПЕРЕД ним. События после
# отключения — это следствие (так ведёт себя Ntfs 98: Windows ставит проверку
# диска при следующей загрузке после жёсткого сброса), причиной их назвать нельзя.
$windowHours = 6
$correlations = @()

function Find-Antecedents {
    param([datetime]$Time, $Candidates, [string]$Label)
    if (-not $Candidates -or $Candidates.Count -eq 0) { return $null }
    # только то, что произошло ДО отключения
    $near = @($Candidates | Where-Object {
        $h = ($_.TimeCreated - $Time).TotalHours
        $h -lt 0 -and [math]::Abs($h) -le $windowHours
    })
    if ($near.Count -eq 0) { return $null }
    $closest = ($near | Sort-Object { [math]::Abs(($_ - $Time).TotalHours) })[0]
    return [pscustomobject]@{
        Label = $Label; Count = $near.Count
        OffsetHours = [math]::Round((($closest.TimeCreated - $Time).TotalHours), 2)
        Time = $closest.TimeCreated
    }
}

# Последствия считаем вместе с предшественниками (метки для отчёта).
$antecedentSets = @(
    @{ Label = 'Ошибки накопителя (disk/storAHCI)'; Events = $diskErr },
    @{ Label = 'Перегрев / троттлинг'; Events = $throttle },
    @{ Label = 'Аппаратные ошибки WHEA'; Events = $whea },
    @{ Label = 'Синий экран'; Events = $evBsod }
)

foreach ($k in ($data.KernelPower | Sort-Object Time -Descending)) {
    $found = @()
    foreach ($set in $antecedentSets) {
        $hit = Find-Antecedents -Time $k.Time -Candidates $set.Events -Label $set.Label
        if ($hit) { $found += $hit }
    }
    # следствие: проверка диска в первые минуты после жёсткого отключения
    $afterNtfs = @($ntfs98 | Where-Object {
        $h = ($_.TimeCreated - $k.Time).TotalHours
        $h -gt 0 -and $h -le 2
    }).Count
    $correlations += [pscustomobject]@{
        Shutdown = $k.Time; Antecedents = $found; AfterNtfs = $afterNtfs
    }
}

if ($correlations.Count -eq 0) {
    Write-Line 'Отключений в журнале нет — сравнивать нечего.'
} else {
    Write-Line "Окно связи: до отключения, ±$windowHours ч."
    Write-Line ''
    foreach ($c in $correlations) {
        if ($c.Antecedents.Count -eq 0) {
            $tail = if ($c.AfterNtfs -gt 0) { "  (после: Ntfs 98 ×$($c.AfterNtfs) — следствие жёсткого сброса)" } else { '' }
            Write-Line ("  {0}  — событий-причин перед отключением нет{1}" -f $c.Shutdown.ToString('dd.MM.yyyy HH:mm'), $tail) -ForegroundColor DarkGray
        } else {
            Write-Host ("  " + $c.Shutdown.ToString('dd.MM.yyyy HH:mm') + "  — есть связь:") -ForegroundColor Yellow
            foreach ($a in $c.Antecedents) {
                Write-Line ("      {0,-42} {1,5} шт., ближайшая {2} ч ДО отключения" -f $a.Label, $a.Count, [math]::Abs($a.OffsetHours))
            }
        }
    }
}

# Есть ли хоть одно отключение с причиной перед ним?
$linked = @($correlations | Where-Object { $_.Antecedents.Count -gt 0 })
$unlinked = @($correlations | Where-Object { $_.Antecedents.Count -eq 0 })
$withAfter = @($correlations | Where-Object { $_.AfterNtfs -gt 0 })

if ($linked.Count -gt 0) {
    $labels = ($linked | ForEach-Object { $_.Antecedents } | ForEach-Object { $_.Label } | Sort-Object -Unique) -join ', '
    Add-Chain 'Компьютер выключался сам' `
        ("{0} из {1} отключений идут после: {2}" -f $linked.Count, $correlations.Count, $labels) `
        'Причина видна в журнале перед отключением — это связь, а не совпадение' `
        'Разобрать цепочку из блока «Связь событий по времени» и проверить указанное звено' 1
}
elseif ($unlinked.Count -gt 0) {
    $afterTxt = if ($withAfter.Count -gt 0) {
        " Windows ставила проверку диска сразу после {0} из {1} отключений." -f $withAfter.Count, $unlinked.Count
    } else { '' }
    Add-Finding 'CRIT' 'Питание' 'Отключения без единой записи об ошибке' `
        ("Ни одно из {0} отключений не сопровождается ошибками в журнале за {1} ч до.{2}" -f $unlinked.Count, $windowHours, $afterTxt) `
        'Система не успела ничего записать перед отключением. Значит отключилось не ПО, а питание: пропало напряжение, сработала защита БП или отключилась термозащита. Проверка диска в Ntfs 98 после сброса — следствие, а не причина' `
        'Проверять физику: БП под нагрузкой, разъёмы, кабели, вентиляторы. Логи тут не помогут'
    Add-Chain 'Компьютер выключался сам' `
        ("{0} отключений с BugcheckCode=0, и ни одного сообщения об ошибке перед ними — журнал пуст.{1}" -f $unlinked.Count, $afterTxt) `
        'Электропитание: отключение произошло раньше, чем система успела что-то записать' `
        '1) БП под нагрузкой  2) Просадка 12 В  3) Разъёмы и кабели  4) Защита от перегрева  5) Снять разгон памяти' 1
}
$crits = @($script:Findings | Where-Object { $_.Severity -eq 'CRIT' })
$warns = @($script:Findings | Where-Object { $_.Severity -eq 'WARN' })

Section 'ИТОГ: что к чему'
$chains = @($script:Chain | Sort-Object Priority)
$crits = @($script:Findings | Where-Object { $_.Severity -eq 'CRIT' })
$warns = @($script:Findings | Where-Object { $_.Severity -eq 'WARN' })

if ($chains.Count -eq 0) {
    Write-Host ''
    Write-Host 'Критичных цепочек не найдено. Деталей — в блоке НАХОДКИ ниже.' -ForegroundColor Green
} else {
    $n = 1
    foreach ($c in $chains) {
        Write-Line ''
        Write-Line "[$n] $($c.Symptom)" -ForegroundColor Yellow
        Write-Line "    Улика:     $($c.Evidence)"
        Write-Line "    Причина:   $($c.Cause)" -ForegroundColor Yellow
        Write-Line "    Проверить: $($c.Check)"
        $n++
    }
}

Write-Line ''
Write-Host ('Критичных находок: {0}   Предупреждений: {1}   Всего: {2}' -f $crits.Count, $warns.Count, $script:Findings.Count) -ForegroundColor DarkGray

# ---------------------------------------------------------------------------
# Отчёты
# ---------------------------------------------------------------------------

if (-not $OutDir) { $OutDir = Join-Path $PSScriptRoot ("Отчёт-ПК-" + (Get-Date -Format 'yyyy-MM-dd_HHmm')) }
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

$fileTxt  = Join-Path $OutDir 'Диагностика-текст.txt'
$fileHtml = Join-Path $OutDir 'Диагностика-отчёт.html'
$fileJson = Join-Path $OutDir 'Диагностика-данные.json'

# --- текстовый отчёт
$sb = New-Object System.Text.StringBuilder
function L { param([string]$s = '') [void]$sb.AppendLine($s) }
function AddToText { param([string]$s = '') [void]$sb.AppendLine($s) }

L "ДИАГНОСТИКА ПК"
L ("Собрано: " + (Get-Date -Format 'dd.MM.yyyy HH:mm:ss'))
L ("Компьютер: " + $env:COMPUTERNAME + "   Пользователь: " + $env:USERNAME)
L ("Права: " + $(if ($script:Admin) { 'Администратор' } else { 'обычные (часть проверок недоступна)' }))
L ""
L "СИСТЕМА"
L ("  ОС: " + $osName)
L ("  Процессор: " + $cpuName)
L ("  Плата: " + $boardTxt)
L ("  BIOS: " + $biosTxt)
L ("  Память: $ramGB ГБ")
L ("  Видео: " + (($data.GPU | ForEach-Object { $_.Name }) -join ', '))
L ""
L "СОБЫТИЯ ВЫКЛЮЧЕНИЯ"
L ("  Kernel-Power 41 (аварийное): " + $kp41.Count)
L ("  EventLog 6008 (незапланированное завершение): " + $ev6008.Count)
L ("  BSOD (1001): " + $bsods.Count)
L ("  Дампов: " + $minidumps.Count + $(if ($memdump) { " (+ " + $memdump.FullName + ")" } else { '' }))
foreach ($k in ($data.KernelPower | Sort-Object Time -Descending)) {
    L ("    " + $k.Time.ToString('dd.MM.yyyy HH:mm:ss') + "  BSOD=" + $k.BugcheckCode + "  кнопка=" + $k.LongPress)
}
L ""
L "ТЕМПЕРАТУРЫ"
if ($temps.Count) { foreach ($t in $temps) { L ("  " + $t.Source + ": " + $t.Temp + " °C") } } else { L "  Датчики через WMI недоступны, измеряйте HWiNFO/LibreHardwareMonitor" }
L ""
L "ДИСКИ"
foreach ($d in $data.Disks) {
    L ("  " + $d.Name + " | " + $d.MediaType + " | " + $d.Health + " | " + $(if ($d.Temperature) { $d.Temperature.ToString() + " °C" } else { 'темп. н/д' }) + " | " + $(if ($null -ne $d.Wear) { "износ " + $d.Wear + "%" } else { 'износ н/д' }))
}
L ("  Ntfs 98 (помечен для проверки): " + $ntfs98.Count + "   прочих дисковых ошибок: " + $diskErr.Count)
L ""
L "ПАМЯТЬ"
foreach ($m in $data.RamModules) {
    L ("  " + $m.Bank + " " + $m.Slot + ": " + $m.GB + " ГБ, паспорт " + $m.Speed + " МГц, работает " + $m.Configured + " МГц")
}
L ""
L "ЖЕЛЕЗО И ДРАЙВЕРЫ"
L ("  WHEA: " + $whea.Count + "   Устройств с ошибками: " + $problem.Count)
foreach ($p in $problem) { L ("    " + $p.Name + " — код " + $p.ConfigManagerErrorCode) }
L ""
L "СВЯЗЬ СОБЫТИЙ ПО ВРЕМЕНИ (учитываем только события ДО отключения, окно ±$windowHours ч)"
if ($correlations.Count -eq 0) {
    L "  Отключений нет."
} else {
    foreach ($c in $correlations) {
        if ($c.Antecedents.Count -eq 0) {
            $tail = if ($c.AfterNtfs -gt 0) { "; после сброса Ntfs 98 ×$($c.AfterNtfs) — следствие" } else { '' }
            L ("  " + $c.Shutdown.ToString('dd.MM.yyyy HH:mm') + " — событий-причин перед отключением нет" + $tail)
        } else {
            L ("  " + $c.Shutdown.ToString('dd.MM.yyyy HH:mm') + " — есть связь:")
            foreach ($a in $c.Antecedents) {
                L ("      " + $a.Label + ": " + $a.Count + " шт., ближайшая " + [math]::Abs($a.OffsetHours) + " ч ДО отключения")
            }
        }
    }
}
L ""
L "ЧТО К ЧЕМУ"
if ($chains.Count -eq 0) {
    L "  Критичных цепочек не найдено."
} else {
    $i = 1
    foreach ($c in $chains) {
        L ("  [$i] " + $c.Symptom)
        L ("      Улика: " + $c.Evidence)
        L ("      Причина: " + $c.Cause)
        L ("      Проверить: " + $c.Check)
        $i++
    }
}
L ""
L "НАХОДКИ"
foreach ($f in $script:Findings) {
    L ("  " + $sevIcon[$f.Severity] + " [" + $f.Area + "] " + $f.Title)
    L ("      Что:  " + $f.What)
    if ($f.Why)     { L ("      Почему: " + $f.Why) }
    if ($f.Action)  { L ("      Что делать: " + $f.Action) }
    L ""
}
$utf8 = New-Object System.Text.UTF8Encoding($true)
[System.IO.File]::WriteAllText($fileTxt, $sb.ToString(), $utf8)

# --- машинный отчёт
# ConvertTo-Json в PowerShell 5.1 не умеет OrderedDictionary, а pscustomobject
# требует целый хеш на входе. Поэтому собираем обычный хеш и оборачиваем.
$fields = [ordered]@{}
$fields['computer']     = $env:COMPUTERNAME
$fields['collectedAt']  = (Get-Date).ToString('o')
$fields['admin']        = $script:Admin
$fields['system']       = [pscustomobject]@{
    os = $osName; cpu = $cpuName; board = $boardTxt; bios = $biosTxt
    ramGb = $ramGB; gpu = @($data.GPU | ForEach-Object { $_.Name })
}
$fields['shutdowns']    = [pscustomobject]@{
    kernelPower41 = $kp41.Count
    eventLog6008  = $ev6008.Count
    bsod          = $bsods.Count
    minidumps     = $minidumps.Count
    events        = @($data.KernelPower)
}
$fields['bsodDetails']  = @($data.Bsods)
$fields['thermal']      = [pscustomobject]@{ throttling = $throttle.Count; sensors = @($temps) }
$fields['whea']         = [pscustomobject]@{
    total = $whea.Count; fatal = $wheaFatal.Count; events = @($data.Whea)
}
$fields['disks']        = @($data.Disks)
$fields['memory']       = @($data.RamModules)
$fields['problemDevices'] = @($data.ProblemDevices | ForEach-Object {
    [pscustomobject]@{ name = $_.Name; code = $_.ConfigManagerErrorCode } })
$fields['correlations'] = @($correlations | ForEach-Object {
    [pscustomobject]@{
        shutdown = $_.Shutdown; afterNtfs = $_.AfterNtfs; antecedents = @($_.Antecedents)
    } })
$fields['chains']       = @($chains)
$fields['findings']     = @($script:Findings)

$export = [pscustomobject]$fields
try {
    $jsonText = $export | ConvertTo-Json -Depth 8
    if (-not $jsonText) { throw 'ConvertTo-Json вернул пусто' }
    [System.IO.File]::WriteAllText($fileJson, $jsonText, $utf8)
} catch {
    Write-Host "ОШИБКА ЗАПИСИ JSON: $($_.Exception.Message)" -ForegroundColor Red
}

# --- HTML-отчёт
if (-not $NoHtml) {
    $esc = { param($t) if ($null -eq $t) { '' } else { [System.Net.WebUtility]::HtmlEncode([string]$t) } }
    $color = @{ 'CRIT' = '#b3261e'; 'WARN' = '#b26a00'; 'OK' = '#1a7f37'; 'INFO' = '#5f6368' }
    $hb = New-Object System.Text.StringBuilder
    function Add-Html { param([string]$s) [void]$hb.AppendLine($s) }

    # Короткий H вызывается ниже (876, 881, 882, 903), но нигде не был
    # определён: из-за $ErrorActionPreference = 'SilentlyContinue' вызовы
    # падали молча, и в HTML-отчёт не попадали «Замечаний нет»,
    # «Почему важно», «Что делать» и таблица температур.
    function H { param([string]$s) Add-Html $s }

    Add-Html '<!DOCTYPE html><html lang="ru"><head><meta charset="utf-8">'
    Add-Html '<meta name="viewport" content="width=device-width, initial-scale=1">'
    Add-Html '<title>Диагностика ПК — ' + ($env:COMPUTERNAME) + '</title>'
    Add-Html '<style>'
    Add-Html 'body{font:15px/1.55 -apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:0;padding:28px;background:#f6f7f9;color:#1c1e21;max-width:1080px}'
    Add-Html 'h1{font-size:24px;margin:0 0 4px}h2{font-size:19px;margin:28px 0 10px;padding-bottom:6px;border-bottom:1px solid #d8dbdf}'
    Add-Html '.sub{color:#6b7076;font-size:13px;margin-bottom:20px}'
    Add-Html '.chain{background:#fff;border:1px solid #e2e5e9;border-left:4px solid #b26a00;border-radius:8px;padding:14px 16px;margin:10px 0}'
    Add-Html '.chain.crit{border-left-color:#b3261e}.chain.ok{border-left-color:#1a7f37}'
    Add-Html '.f{background:#fff;border:1px solid #e2e5e9;border-radius:8px;padding:13px 16px;margin:9px 0}'
    Add-Html '.tag{font-weight:700;font-size:12px;letter-spacing:.3px;padding:2px 7px;border-radius:4px;color:#fff;margin-right:8px}'
    Add-Html 'table{border-collapse:collapse;width:100%;background:#fff;border:1px solid #e2e5e9;border-radius:8px;overflow:hidden;font-size:14px}'
    Add-Html 'th,td{padding:8px 11px;text-align:left;border-bottom:1px solid #eceef1}th{background:#eef0f3;font-weight:600;font-size:13px}'
    Add-Html 'tr:last-child td{border-bottom:none}'
    Add-Html 'code{background:#eceef1;padding:1px 5px;border-radius:3px;font-size:13px}'
    Add-Html '.lbl{color:#6b7076;font-size:12px;text-transform:uppercase;letter-spacing:.4px;margin-top:9px}'
    Add-Html '</style></head><body>'

    Add-Html ('<h1>Диагностика ПК</h1>')
    Add-Html ('<div class="sub">' + (& $esc $env:COMPUTERNAME) + ' · собрано ' + (& $esc (Get-Date -Format 'dd.MM.yyyy HH:mm')) + ' · ' + (& $esc $(if ($script:Admin) { 'права администратора' } else { 'без прав администратора' })) + '</div>')

    Add-Html '<h2>Связь событий по времени</h2>'
    if ($correlations.Count -eq 0) {
        Add-Html '<div class="chain ok">Отключений в журнале нет.</div>'
    } else {
Add-Html ('<p class="sub">Учитываются только события ДО отключения, окно ±' + $windowHours + ' ч. Ntfs 98 после сброса — следствие жёсткого отключения, а не причина.</p>')
    Add-Html '<table><tr><th>Отключение</th><th>Что было перед ним</th></tr>'
    foreach ($c in $correlations) {
        if ($c.Antecedents.Count -eq 0) {
            $tail = if ($c.AfterNtfs -gt 0) { " · следствие: Ntfs 98 ×" + $c.AfterNtfs } else { '' }
            Add-Html ('<tr><td>' + (& $esc $c.Shutdown.ToString('dd.MM.yyyy HH:mm')) + '</td><td style="color:#6b7076">причин нет' + (& $esc $tail) + '</td></tr>')
        } else {
            $parts = @()
            foreach ($a in $c.Antecedents) {
                $parts += ($a.Label + ' — ' + $a.Count + ' шт., ближайшая ' + [math]::Abs($a.OffsetHours) + ' ч до')
            }
            Add-Html ('<tr><td>' + (& $esc $c.Shutdown.ToString('dd.MM.yyyy HH:mm')) + '</td><td>' + (& $esc ($parts -join '; ')) + '</td></tr>')
        }
    }
    Add-Html '</table>'
    }

    Add-Html '<h2>Что к чему</h2>'
    if ($chains.Count -eq 0) {
        Add-Html '<div class="chain ok">Критичных цепочек не найдено.</div>'
    } else {
        foreach ($c in $chains) {
            Add-Html ('<div class="chain crit"><b>' + (& $esc $c.Symptom) + '</b>')
            Add-Html ('<div class="lbl">Улика</div>' + (& $esc $c.Evidence))
            Add-Html ('<div class="lbl">Причина</div>' + (& $esc $c.Cause))
            Add-Html ('<div class="lbl">Что проверить</div>' + (& $esc $c.Check))
            Add-Html '</div>'
        }
    }

    Add-Html '<h2>Находки</h2>'
    if ($script:Findings.Count -eq 0) { H '<div class="chain ok">Замечаний нет.</div>' }
    foreach ($f in $script:Findings) {
        Add-Html '<div class="f">'
        Add-Html ('<span class="tag" style="background:' + $color[$f.Severity] + '">' + $sevIcon[$f.Severity] + '</span><b>' + (& $esc ("[" + $f.Area + "] " + $f.Title)) + '</b>')
        Add-Html ('<div class="lbl">Что</div>' + (& $esc $f.What))
        if ($f.Why) { H ('<div class="lbl">Почему важно</div>' + (& $esc $f.Why)) }
        if ($f.Action) { H ('<div class="lbl">Что делать</div>' + (& $esc $f.Action)) }
        Add-Html '</div>'
    }

    Add-Html '<h2>События выключения</h2><table><tr><th>Дата</th><th>BSOD</th><th>Кнопка питания</th></tr>'
    foreach ($k in ($data.KernelPower | Sort-Object Time -Descending)) {
        Add-Html ('<tr><td>' + (& $esc $k.Time.ToString('dd.MM.yyyy HH:mm:ss')) + '</td><td>' + (& $esc $k.BugcheckCode) + '</td><td>' + (& $esc $k.LongPress) + '</td></tr>')
    }
    Add-Html '</table>'

    Add-Html '<h2>Система</h2><table>'
    Add-Html ('<tr><th>ОС</th><td>' + (& $esc $osName) + '</td></tr>')
    Add-Html ('<tr><th>Процессор</th><td>' + (& $esc $cpuName) + '</td></tr>')
    Add-Html ('<tr><th>Плата</th><td>' + (& $esc $boardTxt) + '</td></tr>')
    Add-Html ('<tr><th>BIOS</th><td>' + (& $esc $biosTxt) + '</td></tr>')
    Add-Html ('<tr><th>Память</th><td>' + (& $esc "$ramGB ГБ, планок $($data.RAM.Count)") + '</td></tr>')
    Add-Html ('<tr><th>Видео</th><td>' + (& $esc (($data.GPU | ForEach-Object { $_.Name }) -join ', ')) + '</td></tr>')
    Add-Html '</table>'

    if ($temps.Count) {
        Add-Html '<h2>Температуры</h2><table><tr><th>Источник</th><th>Температура</th></tr>'
        foreach ($t in $temps) { H ('<tr><td>' + (& $esc $t.Source) + '</td><td>' + (& $esc $t.Temp) + ' °C</td></tr>') }
        Add-Html '</table>'
    }

    Add-Html '<h2>Диски</h2><table><tr><th>Диск</th><th>Тип</th><th>Здоровье</th><th>Температура</th><th>Износ</th></tr>'
    foreach ($d in $data.Disks) {
        Add-Html ('<tr><td>' + (& $esc $d.Name) + '</td><td>' + (& $esc $d.MediaType) + '</td><td>' + (& $esc $d.Health) + '</td><td>' + (& $esc $(if ($d.Temperature) { $d.Temperature.ToString() + ' °C' } else { 'н/д' })) + '</td><td>' + (& $esc $(if ($null -ne $d.Wear) { $d.Wear.ToString() + '%' } else { 'н/д' })) + '</td></tr>')
    }
    Add-Html '</table>'

    Add-Html '<h2>Память</h2><table><tr><th>Банк</th><th>Слот</th><th>Объём</th><th>Паспорт</th><th>Работает</th></tr>'
    foreach ($m in $data.RamModules) {
        Add-Html ('<tr><td>' + (& $esc $m.Bank) + '</td><td>' + (& $esc $m.Slot) + '</td><td>' + (& $esc "$($m.GB) ГБ") + '</td><td>' + (& $esc "$($m.Speed) МГц") + '</td><td>' + (& $esc "$($m.Configured) МГц") + '</td></tr>')
    }
    Add-Html '</table>'

    if ($problem.Count -gt 0) {
        Add-Html '<h2>Устройства с ошибками</h2><table><tr><th>Устройство</th><th>Код</th><th>Что значит</th></tr>'
        foreach ($p in $problem) {
            $code = $p.ConfigManagerErrorCode
            $mean = if ($codeNames.ContainsKey([int]$code)) { $codeNames[[int]$code] } else { '' }
            Add-Html ('<tr><td>' + (& $esc $p.Name) + '</td><td>' + (& $esc $code) + '</td><td>' + (& $esc $mean) + '</td></tr>')
        }
        Add-Html '</table>'
    }

    Add-Html '</body></html>'
try {
    [System.IO.File]::WriteAllText($fileHtml, $hb.ToString(), $utf8)
} catch {
    Write-Host "ОШИБКА ЗАПИСИ HTML: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
}
}

Write-Host ""
Write-Host "Отчёты сохранены: $OutDir" -ForegroundColor Green
Write-Host ("  Диагностика-отчёт.html" + $(if ($NoHtml) { " (пропущен)" } else { "" }))
Write-Host "  Диагностика-текст.txt"
Write-Host "  Диагностика-данные.json"
