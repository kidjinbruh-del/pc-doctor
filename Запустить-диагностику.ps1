<#
    Диагност ПК — запускалка.

    Кладётся рядом с Diagnose-PC.ps1. Мастеру удобнее дважды кликнуть, чем
    набирать команду в консоли. Права администратора запрашиваются сами —
    без них не видны счётчики SMART и часть проверок.
#>
$ErrorActionPreference = 'Stop'
$script = Join-Path $PSScriptRoot 'Diagnose-PC.ps1'

if (-not (Test-Path $script)) {
    Write-Host "Не найден Diagnose-PC.ps1 рядом с этим файлом." -ForegroundColor Red
    Read-Host 'Нажмите Enter'
    exit 1
}

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host 'Запускаю с правами администратора — часть проверок без них недоступна.' -ForegroundColor Yellow
    try {
        Start-Process powershell -Verb RunAs -ArgumentList @(
            '-ExecutionPolicy', 'Bypass',
            '-NoProfile',
            '-NoExit',
            '-File', ('"{0}"' -f $script)
        )
        exit 0
    } catch {
        Write-Host 'Не удалось получить права администратора. Продолжаю без них.' -ForegroundColor Yellow
    }
}

& $script

Write-Host ''
Write-Host 'Готово. Отчёты лежат в папке Отчёт-ПК-* рядом с этим файлом.' -ForegroundColor Green
Read-Host 'Нажмите Enter, чтобы закрыть окно'