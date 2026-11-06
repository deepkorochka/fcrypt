param(
    [switch]$Dynamic
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = $PSScriptRoot
$SourceDir = Join-Path $ProjectRoot 'src'
$DistDir = Join-Path $ProjectRoot 'dist'
$TempExe = Join-Path $DistDir ('.fcrypt-build-' + $PID + '.exe')

$CompilerCommand = Get-Command 'g++.exe' -ErrorAction SilentlyContinue
if (-not $CompilerCommand) {
    throw 'g++ не найден. Установите MSYS2 UCRT64 и компоненты mingw-w64-ucrt-x86_64-gcc + mingw-w64-ucrt-x86_64-openssl.'
}
$Compiler = $CompilerCommand.Source

$Sources = @(Get-ChildItem -LiteralPath $SourceDir -Filter '*.cpp' | ForEach-Object { $_.FullName })
if ($Sources.Count -eq 0) {
    throw "В каталоге $SourceDir не найдены исходные файлы."
}

New-Item -ItemType Directory -Path $DistDir -Force | Out-Null

$Flags = @(
    '-std=c++17',
    '-O2',
    '-s',
    '-Wall',
    '-Wextra',
    '-Wpedantic',
    '-Wshadow',
    '-Wformat=2',
    '-D_WIN32_WINNT=0x0601',
    '-municode',
    '-static-libgcc',
    '-static-libstdc++'
)

if (-not $Dynamic) {
    $Flags += @('-static')
}

$Libraries = @(
    '-lcrypto',
    '-lbcrypt',
    '-lws2_32',
    '-lcrypt32',
    '-luser32',
    '-ladvapi32'
)

Write-Host "Компилятор: $Compiler"
Write-Host ("Режим: " + $(if ($Dynamic) { 'динамическая libcrypto' } else { 'полностью статическая сборка' }))

try {
    & $Compiler @Flags @Sources '-o' $TempExe @Libraries
    if ($LASTEXITCODE -ne 0) {
        throw "Компиляция завершилась с кодом $LASTEXITCODE."
    }

    $FinalExe = Join-Path $DistDir 'fcrypt.exe'
    Move-Item -LiteralPath $TempExe -Destination $FinalExe -Force

    if ($Dynamic) {
        $ToolchainBin = Split-Path -Parent $Compiler
        $OpenSslDll = Join-Path $ToolchainBin 'libcrypto-3-x64.dll'
        if (-not (Test-Path -LiteralPath $OpenSslDll)) {
            throw "Не найден $OpenSslDll. Для динамической сборки нужна libcrypto-3-x64.dll из MSYS2 UCRT64."
        }
        Copy-Item -LiteralPath $OpenSslDll -Destination $DistDir -Force
        Write-Host "Скопировано: $OpenSslDll"
    } else {
        $StaleDll = Join-Path $DistDir 'libcrypto-3-x64.dll'
        if (Test-Path -LiteralPath $StaleDll) {
            Remove-Item -LiteralPath $StaleDll -Force
        }
    }

    # Keep license notices next to binary distributions of statically linked OpenSSL.
    Copy-Item -LiteralPath (Join-Path $ProjectRoot 'README.md') -Destination $DistDir -Force
    Copy-Item -LiteralPath (Join-Path $ProjectRoot 'FORMAT.md') -Destination $DistDir -Force
    Copy-Item -LiteralPath (Join-Path $ProjectRoot 'LICENSE') -Destination $DistDir -Force
    Copy-Item -LiteralPath (Join-Path $ProjectRoot 'THIRD_PARTY_NOTICES.md') -Destination $DistDir -Force
    $LicenseDir = Join-Path $DistDir 'LICENSES'
    New-Item -ItemType Directory -Path $LicenseDir -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $ProjectRoot 'LICENSES\OpenSSL-LICENSE.txt') -Destination $LicenseDir -Force

    Write-Host ''
    Write-Host "Готово: $FinalExe" -ForegroundColor Green
    & $FinalExe --version
} finally {
    if (Test-Path -LiteralPath $TempExe) {
        Remove-Item -LiteralPath $TempExe -Force -ErrorAction SilentlyContinue
    }
}
