$ErrorActionPreference = 'Continue'

$ProjectRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Exe = Join-Path $ProjectRoot 'dist\fcrypt.exe'
$Password = 'Correct-Horse-Battery-Staple-42'
$FastKdf = @('--kdf-memory', '16', '--kdf-time', '2', '--kdf-lanes', '1')
$TestDir = Join-Path $env:TEMP ('fcrypt-tests-' + [Guid]::NewGuid().ToString('N'))
$Failures = 0
$Checks = 0

function Check {
    param(
        [bool]$Condition,
        [string]$Name,
        [string]$Details = ''
    )
    $script:Checks++
    if ($Condition) {
        Write-Host "PASS: $Name" -ForegroundColor Green
    } else {
        $script:Failures++
        Write-Host "FAIL: $Name" -ForegroundColor Red
        if ($Details) {
            Write-Host "      $Details" -ForegroundColor DarkRed
        }
    }
}

function Invoke-Fcrypt {
    param(
        [string[]]$Arguments,
        [string]$Password = $null
    )
    if ($null -ne $Password) {
        $output = $Password | & $Exe @Arguments 2>&1 | Out-String
    } else {
        $output = & $Exe @Arguments 2>&1 | Out-String
    }
    return [pscustomobject]@{
        Code = $LASTEXITCODE
        Output = $output
    }
}

function Encrypt-File {
    param(
        [string]$InputFile,
        [string]$OutputFile,
        [string]$Password,
        [string[]]$Extra = @()
    )
    $arguments = @('encrypt', $InputFile, '-o', $OutputFile, '--password-stdin') + $Extra
    return Invoke-Fcrypt -Arguments $arguments -Password $Password
}

function Decrypt-File {
    param(
        [string]$InputFile,
        [string]$OutputFile,
        [string]$Password,
        [string[]]$Extra = @()
    )
    $arguments = @('decrypt', $InputFile, '-o', $OutputFile, '--password-stdin') + $Extra
    return Invoke-Fcrypt -Arguments $arguments -Password $Password
}

function File-Hash {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

try {
    if (-not (Test-Path -LiteralPath $Exe)) {
        throw "Не найден $Exe. Сначала запустите build.ps1."
    }
    New-Item -ItemType Directory -Path $TestDir -Force | Out-Null

    $small = Join-Path $TestDir 'small.txt'
    $empty = Join-Path $TestDir 'empty.bin'
    $multi = Join-Path $TestDir 'multi.bin'
    $exact = Join-Path $TestDir 'exact.bin'
    $unicode = Join-Path $TestDir 'тест файл.txt'

    Set-Content -LiteralPath $small -Value 'Hello, fcrypt! Это тест.' -Encoding UTF8 -NoNewline
    New-Item -ItemType File -Path $empty | Out-Null
    Set-Content -LiteralPath $unicode -Value 'Юникодный путь и содержимое.' -Encoding UTF8 -NoNewline

    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $multiBytes = New-Object byte[] (3670016)
    $rng.GetBytes($multiBytes)
    [IO.File]::WriteAllBytes($multi, $multiBytes)
    $exactBytes = New-Object byte[] (2097152)
    $rng.GetBytes($exactBytes)
    [IO.File]::WriteAllBytes($exact, $exactBytes)

    # Basic round trips, including empty and exact chunk-boundary files.
    $roundTrips = @($small, $empty, $multi, $exact, $unicode)
    foreach ($file in $roundTrips) {
        $encrypted = "$file.fast.fcrypt"
        $decrypted = "$file.fast.out"
        $enc = Encrypt-File -InputFile $file -OutputFile $encrypted -Password $Password -Extra $FastKdf
        Check ($enc.Code -eq 0) "Шифрование $([IO.Path]::GetFileName($file))" $enc.Output
        Check (Test-Path -LiteralPath $file) "Исходный файл не удалён: $([IO.Path]::GetFileName($file))"

        $dec = Decrypt-File -InputFile $encrypted -OutputFile $decrypted -Password $Password
        Check ($dec.Code -eq 0) "Расшифровка $([IO.Path]::GetFileName($file))" $dec.Output
        if ($dec.Code -eq 0) {
            Check ((File-Hash $file) -eq (File-Hash $decrypted)) "SHA-256 совпадает: $([IO.Path]::GetFileName($file))"
        }
    }

    Check ((Get-Item -LiteralPath "$empty.fast.fcrypt").Length -eq 96) "Пустой файл: размер 96 байт"
    Check ((Get-Item -LiteralPath "$exact.fast.fcrypt").Length -eq 2097264) "Файл 2 МиБ: 2 блока + теги"
    Check ((Get-Item -LiteralPath "$multi.fast.fcrypt").Length -eq 3670160) "Файл 3,5 МиБ: 4 блока + теги"

    # Default KDF parameters.
    $defaultEnc = Encrypt-File -InputFile $small -OutputFile (Join-Path $TestDir 'default.fcrypt') -Password $Password
    $defaultDec = Decrypt-File -InputFile (Join-Path $TestDir 'default.fcrypt') -OutputFile (Join-Path $TestDir 'default.out') -Password $Password
    Check ($defaultEnc.Code -eq 0 -and $defaultDec.Code -eq 0) "Параметры Argon2id по умолчанию"
    Check ((File-Hash $small) -eq (File-Hash (Join-Path $TestDir 'default.out'))) "Расшифровка с параметрами по умолчанию"

    $uniqueA = Join-Path $TestDir 'unique-a.fcrypt'
    $uniqueB = Join-Path $TestDir 'unique-b.fcrypt'
    $uniqueEncA = Encrypt-File -InputFile $small -OutputFile $uniqueA -Password $Password -Extra $FastKdf
    $uniqueEncB = Encrypt-File -InputFile $small -OutputFile $uniqueB -Password $Password -Extra $FastKdf
    Check ($uniqueEncA.Code -eq 0 -and $uniqueEncB.Code -eq 0) "Двойное шифрование одного файла"
    if ((Test-Path -LiteralPath $uniqueA) -and (Test-Path -LiteralPath $uniqueB)) {
        Check ((File-Hash $uniqueA) -ne (File-Hash $uniqueB)) "Соль и шифротекст уникальны для каждого файла"
    }

    # Wrong password, with and without --force.
    $wrongOut = Join-Path $TestDir 'wrong.out'
    $wrong = Decrypt-File -InputFile (Join-Path $TestDir 'default.fcrypt') -OutputFile $wrongOut -Password 'Wrong-Password-123456'
    Check ($wrong.Code -eq 2) "Неверный пароль: код 2" $wrong.Output
    Check (-not (Test-Path -LiteralPath $wrongOut)) "Неверный пароль: выход не создан"

    $sentinel = Join-Path $TestDir 'sentinel.out'
    Set-Content -LiteralPath $sentinel -Value 'SENTINEL' -Encoding ASCII -NoNewline
    $wrongForce = Decrypt-File -InputFile (Join-Path $TestDir 'default.fcrypt') -OutputFile $sentinel -Password 'Wrong-Password-123456' -Extra @('--force')
    Check ($wrongForce.Code -eq 2) "Неверный пароль + --force: код 2" $wrongForce.Output
    Check ((Get-Content -LiteralPath $sentinel -Raw) -eq 'SENTINEL') "Неверный пароль + --force: старый файл не изменён"

    # Tampering must never produce plaintext.
    $original = [IO.File]::ReadAllBytes((Join-Path $TestDir 'multi.bin.fast.fcrypt'))
    $chunkBytes = 1048576 + 16

    $tamperedData = [byte[]]$original.Clone()
    $tamperedData[80 + 100] = $tamperedData[80 + 100] -bxor 0x01
    $tamperedDataPath = Join-Path $TestDir 'tampered-data.fcrypt'
    [IO.File]::WriteAllBytes($tamperedDataPath, $tamperedData)

    $tamperedSalt = [byte[]]$original.Clone()
    $tamperedSalt[42] = $tamperedSalt[42] -bxor 0x01
    $tamperedSaltPath = Join-Path $TestDir 'tampered-salt.fcrypt'
    [IO.File]::WriteAllBytes($tamperedSaltPath, $tamperedSalt)

    $tamperedSize = [byte[]]$original.Clone()
    $tamperedSize[39] = $tamperedSize[39] -bxor 0x01
    $tamperedSizePath = Join-Path $TestDir 'tampered-size.fcrypt'
    [IO.File]::WriteAllBytes($tamperedSizePath, $tamperedSize)

    $truncatedPath = Join-Path $TestDir 'truncated.fcrypt'
    [IO.File]::WriteAllBytes($truncatedPath, $original[0..($original.Length - 2)])

    $appendedPath = Join-Path $TestDir 'appended.fcrypt'
    [IO.File]::WriteAllBytes($appendedPath, [byte[]]($original + [byte]0x00))

    $swapped = [byte[]]$original.Clone()
    [Array]::Copy($original, 80, $swapped, 80 + $chunkBytes, $chunkBytes)
    [Array]::Copy($original, 80 + $chunkBytes, $swapped, 80, $chunkBytes)
    $swappedPath = Join-Path $TestDir 'swapped.fcrypt'
    [IO.File]::WriteAllBytes($swappedPath, $swapped)

    $tamperCases = @(
        @($tamperedDataPath, 2, 'изменённый шифротекст'),
        @($tamperedSaltPath, 2, 'изменённая соль'),
        @($tamperedSizePath, 1, 'изменённый размер'),
        @($truncatedPath, 1, 'усечённый файл'),
        @($appendedPath, 1, 'добавленные данные'),
        @($swappedPath, 2, 'переставленные блоки')
    )
    $index = 0
    foreach ($case in $tamperCases) {
        $index++
        $out = Join-Path $TestDir "tamper-$index.out"
        $result = Decrypt-File -InputFile $case[0] -OutputFile $out -Password $Password
        Check ($result.Code -eq $case[1]) "$($case[2]): код $($case[1])" $result.Output
        Check (-not (Test-Path -LiteralPath $out)) "$($case[2]): выход не создан"
    }

    # Output handling.
    $existing = Join-Path $TestDir 'existing.out'
    Set-Content -LiteralPath $existing -Value 'KEEP-ME' -Encoding ASCII -NoNewline
    $existingResult = Decrypt-File -InputFile (Join-Path $TestDir 'default.fcrypt') -OutputFile $existing -Password $Password
    Check ($existingResult.Code -eq 1) "Существующий выход без --force: ошибка" $existingResult.Output
    Check ((Get-Content -LiteralPath $existing -Raw) -eq 'KEEP-ME') "Существующий выход не изменён"
    $forceResult = Decrypt-File -InputFile (Join-Path $TestDir 'default.fcrypt') -OutputFile $existing -Password $Password -Extra @('--force')
    Check ($forceResult.Code -eq 0) "Существующий выход с --force: замена" $forceResult.Output
    Check ((File-Hash $small) -eq (File-Hash $existing)) "Файл после --force корректен"

    $smallHashBefore = File-Hash $small
    $sameFile = Encrypt-File -InputFile $small -OutputFile $small -Password $Password -Extra @('--force')
    Check ($sameFile.Code -eq 1) "Запрет вход = выход" $sameFile.Output
    Check ((File-Hash $small) -eq $smallHashBefore) "Входной файл не изменён"

    # Password policy.
    $shortInput = Join-Path $TestDir 'short.txt'
    Set-Content -LiteralPath $shortInput -Value 'short password' -Encoding ASCII -NoNewline
    $shortOut = Join-Path $TestDir 'short.fcrypt'
    $short = Encrypt-File -InputFile $shortInput -OutputFile $shortOut -Password 'short'
    Check ($short.Code -eq 1) "Короткий пароль отклонён" $short.Output
    Check (-not (Test-Path -LiteralPath $shortOut)) "Короткий пароль: выход не создан"
    $shortAllowed = Encrypt-File -InputFile $shortInput -OutputFile $shortOut -Password 'short' -Extra (@('--allow-weak-password') + $FastKdf)
    Check ($shortAllowed.Code -eq 0) "Короткий пароль с --allow-weak-password" $shortAllowed.Output
    $shortDec = Decrypt-File -InputFile $shortOut -OutputFile (Join-Path $TestDir 'short.out') -Password 'short'
    Check ($shortDec.Code -eq 0) "Расшифровка короткого пароля без флага"

    $emptyPass = Encrypt-File -InputFile $small -OutputFile (Join-Path $TestDir 'empty-pass.fcrypt') -Password ''
    Check ($emptyPass.Code -eq 1) "Пустой пароль отклонён" $emptyPass.Output
    Check (-not (Test-Path -LiteralPath (Join-Path $TestDir 'empty-pass.fcrypt'))) "Пустой пароль: выход не создан"

    # Default output name and KDF option validation.
    $autoPath = Join-Path $TestDir 'auto.fcrypt'
    Copy-Item -LiteralPath (Join-Path $TestDir 'default.fcrypt') -Destination $autoPath
    $auto = Invoke-Fcrypt -Arguments @('decrypt', $autoPath, '--password-stdin') -Password $Password
    Check ($auto.Code -eq 0) "Автоматическое имя выхода" $auto.Output
    Check (Test-Path -LiteralPath (Join-Path $TestDir 'auto')) "Создан файл без .fcrypt"
    if (Test-Path -LiteralPath (Join-Path $TestDir 'auto')) {
        Check ((File-Hash $small) -eq (File-Hash (Join-Path $TestDir 'auto'))) "Автоматический выход корректен"
    }

    $kdfOnDecrypt = Invoke-Fcrypt -Arguments @('decrypt', $autoPath, '-o', (Join-Path $TestDir 'x.out'), '--password-stdin', '--kdf-memory', '16') -Password $Password
    Check ($kdfOnDecrypt.Code -eq 1) "Параметры KDF запрещены при расшифровке" $kdfOnDecrypt.Output

    # Basic CLI.
    $help = Invoke-Fcrypt -Arguments @('--help')
    Check ($help.Code -eq 0 -and $help.Output.Contains('Использование')) "Справка --help"
    $version = Invoke-Fcrypt -Arguments @('--version')
    Check ($version.Code -eq 0 -and $version.Output.Contains('1.0.0')) "Версия --version"
    $unknown = Invoke-Fcrypt -Arguments @('unknown', $small)
    Check ($unknown.Code -eq 1) "Неизвестная команда отклонена"

    $tempFiles = @(Get-ChildItem -LiteralPath $TestDir -Recurse -Force -Filter '.fcrypt-*.tmp' -ErrorAction SilentlyContinue)
    Check ($tempFiles.Count -eq 0) "Временные файлы не остались"
}
catch {
    $script:Failures++
    Write-Host "FAIL: непредвиденное исключение" -ForegroundColor Red
    Write-Host $_.Exception.ToString() -ForegroundColor DarkRed
}
finally {
    if (Test-Path -LiteralPath $TestDir) {
        Remove-Item -LiteralPath $TestDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host ""
if ($Failures -eq 0) {
    Write-Host "Все проверки пройдены: $Checks" -ForegroundColor Green
    exit 0
} else {
    Write-Host "Провалено проверок: $Failures из $Checks" -ForegroundColor Red
    exit 1
}
