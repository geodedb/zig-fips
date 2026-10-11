# SPDX-License-Identifier: Apache-2.0
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/ci-native.ps1"
$shell = (Get-Process -Id $PID).Path
$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $tempDir | Out-Null
try {
    $child = Join-Path $tempDir 'child with spaces.ps1'
    [System.IO.File]::WriteAllText($child, @'
param([string] $Value, [int] $Code)
[Console]::Out.WriteLine('stdout:' + $Value)
[Console]::Error.WriteLine('stderr:' + $Value)
exit $Code
'@)
    $value = 'spaces and $dollars; literal'
    $lines = @(Invoke-CiNative -FilePath $shell -ArgumentList @('-NoProfile', '-File', $child, '-Value', $value, '-Code', '0'))
    if ($lines -notcontains "stdout:$value" -or $lines -notcontains "stderr:$value") {
        throw 'Native stdout/stderr or literal arguments were lost'
    }
    if ($ErrorActionPreference -ne 'Stop') { throw 'Error preference leaked after success' }
    $failed = $false
    try {
        Invoke-CiNative -FilePath $shell -ArgumentList @('-NoProfile', '-File', $child, '-Value', $value, '-Code', '7') | Out-Null
    }
    catch {
        if ($_.ToString() -notmatch 'exit code 7') { throw }
        $failed = $true
    }
    if (-not $failed) { throw 'Native nonzero exit was accepted' }
    if ($ErrorActionPreference -ne 'Stop') { throw 'Error preference leaked after failure' }
    $missingFailed = $false
    try { Invoke-CiNative -FilePath (Join-Path $tempDir 'missing-executable') | Out-Null }
    catch { $missingFailed = $true }
    if (-not $missingFailed) { throw 'Missing executable was accepted' }
    $savedPath = $env:PATH
    try {
        $first = Join-Path $tempDir 'first'
        $second = Join-Path $tempDir 'second'
        New-Item -ItemType Directory -Path $first, $second | Out-Null
        $windows = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
        $commandName = if ($windows) { 'ci-native-fixture.cmd' } else { 'ci-native-fixture.sh' }
        foreach ($entry in @(@($first, 'first'), @($second, 'second'))) {
            $commandPath = Join-Path $entry[0] $commandName
            $body = if ($windows) { "@echo off`r`necho $($entry[1])`r`n" } else { "#!/bin/sh`necho $($entry[1])`n" }
            [System.IO.File]::WriteAllText($commandPath, $body)
            if (-not $windows) { Invoke-CiNative chmod @('+x', $commandPath) | Out-Null }
        }
        $separator = [System.IO.Path]::PathSeparator
        $env:PATH = "$first$separator$second$separator$savedPath"
        $chosen = @(Invoke-CiNative $commandName)
        if ($chosen.Count -ne 1 -or $chosen[0] -ne 'first') {
            throw 'Multiple PATH matches did not select the first native executable'
        }
    }
    finally { $env:PATH = $savedPath }
    Write-Host 'PASS: native command selects the first of multiple PATH matches'
    Write-Host 'PASS: native stderr success, nonzero exit, literal arguments, missing executable, preference restoration'
}
finally {
    Remove-Item -LiteralPath $tempDir -Recurse -Force
}
