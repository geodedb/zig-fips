# SPDX-License-Identifier: Apache-2.0
# Real Git history fixtures: no network or native-process mocks.
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/ci-vcpkg.ps1"
$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $tempDir | Out-Null

function Assert-Fails {
    param([scriptblock] $Action, [string] $Message)
    $failed = $false
    try { & $Action | Out-Null }
    catch { $failed = $true }
    if (-not $failed) { throw $Message }
}

try {
    $remote = Join-Path $tempDir 'remote with spaces'
    Invoke-CiNative git @('init', $remote) | Out-Null
    Invoke-CiNative git @('-C', $remote, 'config', 'user.name', 'Fixture') | Out-Null
    Invoke-CiNative git @('-C', $remote, 'config', 'user.email', 'fixture@example.invalid') | Out-Null
    Invoke-CiNative git @('-C', $remote, 'config', 'commit.gpgsign', 'false') | Out-Null
    $port = Join-Path $remote 'ports/openssl'
    New-Item -ItemType Directory -Path $port -Force | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $port 'portfile.txt'), 'old pinned port')
    Invoke-CiNative git @('-C', $remote, 'add', '.') | Out-Null
    Invoke-CiNative git @('-C', $remote, 'commit', '-m', 'historical port') | Out-Null
    $oldTree = @(Invoke-CiNative git @('-C', $remote, 'rev-parse', 'HEAD:ports/openssl'))[0]
    [System.IO.File]::WriteAllText((Join-Path $port 'portfile.txt'), 'new default port')
    [System.IO.File]::WriteAllText((Join-Path $remote 'versions.txt'), $oldTree)
    Invoke-CiNative git @('-C', $remote, 'add', '.') | Out-Null
    Invoke-CiNative git @('-C', $remote, 'commit', '-m', 'pinned registry baseline') | Out-Null
    $pin = @(Invoke-CiNative git @('-C', $remote, 'rev-parse', 'HEAD'))[0]
    [System.IO.File]::WriteAllText((Join-Path $remote 'later.txt'), 'must not become checkout HEAD')
    Invoke-CiNative git @('-C', $remote, 'add', '.') | Out-Null
    Invoke-CiNative git @('-C', $remote, 'commit', '-m', 'later upstream commit') | Out-Null
    $later = @(Invoke-CiNative git @('-C', $remote, 'rev-parse', 'HEAD'))[0]
    $url = ([System.Uri]::new($remote, [System.UriKind]::Absolute)).AbsoluteUri

    $fresh = Join-Path $tempDir 'fresh checkout'
    Initialize-CiVcpkgCheckout -CheckoutPath $fresh -Commit $pin -RepositoryUrl $url
    Invoke-CiNative git @('-C', $fresh, 'cat-file', '-e', "$oldTree^{tree}") | Out-Null
    if (@(Invoke-CiNative git @('-C', $fresh, 'rev-parse', 'HEAD'))[0] -ne $pin) {
        throw 'Fresh checkout moved beyond the pinned commit'
    }
    Write-Host 'PASS: fresh checkout retains historical port trees and exact pin'

    $cached = Join-Path $tempDir 'shallow cached checkout'
    Invoke-CiNative git @('init', $cached) | Out-Null
    Invoke-CiNative git @('-C', $cached, 'remote', 'add', 'origin', $url) | Out-Null
    Invoke-CiNative git @('-C', $cached, 'fetch', '--depth=1', 'origin', $pin) | Out-Null
    Invoke-CiNative git @('-C', $cached, 'checkout', '--detach', $pin) | Out-Null
    Assert-Fails { Invoke-CiNative git @('-C', $cached, 'cat-file', '-e', "$oldTree^{tree}") } 'Fixture failed to reproduce missing historical tree'
    Initialize-CiVcpkgCheckout -CheckoutPath $cached -Commit $pin -RepositoryUrl $url
    Invoke-CiNative git @('-C', $cached, 'cat-file', '-e', "$oldTree^{tree}") | Out-Null
    if (@(Invoke-CiNative git @('-C', $cached, 'rev-parse', 'HEAD'))[0] -ne $pin) {
        throw 'History repair moved the pinned checkout'
    }
    Write-Host 'PASS: shallow cache reproduces missing tree, then repairs it without changing HEAD'

    Assert-Fails { Initialize-CiVcpkgCheckout -CheckoutPath $cached -Commit $later -RepositoryUrl $url } 'Incorrect cached HEAD was accepted'
    Assert-Fails { Initialize-CiVcpkgCheckout -CheckoutPath $cached -Commit $pin -RepositoryUrl ($url + '-wrong') } 'Incorrect cached origin was accepted'
    Write-Host 'PASS: cached commit and origin mismatches are rejected'

    $unrepairable = Join-Path $tempDir 'unrepairable shallow cache'
    Invoke-CiNative git @('clone', '--depth=1', $url, $unrepairable) | Out-Null
    # A complete cache can be reused without a fetch or upstream availability.
    Move-Item -LiteralPath $remote -Destination ($remote + '-offline')
    Initialize-CiVcpkgCheckout -CheckoutPath $cached -Commit $pin -RepositoryUrl $url
    Invoke-CiNative git @('-C', $cached, 'cat-file', '-e', "$oldTree^{tree}") | Out-Null
    Write-Host 'PASS: complete pinned cache works offline'

    Assert-Fails { Initialize-CiVcpkgCheckout -CheckoutPath $unrepairable -Commit $later -RepositoryUrl $url } 'Failed shallow-cache repair was accepted'
    Assert-Fails { Initialize-CiVcpkgCheckout -CheckoutPath (Join-Path $tempDir 'unavailable') -Commit $pin -RepositoryUrl $url } 'Failed fetch was accepted'
    Assert-Fails { Initialize-CiVcpkgCheckout -CheckoutPath (Join-Path $tempDir 'invalid') -Commit 'main' -RepositoryUrl $url } 'Unpinned revision was accepted'
    Write-Host 'PASS: failed history repair, failed fetch, and unpinned revision are rejected'
}
catch {
    Write-Host $_.ScriptStackTrace
    throw
}
finally {
    Remove-Item -LiteralPath $tempDir -Recurse -Force
}
