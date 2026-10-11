# SPDX-License-Identifier: Apache-2.0
# Keep PowerShell errors fatal while interpreting native tools by their exit code.
function Invoke-CiNative {
    param(
        [Parameter(Mandatory = $true)][string] $FilePath,
        [string[]] $ArgumentList = @()
    )
    $executable = (Get-Command -Name $FilePath -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    $savedPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $PSNativeCommandUseErrorActionPreference = $false
        & $executable @ArgumentList 2>&1 | ForEach-Object { $_.ToString() }
        $nativeExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $savedPreference
    }
    if ($nativeExitCode -ne 0) {
        throw "$FilePath failed with exit code $nativeExitCode"
    }
}
