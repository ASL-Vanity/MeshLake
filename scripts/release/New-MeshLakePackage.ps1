#Requires -Version 7.4
<#
.SYNOPSIS
Packages existing MeshLake binaries and the public documentation in the Git index.
.DESCRIPTION
Does not build, install, start services, or publish. Run from the release checkout
after staging/committing its documentation. Untracked local notes are excluded.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Windows', 'Linux')]
    [string]$Platform,
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$BinaryDirectory,
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory,
    [string]$Version,
    [string]$SourceCommit
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Platform = if ($Platform -ieq 'Windows') { 'Windows' } else { 'Linux' }
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$pathComparison = if ($IsWindows) { [StringComparison]::OrdinalIgnoreCase } else { [StringComparison]::Ordinal }
$utf8 = [Text.UTF8Encoding]::new($false)

function Invoke-RepositoryGit([string[]]$Arguments) {
    $start = [Diagnostics.ProcessStartInfo]::new('git')
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = $utf8
    $start.ArgumentList.Add('-C')
    $start.ArgumentList.Add($repositoryRoot)
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::Start($start)
    try {
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $output = $stdout.GetAwaiter().GetResult()
        $errorOutput = $stderr.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) { throw "Git source inspection failed: $errorOutput" }
        return $output
    } finally {
        $process.Dispose()
    }
}

function Get-AbsolutePath([string]$Path) {
    return [IO.Path]::GetFullPath($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path))
}

function Assert-RegularFile([string]$Path) {
    if (-not [IO.File]::Exists($Path)) { throw "Required package input is missing: $Path" }
    if ([IO.File]::GetAttributes($Path) -band [IO.FileAttributes]::ReparsePoint) {
        throw "Package inputs must be regular files, not links: $Path"
    }
}

function Assert-NativeBinary([string]$Path, [string]$TargetPlatform) {
    Assert-RegularFile $Path
    $stream = [IO.File]::OpenRead($Path)
    $reader = [IO.BinaryReader]::new($stream)
    try {
        if ($TargetPlatform -eq 'Linux') {
            $header = $reader.ReadBytes(20)
            if ($header.Length -ne 20 -or $header[0] -ne 0x7f -or $header[1] -ne 0x45 -or
                $header[2] -ne 0x4c -or $header[3] -ne 0x46 -or $header[4] -ne 2 -or
                $header[5] -ne 1 -or $header[18] -ne 0x3e -or $header[19] -ne 0) {
                throw "Expected a Linux x64 ELF binary: $Path"
            }
        } else {
            if ($stream.Length -lt 64 -or $reader.ReadUInt16() -ne 0x5a4d) {
                throw "Expected a Windows x64 PE binary: $Path"
            }
            $stream.Position = 0x3c
            $peOffset = $reader.ReadUInt32()
            if ($peOffset -lt 64 -or $peOffset -gt $stream.Length - 6) {
                throw "Invalid Windows PE header: $Path"
            }
            $stream.Position = $peOffset
            if ($reader.ReadUInt32() -ne 0x00004550 -or $reader.ReadUInt16() -ne 0x8664) {
                throw "Expected a Windows x64 PE binary: $Path"
            }
        }
    } finally {
        $reader.Dispose()
    }
}

function Get-Sha256([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    try { return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stream)).ToLowerInvariant() }
    finally { $stream.Dispose() }
}

$gitRoot = (Invoke-RepositoryGit -Arguments @('rev-parse', '--show-toplevel')).Trim()
if (-not $repositoryRoot.Equals([IO.Path]::GetFullPath($gitRoot), $pathComparison)) {
    throw 'The packaging script must reside inside the MeshLake repository root.'
}
if ([string]::IsNullOrWhiteSpace($Version)) {
    $manifest = [IO.File]::ReadAllText((Join-Path $repositoryRoot 'Cargo.toml'))
    $section = [regex]::Match($manifest, '(?ms)^\[workspace\.package\]\s*\r?\n(?<body>.*?)(?=^\[|\z)')
    $Version = [regex]::Match($section.Groups['body'].Value, '(?m)^version\s*=\s*"(?<version>[^"]+)"').Groups['version'].Value
}
if ($Version -notmatch '^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$') {
    throw 'Version must be a semantic version, or available in workspace.package.version.'
}
if ([string]::IsNullOrWhiteSpace($SourceCommit)) {
    $SourceCommit = (Invoke-RepositoryGit -Arguments @('rev-parse', 'HEAD')).Trim()
}
if ($SourceCommit -notmatch '^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$') {
    throw 'SourceCommit must be a complete Git commit hash.'
}
$SourceCommit = (Invoke-RepositoryGit -Arguments @('rev-parse', '--verify', "$SourceCommit^{commit}")).Trim()
$binaryRoot = Get-AbsolutePath $BinaryDirectory
$outputRoot = Get-AbsolutePath $OutputDirectory
if (-not [IO.Directory]::Exists($binaryRoot)) { throw "BinaryDirectory does not exist: $binaryRoot" }
$packageName = "MeshLake-$Platform-x64"
$archiveName = if ($Platform -eq 'Windows') { "$packageName.zip" } else { "$packageName.tar.gz" }
$archivePath = Join-Path $outputRoot $archiveName
$checksumPath = "$archivePath.sha256"
foreach ($destination in @($archivePath, $checksumPath)) {
    if (Test-Path -LiteralPath $destination) { throw "Refusing to overwrite existing output: $destination" }
}

$inputs = [Collections.Generic.List[object]]::new()
$packageNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$executables = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
function Add-PackageInput([string]$Source, [string]$RelativePath, [bool]$Executable = $false) {
    Assert-RegularFile $Source
    if ($RelativePath -match '[\\\r\n]' -or $RelativePath.StartsWith('/') -or
        @($RelativePath.Split('/') | Where-Object { $_ -in @('', '.', '..') }).Count -gt 0) {
        throw "Invalid relative package path: $RelativePath"
    }
    if (-not $packageNames.Add($RelativePath)) { throw "Duplicate package path: $RelativePath" }
    $inputs.Add([pscustomobject]@{ Source = $Source; RelativePath = $RelativePath })
    if ($Executable) { [void]$executables.Add($RelativePath) }
}

$binaryNames = @('meshlaked', 'meshlake-cli', 'meshlake-controller', 'meshlake-root', 'meshlake-relay')
if ($Platform -eq 'Windows') { $binaryNames = @('MeshLake') + $binaryNames }
foreach ($name in $binaryNames) {
    $fileName = if ($Platform -eq 'Windows') { "$name.exe" } else { $name }
    $source = Join-Path $binaryRoot $fileName
    Assert-NativeBinary $source $Platform
    Add-PackageInput $source $fileName $true
}
foreach ($name in @('LICENSE', 'README.md', 'THIRD_PARTY_NOTICES.md', 'SECURITY.md', 'CONTRIBUTING.md')) {
    Add-PackageInput (Join-Path $repositoryRoot $name) $name
}
$trackedDocs = (Invoke-RepositoryGit -Arguments @('ls-files', '-z', '--', 'docs')).Split([char]0, [StringSplitOptions]::RemoveEmptyEntries)
foreach ($relative in $trackedDocs) {
    if (-not $relative.StartsWith('docs/', [StringComparison]::Ordinal)) {
        throw 'Git returned a documentation path outside docs/.'
    }
    Add-PackageInput (Join-Path $repositoryRoot $relative) $relative
}
if ($Platform -eq 'Windows') {
    $wintun = Join-Path $repositoryRoot 'third_party/wintun/wintun.dll'
    Assert-NativeBinary $wintun 'Windows'
    Add-PackageInput $wintun 'wintun.dll'
    foreach ($relative in @('third_party/wintun/LICENSE.txt', 'third_party/wintun/package/wintun/LICENSE.txt')) {
        Add-PackageInput (Join-Path $repositoryRoot $relative) $relative
    }
    foreach ($name in @('NOTICE.txt', 'MiSans-License.pdf')) {
        Add-PackageInput (Join-Path $repositoryRoot "crates/meshlake-gui/assets/fonts/$name") "licenses/MiSans/$name"
    }
}

[void][IO.Directory]::CreateDirectory($outputRoot)
$outputRoot = (Resolve-Path -LiteralPath $outputRoot).ProviderPath
$temporaryName = '.meshlake-package-' + [guid]::NewGuid().ToString('N')
$temporaryRoot = Join-Path $outputRoot $temporaryName
if (Test-Path -LiteralPath $temporaryRoot) { throw 'Temporary package directory already exists.' }
[void][IO.Directory]::CreateDirectory($temporaryRoot)
$packageRoot = Join-Path $temporaryRoot $packageName
$temporaryArchive = Join-Path $temporaryRoot $archiveName
try {
    [void][IO.Directory]::CreateDirectory($packageRoot)
    foreach ($inputFile in $inputs) {
        $destination = Join-Path $packageRoot $inputFile.RelativePath
        [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination))
        [IO.File]::Copy($inputFile.Source, $destination, $false)
    }
    $release = [ordered]@{ version = $Version; source_commit = $SourceCommit; platform = $Platform.ToLowerInvariant() + '-x64' }
    [IO.File]::WriteAllText((Join-Path $packageRoot 'RELEASE.json'), ($release | ConvertTo-Json) + "`n", $utf8)
    $relativeFiles = [string[]]@([IO.Directory]::EnumerateFiles($packageRoot, '*', [IO.SearchOption]::AllDirectories) | ForEach-Object {
        [IO.Path]::GetRelativePath($packageRoot, $_).Replace('\', '/')
    })
    [Array]::Sort($relativeFiles, [StringComparer]::Ordinal)
    $hashLines = foreach ($relative in $relativeFiles) { "$(Get-Sha256 (Join-Path $packageRoot $relative))  $relative" }
    [IO.File]::WriteAllText((Join-Path $packageRoot 'SHA256SUMS.txt'), ($hashLines -join "`n") + "`n", $utf8)

    if ($Platform -eq 'Windows') {
        [IO.Compression.ZipFile]::CreateFromDirectory($packageRoot, $temporaryArchive, [IO.Compression.CompressionLevel]::Optimal, $false)
    } else {
        # Explicit tar modes work when packaging Linux binaries on Windows too.
        $archiveStream = [IO.File]::Open($temporaryArchive, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $gzip = [IO.Compression.GZipStream]::new($archiveStream, [IO.Compression.CompressionLevel]::Optimal, $true)
            try {
                $writer = [System.Formats.Tar.TarWriter]::new($gzip, [System.Formats.Tar.TarEntryFormat]::Pax, $true)
                try {
                    $directories = [string[]]@('') + @([IO.Directory]::EnumerateDirectories($packageRoot, '*', [IO.SearchOption]::AllDirectories) | ForEach-Object {
                        [IO.Path]::GetRelativePath($packageRoot, $_).Replace('\', '/')
                    })
                    [Array]::Sort($directories, [StringComparer]::Ordinal)
                    foreach ($relative in $directories) {
                        $entryName = if ($relative) { "$packageName/$relative/" } else { "$packageName/" }
                        $entry = [System.Formats.Tar.PaxTarEntry]::new([System.Formats.Tar.TarEntryType]::Directory, $entryName)
                        $entry.Mode = [IO.UnixFileMode]493 # 0755
                        $entry.Uid = 0; $entry.Gid = 0
                        $entry.UserName = 'root'; $entry.GroupName = 'root'
                        $entry.ModificationTime = [DateTimeOffset]::UnixEpoch
                        $writer.WriteEntry($entry)
                    }
                    $tarFiles = [string[]]@($relativeFiles) + @('SHA256SUMS.txt')
                    [Array]::Sort($tarFiles, [StringComparer]::Ordinal)
                    foreach ($relative in $tarFiles) {
                        $entry = [System.Formats.Tar.PaxTarEntry]::new([System.Formats.Tar.TarEntryType]::RegularFile, "$packageName/$relative")
                        $entry.Mode = [IO.UnixFileMode]$(if ($executables.Contains($relative)) { 493 } else { 420 }) # 0755 / 0644
                        $entry.Uid = 0; $entry.Gid = 0
                        $entry.UserName = 'root'; $entry.GroupName = 'root'
                        $entry.ModificationTime = [DateTimeOffset]::UnixEpoch
                        $content = [IO.File]::OpenRead((Join-Path $packageRoot $relative))
                        try { $entry.DataStream = $content; $writer.WriteEntry($entry) }
                        finally { $content.Dispose() }
                    }
                } finally { $writer.Dispose() }
            } finally { $gzip.Dispose() }
        } finally { $archiveStream.Dispose() }
    }
    $archiveHash = Get-Sha256 $temporaryArchive
    $temporaryChecksum = "$temporaryArchive.sha256"
    [IO.File]::WriteAllText($temporaryChecksum, "$archiveHash  $archiveName`n", $utf8)
    # File.Move without overwrite also rejects a destination created during packaging.
    [IO.File]::Move($temporaryArchive, $archivePath)
    [IO.File]::Move($temporaryChecksum, $checksumPath)
    [pscustomobject]@{
        Platform = $Platform
        Version = $Version
        SourceCommit = $SourceCommit
        Archive = $archivePath
        Sha256 = $archiveHash
        ChecksumFile = $checksumPath
    }
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        $resolvedTemporary = (Resolve-Path -LiteralPath $temporaryRoot).ProviderPath
        $expectedTemporary = [IO.Path]::GetFullPath((Join-Path $outputRoot $temporaryName))
        $outputPrefix = $outputRoot.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
        if (-not $resolvedTemporary.Equals($expectedTemporary, $pathComparison) -or
            -not $resolvedTemporary.StartsWith($outputPrefix, $pathComparison) -or
            ([IO.File]::GetAttributes($resolvedTemporary) -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Refusing cleanup outside the owned temporary package directory.'
        }
        Remove-Item -LiteralPath $resolvedTemporary -Recurse -Force
    }
}
