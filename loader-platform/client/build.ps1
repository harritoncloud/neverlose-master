param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"
$project = Join-Path $PSScriptRoot "nl-loader.vcxproj"
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
$injectorSource = Join-Path $repoRoot "Release\injector.exe"
$assetDirectory = Join-Path $PSScriptRoot "assets"
$injectorAsset = Join-Path $assetDirectory "injector.exe"

if (-not (Test-Path -LiteralPath $injectorSource -PathType Leaf)) {
    throw "Build the main Release|x86 solution first. Missing: $injectorSource"
}

New-Item -ItemType Directory -Path $assetDirectory -Force | Out-Null
Copy-Item -LiteralPath $injectorSource -Destination $injectorAsset -Force

$candidates = @(
    "C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe",
    "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
)
$msbuild = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $msbuild) {
    throw "MSBuild with the C++ toolchain was not found."
}

& $msbuild $project /m /t:Rebuild "/p:Configuration=$Configuration" /p:Platform=Win32 /nologo
if ($LASTEXITCODE -ne 0) {
    throw "Loader build failed with exit code $LASTEXITCODE."
}

$output = Join-Path $PSScriptRoot "bin\$Configuration\nl-loader.exe"
if (-not (Test-Path -LiteralPath $output)) {
    throw "Loader output was not created."
}
Get-Item -LiteralPath $output
