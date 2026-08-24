param()

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$rawPath = Join-Path $root "neverlose\bins\nl.bin"
$sourcePath = Join-Path $root "neverlose\nl_anim_hook.cpp"
$setupPath = Join-Path $root "neverlose\setup_hooks.cpp"
$projectPath = Join-Path $root "neverlose\neverlose.vcxproj"
$imageBase = [int64]0x412A0000
$targetRva = [int]0xCB2F10
$targetVa = $imageBase + $targetRva

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Assert-Bytes(
    [byte[]]$Bytes,
    [int]$Offset,
    [byte[]]$Expected,
    [string]$Description
) {
    Assert-True ($Offset -ge 0) "$Description starts before the image"
    Assert-True (($Offset + $Expected.Length) -le $Bytes.Length) "$Description exceeds the image"
    for ($index = 0; $index -lt $Expected.Length; ++$index) {
        Assert-True ($Bytes[$Offset + $index] -eq $Expected[$index]) (
            "{0}: byte {1} is 0x{2:X2}, expected 0x{3:X2}" -f
                $Description,
                $index,
                $Bytes[$Offset + $index],
                $Expected[$index])
    }
}

function Test-WindowContains(
    [byte[]]$Bytes,
    [int]$Offset,
    [int]$Length,
    [byte[]]$Needle
) {
    $last = $Offset + $Length - $Needle.Length
    for ($cursor = $Offset; $cursor -le $last; ++$cursor) {
        $matched = $true
        for ($index = 0; $index -lt $Needle.Length; ++$index) {
            if ($Bytes[$cursor + $index] -ne $Needle[$index]) {
                $matched = $false
                break
            }
        }
        if ($matched) {
            return $true
        }
    }
    return $false
}

$signature = [byte[]](
    0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x14, 0x53, 0x56,
    0x8B, 0x75, 0x08, 0x57, 0x8B, 0x86, 0x98, 0x2D,
    0x00, 0x00, 0x80, 0x78, 0x05, 0x00, 0x74, 0x0D,
    0x80, 0xBE, 0x8D, 0x2D, 0x00, 0x00, 0x00, 0x75,
    0x04, 0xB3, 0x01, 0xEB, 0x02, 0x32, 0xDB)

$raw = [IO.File]::ReadAllBytes($rawPath)
$encoding = [Text.Encoding]::GetEncoding(28591)
$rawText = $encoding.GetString($raw)
$signatureText = $encoding.GetString($signature)
$firstMatch = $rawText.IndexOf(
    $signatureText,
    [StringComparison]::Ordinal)
Assert-True ($firstMatch -eq $targetRva) (
    "Animation target signature resolved to 0x{0:X}, expected 0x{1:X}" -f
        $firstMatch,
        $targetRva)
$secondMatch = $rawText.IndexOf(
    $signatureText,
    $firstMatch + 1,
    [StringComparison]::Ordinal)
Assert-True ($secondMatch -eq -1) "Animation target signature is not unique"

Assert-Bytes $raw $targetRva ([byte[]](0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x14)) (
    "six-byte whole-instruction prologue")
Assert-Bytes $raw ($targetRva + 0x2D) ([byte[]](0x8B, 0x45, 0x0C)) (
    "second stack argument load")
Assert-Bytes $raw ($targetRva + 0x30) ([byte[]](0x8B, 0x7D, 0x10)) (
    "third stack argument load")
Assert-Bytes $raw ($targetRva + 0x163) ([byte[]](0xC3)) "cdecl return"

$callSites = [int64[]](
    0x41F53274,
    0x41F53E15,
    0x41F53EEA,
    0x41F5429C,
    0x41F542E0,
    0x41F5672A,
    0x41F579D4)
foreach ($callSite in $callSites) {
    $offset = [int]($callSite - $imageBase)
    Assert-True ($raw[$offset] -eq 0xE8) (
        "Expected call opcode at 0x{0:X8}" -f $callSite)
    $destination = $callSite + 5 + [BitConverter]::ToInt32($raw, $offset + 1)
    Assert-True ($destination -eq $targetVa) (
        "Call at 0x{0:X8} resolves to 0x{1:X8}" -f $callSite, $destination)
    Assert-True (Test-WindowContains $raw ($offset + 5) 16 ([byte[]](0x83, 0xC4, 0x0C))) (
        "Call at 0x{0:X8} does not clean three cdecl arguments" -f $callSite)
}

$source = Get-Content -Raw -LiteralPath $sourcePath
$signatureBlock = [regex]::Match(
    $source,
    'kTargetSignature\[\]\s*=\s*\{(?<body>.*?)\};',
    [Text.RegularExpressions.RegexOptions]::Singleline)
Assert-True $signatureBlock.Success "Cannot locate C++ target signature"
$sourceSignature = [byte[]]@(
    [regex]::Matches($signatureBlock.Groups['body'].Value, '0x([0-9A-Fa-f]{2})') |
        ForEach-Object { [Convert]::ToByte($_.Groups[1].Value, 16) })
Assert-True ($sourceSignature.Length -eq $signature.Length) "C++ signature length changed"
for ($index = 0; $index -lt $signature.Length; ++$index) {
    Assert-True ($sourceSignature[$index] -eq $signature[$index]) (
        "C++ signature differs at byte $index")
}

Assert-True ([regex]::IsMatch(
    $source,
    'using\s+target_fn\s*=\s*void\(__cdecl\*\)\(\s*void\*,\s*std::uint32_t,\s*std::uint32_t\s*\)',
    [Text.RegularExpressions.RegexOptions]::Singleline)) (
    "Native target ABI is not three-argument cdecl")
Assert-True ($source.Contains("constexpr std::size_t kPatchTailBytes = 1;")) (
    "Hook does not cover the complete six-byte prologue")
Assert-True ($source.Contains("&g_original_trampoline")) (
    "Hook trampoline output is not wired before activation")

$setup = Get-Content -Raw -LiteralPath $setupPath
$project = Get-Content -Raw -LiteralPath $projectPath
Assert-True ($setup.Contains("install_nl_anim_hook()")) "Animation hook is not installed"
Assert-True ($project.Contains('<ClCompile Include="nl_anim_hook.cpp" />')) (
    "Animation hook source is missing from the project")
Assert-True ($project.Contains('<ClInclude Include="nl_anim_hook.h" />')) (
    "Animation hook header is missing from the project")

[pscustomobject]@{
    SignatureMatches = 1
    Target = ("0x{0:X8}" -f $targetVa)
    Callers = $callSites.Count
    CallingConvention = "cdecl/3 args"
    PatchedPrologueBytes = 6
}
