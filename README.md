# nltop1

Source tree for the x86 client, injector, local Rust server, and optional license-loader platform.

## Repository layout

- `neverlose/` - client DLL source and required embedded payloads.
- `injector/` - injector source.
- `server/rust-server/` - local server and parser.
- `server/data/` - server resources embedded at compile time.
- `libraries/open_source/` - Lua libraries embedded by the Rust build script.
- `loader-platform/` - optional C++ loader, Go authorization service, and deployment files.
- `tests/` - small source-level regression tests only.
- `phnt/` and `detours/` - required build dependencies.

Generated binaries, IDE state, reverse databases, diagnostics, and backups are intentionally excluded.

## Requirements

- Git LFS
- Visual Studio Build Tools 2026 with the v145 MSVC toolset
- Windows 10 SDK
- Rust 1.88.0 or newer
- Go 1.24 or newer for `loader-platform/server`

Clone with LFS assets:

```powershell
git lfs install
git lfs pull
```

## Build the main project

Build the Rust server first:

```powershell
Push-Location server\rust-server
cargo build --release --locked
New-Item -ItemType Directory -Force ..\..\Release | Out-Null
Copy-Item target\release\neverlose-server.exe ..\..\Release\neverlose-server.exe
Pop-Location
```

Then build the x86 C++ solution:

```powershell
msbuild neverlose.sln /m /p:Configuration=Release /p:Platform=x86 /p:PlatformToolset=v145
```

Expected outputs are `Release\neverlose.dll` and `Release\injector.exe`.

## Build the optional loader platform

The loader embeds the injector produced by the main solution. After the main build:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\loader-platform\client\build.ps1
```

Run the authorization service tests with:

```powershell
Push-Location loader-platform\server
go test ./...
Pop-Location
```

Copy `loader-platform/server/.env.example` to a local `.env` or service environment and fill in deployment-specific values. Never commit the completed environment file, signing keys, bot tokens, databases, or payload artifacts.

Refer to `LICENSE` for the project license disclaimer.

