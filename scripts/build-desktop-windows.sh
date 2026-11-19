#!/usr/bin/env bash
# WSL/Linux -> native Windows x64 GPUI release, without installing a Windows SDK.
set -euo pipefail
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
build_root=$(realpath -m -- "${WSL_PROXY_BUILD_DIR:-/tmp/wsl-proxy-desktop-build}")
output_dir=$(realpath -m -- "${WSL_PROXY_OUTPUT_DIR:-$build_root/output}")
jobs=${WSL_PROXY_BUILD_JOBS:-2}
if [[ ${1:-} == --help ]]; then
    printf '%s\n' 'Usage: scripts/build-desktop-windows.sh [--clean]' \
        'Requires WSL interop, Rust with x86_64-pc-windows-gnu, host cc and gcc, Ubuntu apt-get/dpkg-deb, curl, tar, patch, Python 3.' \
        'WSL_PROXY_BUILD_DIR: isolated compiler/source/cache directory (default /tmp/wsl-proxy-desktop-build)' \
        'WSL_PROXY_OUTPUT_DIR: output EXE directory (default BUILD_DIR/output)' \
        'WSL_PROXY_BUILD_JOBS: Cargo parallel jobs (default 2)' \
        '--clean removes only Cargo build artifacts; downloaded compiler/source cache is retained.'
    exit 0
fi
if [[ ${1:-} == --clean ]]; then
    if [[ -f "$build_root/workspace/Cargo.toml" ]]; then
        exec cargo clean --manifest-path "$build_root/workspace/Cargo.toml" --target-dir "$build_root/target"
    fi
    exit 0
fi
if [[ $# != 0 ]]; then printf 'Unknown argument: %s\n' "$1" >&2; exit 2; fi
for tool in cargo rustc cc gcc curl tar patch python3 apt-get dpkg-deb wslpath powershell.exe; do
    command -v "$tool" >/dev/null || { printf 'Missing prerequisite: %s\n' "$tool" >&2; exit 1; }
done
stdlib=$(rustc --print target-libdir --target x86_64-pc-windows-gnu)
compgen -G "$stdlib/libstd-*.rlib" >/dev/null || {
    printf 'Rust target x86_64-pc-windows-gnu is not installed in the selected toolchain. No toolchain was modified.\n' >&2
    exit 1
}
mkdir -p "$build_root/gnu-debs" "$build_root/gnu" "$build_root/crates" "$build_root/tools" "$output_dir"
if [[ ! -x "$build_root/gnu/usr/bin/x86_64-w64-mingw32-gcc-posix" ]]; then
    (
        cd "$build_root/gnu-debs"
        apt-get download \
            'binutils-mingw-w64-x86-64=2.41.90.20240122-1ubuntu1+11.4' \
            'gcc-mingw-w64-base=13.2.0-6ubuntu1+26.1' \
            'gcc-mingw-w64-x86-64-posix=13.2.0-6ubuntu1+26.1' \
            'gcc-mingw-w64-x86-64-posix-runtime=13.2.0-6ubuntu1+26.1' \
            'mingw-w64-common=11.0.1-3build1' \
            'mingw-w64-x86-64-dev=11.0.1-3build1'
        for archive in ./*.deb; do dpkg-deb -x "$archive" "$build_root/gnu"; done
    )
fi
export PATH="$build_root/gnu/usr/bin:$PATH"
compiler="$build_root/gnu/usr/bin/x86_64-w64-mingw32-gcc-posix"
"$compiler" -O2 -Wall -Wextra -municode -static "$repo_root/scripts/build-desktop-hlsl.c" \
    -o "$build_root/tools/hlsl-bridge.exe" -ld3dcompiler_47
if [[ ! -f "$build_root/crates/gpui-0.2.2/.cross-host-corrected" ]]; then
    curl -fL --retry 2 https://crates.io/api/v1/crates/gpui/0.2.2/download -o "$build_root/crates/gpui.tar.gz"
    printf '%s  %s\n' 979b45cfa6ec723b6f42330915a1b3769b930d02b2d505f9697f8ca602bee707 "$build_root/crates/gpui.tar.gz" | sha256sum -c -
    tar -xzf "$build_root/crates/gpui.tar.gz" -C "$build_root/crates"
    patch --batch -p0 -d "$build_root/crates" <<'PATCH'
--- gpui-0.2.2/build.rs
+++ gpui-0.2.2/build.rs
@@ -22,7 +22,6 @@
             macos::build();
         }
         Ok("windows") => {
-            #[cfg(target_os = "windows")]
             windows::build();
         }
         _ => (),
@@ -245,7 +244,6 @@
     }
 }
 
-#[cfg(target_os = "windows")]
 mod windows {
     use std::{
         fs,
--- gpui-0.2.2/Cargo.toml
+++ gpui-0.2.2/Cargo.toml
@@ -724,7 +724,7 @@
 [target.'cfg(target_os = "windows")'.dependencies.windows-registry]
 version = "0.5"
 
-[target.'cfg(target_os = "windows")'.build-dependencies.embed-resource]
+[build-dependencies.embed-resource]
 version = "3.0"
 
 [lints.clippy]
PATCH
    touch "$build_root/crates/gpui-0.2.2/.cross-host-corrected"
fi
cat > "$build_root/tools/hlsl-wsl" <<'PYTHON'
#!/usr/bin/env python3
import os
import subprocess
import sys
args = []
for arg in sys.argv[1:]:
    if arg.startswith('/') and (os.path.exists(arg) or arg.startswith('/tmp/') or arg.startswith('/mnt/')):
        arg = subprocess.check_output(['wslpath', '-w', arg], text=True).strip()
    args.append(arg)
raise SystemExit(subprocess.call([os.environ['GPUI_HLSL_BRIDGE'], *args]))
PYTHON
chmod +x "$build_root/tools/hlsl-wsl"
export CARGO_TARGET_DIR="$build_root/target" CARGO_BUILD_JOBS="$jobs"
export CARGO_PROFILE_RELEASE_DEBUG=0 CARGO_PROFILE_RELEASE_INCREMENTAL=false CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16
export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER="$compiler"
export CC_x86_64_pc_windows_gnu="$compiler"
export AR_x86_64_pc_windows_gnu="$build_root/gnu/usr/bin/x86_64-w64-mingw32-ar"
export RC_x86_64_pc_windows_gnu="$build_root/gnu/usr/bin/x86_64-w64-mingw32-windres"
export GPUI_FXC_PATH="$build_root/tools/hlsl-wsl" GPUI_HLSL_BRIDGE="$build_root/tools/hlsl-bridge.exe"
mkdir -p "$build_root/workspace/desktop"
cp "$repo_root/Cargo.toml" "$build_root/workspace/Cargo.toml"
cp "$repo_root/Cargo.lock" "$build_root/workspace/Cargo.lock"
cp "$repo_root/desktop/Cargo.toml" "$build_root/workspace/desktop/Cargo.toml"
ln -sfn "$repo_root/src" "$build_root/workspace/src"
ln -sfn "$repo_root/desktop/src" "$build_root/workspace/desktop/src"
cargo build --manifest-path "$build_root/workspace/Cargo.toml" --release --target x86_64-pc-windows-gnu \
    --package wsl-proxy-desktop --package wsl-proxyctl --config "patch.crates-io.gpui.path=\"$build_root/crates/gpui-0.2.2\""
cp "$CARGO_TARGET_DIR/x86_64-pc-windows-gnu/release/wsl-proxy-desktop.exe" \
    "$CARGO_TARGET_DIR/x86_64-pc-windows-gnu/release/wsl-proxyctl.exe" "$output_dir/"
printf 'Native Windows release: %s\n' "$(wslpath -w "$output_dir/wsl-proxy-desktop.exe")"
printf 'Companion controller: %s\n' "$(wslpath -w "$output_dir/wsl-proxyctl.exe")"
