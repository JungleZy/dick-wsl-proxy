#!/usr/bin/env bash
# WSL/Linux -> native Windows x64 GPUI release, without installing a Windows SDK.
set -euo pipefail
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
build_root=$(realpath -m -- "${WSL_PROXY_BUILD_DIR:-/tmp/wsl-proxy-desktop-build}")
output_dir=$(realpath -m -- "${WSL_PROXY_OUTPUT_DIR:-$build_root/output}")
jobs=${WSL_PROXY_BUILD_JOBS:-2}
if [[ ${1:-} == --help ]]; then
    printf '%s\n' 'Usage: scripts/build-desktop-windows.sh [--clean]' \
        'Requires WSL interop, Rust with x86_64-pc-windows-gnu, Ubuntu apt-get/dpkg-deb and Python 3.' \
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
for tool in cargo rustc python3 apt-get dpkg-deb wslpath powershell.exe; do
    command -v "$tool" >/dev/null || { printf 'Missing prerequisite: %s\n' "$tool" >&2; exit 1; }
done
stdlib=$(rustc --print target-libdir --target x86_64-pc-windows-gnu)
compgen -G "$stdlib/libstd-*.rlib" >/dev/null || {
    printf 'Rust target x86_64-pc-windows-gnu is not installed in the selected toolchain. No toolchain was modified.\n' >&2
    exit 1
}
mkdir -p "$build_root/gnu-debs" "$build_root/gnu" "$build_root/tools" "$output_dir"
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
cp "$repo_root/desktop/build.rs" "$build_root/workspace/desktop/build.rs"
cp "$repo_root/desktop/wsl-proxy-desktop.rc" "$build_root/workspace/desktop/wsl-proxy-desktop.rc"
mkdir -p "$build_root/workspace/desktop/assets"
cp "$repo_root/desktop/assets/wsl-proxy.ico" "$build_root/workspace/desktop/assets/wsl-proxy.ico"
ln -sfn "$repo_root/src" "$build_root/workspace/src"
ln -sfn "$repo_root/desktop/src" "$build_root/workspace/desktop/src"

# gpui-kit 0.10.0's DirectX shader build script is gated on the host OS.
# Cross-compiling from WSL therefore skips shader generation even though the
# Windows target later includes the generated bindings. Patch the cached build
# script only for this invocation, then restore the registry source on exit.
cargo fetch --manifest-path "$build_root/workspace/Cargo.toml" --locked
gpui_build_script=$(find "${CARGO_HOME:-$HOME/.cargo}/registry/src" \
    -path '*/gpui-pre-windows-0.3.12/build.rs' -print -quit)
if [[ -z "$gpui_build_script" ]]; then
    printf '%s\n' 'Unable to locate gpui-pre-windows 0.3.12 build script after cargo fetch.' >&2
    exit 1
fi
gpui_build_backup="$build_root/gpui-pre-windows-0.3.12.build.rs.orig"
cp "$gpui_build_script" "$gpui_build_backup"
restore_gpui_build_script() {
    cp "$gpui_build_backup" "$gpui_build_script"
}
trap restore_gpui_build_script EXIT
python3 - "$gpui_build_script" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
source = path.read_text()
if "__wsl_proxy_cross_shader_patch__" not in source:
    original_main = '''fn main() {
    #[cfg(not(all(target_os = "windows", not(debug_assertions))))]
    println!("cargo:rerun-if-changed=build.rs");
    #[cfg(target_os = "windows")]
    {
        // Compile HLSL shaders
        #[cfg(not(debug_assertions))]
        compile_shaders();
    }
}'''
    patched_main = '''fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    // Compile HLSL shaders for a Windows target built from WSL.
    compile_shaders();
}'''
    if original_main not in source:
        raise SystemExit("unexpected gpui-pre-windows build.rs main function")
    source = source.replace(original_main, patched_main, 1)
    source = source.replace(
        '#[cfg(all(target_os = "windows", not(debug_assertions)))]\nmod shader_compilation',
        'mod shader_compilation',
        1,
    )
    source = source.replace(
        '#[cfg(all(target_os = "windows", not(debug_assertions)))]\nuse shader_compilation::compile_shaders;',
        'use shader_compilation::compile_shaders;',
        1,
    )
    source = source.replace(
        '    pub fn find_latest_windows_sdk_binary(\n',
        '    #[cfg(target_os = "windows")]\n    pub fn find_latest_windows_sdk_binary(\n',
        1,
    )
    sdk_fallback = '''        if let Ok(Some(path)) = find_latest_windows_sdk_binary("fxc.exe") {
            return path.to_string_lossy().into_owned();
        }

'''
    if sdk_fallback not in source:
        raise SystemExit("unexpected gpui-pre-windows SDK fallback")
    source = source.replace(sdk_fallback, "", 1)
    source = source.replace(
        '#![allow(clippy::disallowed_methods, reason = "build scripts are exempt")]',
        '#![allow(clippy::disallowed_methods, reason = "build scripts are exempt")]\n// __wsl_proxy_cross_shader_patch__',
        1,
    )
    path.write_text(source)
PY
cargo build --manifest-path "$build_root/workspace/Cargo.toml" --release --locked --target x86_64-pc-windows-gnu \
    --package wsl-proxy-desktop --package wsl-proxyctl
cp "$CARGO_TARGET_DIR/x86_64-pc-windows-gnu/release/wsl-proxy-desktop.exe" \
    "$CARGO_TARGET_DIR/x86_64-pc-windows-gnu/release/wsl-proxyctl.exe" "$output_dir/"
printf 'Native Windows release: %s\n' "$(wslpath -w "$output_dir/wsl-proxy-desktop.exe")"
printf 'Companion controller: %s\n' "$(wslpath -w "$output_dir/wsl-proxyctl.exe")"
