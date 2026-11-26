#!/usr/bin/env python3
"""Write the GitHub release notes for one tagged Windows package.

The notes say what was released and how it was checked: the tag message (the
maintainer's own summary), the download with its SHA-256, the source commit,
toolchain and runner, the C runtime import check, the test counts read from
the CI logs, the install smoke test, every commit since the previous v* tag
grouped by type, install guidance and the known limitations.

Usage: release-notes.py --version X.Y.Z --tag REF --zip ZIP --imports JSON
                        --smoke JSON --logs DIR --toolchain TXT --output MD
                        [--repository OWNER/NAME]

REF is the release tag, or any commit (HEAD) for a dry run.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parent.parent
GROUPS = (
    ("feat", "新功能"),
    ("fix", "修复"),
    ("perf", "性能"),
    ("refactor", "重构"),
    ("docs", "文档"),
    ("test", "测试"),
    ("build", "构建与维护"),
    ("ci", "构建与维护"),
    ("chore", "构建与维护"),
)
SUBJECT = re.compile(r"^(?P<type>[a-z]+)(?:\([^)]*\))?!?:\s*(?P<text>.+)$")


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True, text=True, encoding="utf-8").stdout


def previous_tag(tag):
    """The nearest v* tag before `tag`, or None for the first release."""
    try:
        return git("describe", "--tags", "--abbrev=0", "--match", "v*", tag + "^").strip() or None
    except subprocess.CalledProcessError:
        return None


def tag_message(tag):
    """An annotated tag's message without any signature; nothing for a
    lightweight tag or a plain commit (dry run)."""
    try:
        if git("cat-file", "-t", "refs/tags/" + tag).strip() != "tag":
            return ""
    except subprocess.CalledProcessError:
        return ""
    text = git("tag", "-l", "--format=%(contents)", tag)
    return text.split("-----BEGIN PGP SIGNATURE-----")[0].strip()


def commits(previous, tag):
    span = f"{previous}..{tag}" if previous else tag
    lines = git("log", "--no-merges", "--format=%h%x09%s", span).splitlines()
    grouped = {}
    for line in lines:
        short, subject = line.split("\t", 1)
        match = SUBJECT.match(subject)
        kind = dict(GROUPS).get(match["type"], "其他") if match else "其他"
        text = match["text"] if match else subject
        grouped.setdefault(kind, []).append(f"- {text}（`{short}`）")
    return len(lines), grouped


def test_counts(logs):
    """{suite: count} from cargo's 'test result' lines and unittest's 'Ran N tests'."""
    counts = {}
    for path in sorted(Path(logs).glob("*.txt")):
        text = path.read_text(encoding="utf-8", errors="replace")
        cargo = sum(int(n) for n in re.findall(r"test result: ok\. (\d+) passed", text))
        python = sum(int(n) for n in re.findall(r"^Ran (\d+) tests? in", text, re.M))
        if cargo or python:
            counts[path.stem] = cargo + python
    return counts


def size(n):
    return f"{n / 1024 / 1024:.1f} MiB"


def license_limit(licenses):
    """The known-limits line on third-party licenses, from release.json."""
    missing = licenses["missing_notice_count"]
    if missing:
        return f"- 第三方许可证尚未完成再分发审查：`THIRD-PARTY-NOTICES.json` 里有 {missing} 条缺少许可文本。"
    return (
        f"- 第三方许可证尚未完成再分发审查：清单里 Windows 版依赖图的 {licenses.get('package_count', '全部')} 个第三方包都附了许可文本，"
        f"其中 {licenses.get('standard_text_count', 0)} 个包自己没带，附的是它声明的许可证的标准全文；"
        "是否满足再分发义务仍待负责人确认。"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    for name in ("version", "tag", "zip", "imports", "smoke", "logs", "toolchain", "output"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    args = parser.parse_args()

    version = args.version
    archive = Path(args.zip)
    data = archive.read_bytes()
    with zipfile.ZipFile(archive) as package:
        manifest = json.loads(package.read("release.json"))
    imports = json.loads(Path(args.imports).read_text(encoding="utf-8"))
    smoke = json.loads(Path(args.smoke).read_text(encoding="utf-8-sig"))
    if smoke.get("passed") is not True:
        raise SystemExit("install smoke test did not pass: " + str(smoke.get("error")))
    toolchain = Path(args.toolchain).read_text(encoding="utf-8").strip()
    commit = git("rev-list", "-n", "1", args.tag).strip()
    previous = previous_tag(args.tag)
    total, grouped = commits(previous, args.tag)
    counts = test_counts(args.logs)
    repo = f"https://github.com/{args.repository}" if args.repository else ""

    out = [f"# WSL Proxy {version}", ""]
    message = tag_message(args.tag)
    if message:
        out += [message, ""]
    out += [
        "> Windows x64 发布包，没有代码签名。SHA-256 只证明下载内容与这里一致，不证明发布者身份；"
        "第三方许可证的再分发义务尚待确认，见文末「已知限制」。",
        "",
        "## 下载",
        "",
        "| 文件 | 大小 | SHA-256 |",
        "|---|---|---|",
        f"| `{archive.name}` | {size(len(data))} | `{hashlib.sha256(data).hexdigest()}` |",
        "",
        f"校验：`Get-FileHash -Algorithm SHA256 .\\{archive.name}`，结果应与上表一致。`.sha256` 文件和 ZIP 来自同一处，不能证明发布者。",
        "",
    ]
    if args.repository:
        out += [
            f"来源：发布流水线为这个 ZIP 生成了 GitHub 构建来源证明。装了 GitHub CLI 的话，运行 `gh attestation verify .\\{archive.name} -R {args.repository}`，"
            "通过就说明它是本仓库的发布流水线从下面的提交构建出来的。这证明的是构建来源，不是代码签名。",
            "",
        ]
    out += [
        "## 构建",
        "",
        f"- 源码：`{args.tag}` → 提交 `{commit}`" + (f"（[查看]({repo}/tree/{commit})）" if repo else ""),
        f"- 目标：`{manifest['target']}`，包类型 `{manifest['kind']}`，清单列出 {len(manifest['files'])} 个文件",
        "- 工具链：" + "；".join(line.strip() for line in toolchain.splitlines() if line.strip().startswith(("rustc ", "host: ", "cargo ", "Python "))),
        f"- 构建机：GitHub Actions `{os.environ.get('ImageOS', 'windows')}` 镜像 `{os.environ.get('ImageVersion', '未知')}`",
        "- 许可证：本项目 MIT（包里的 `LICENSE`）；第三方依赖的许可证见包里的 `THIRD-PARTY-NOTICES.json` 和 `licenses/`",
        "- C 运行库：两个 EXE 的普通导入和延迟加载导入里都没有 C 运行库 DLL（`VCRUNTIME*`、`MSVCP*`、`UCRTBASE`、`api-ms-win-crt-*`），"
        "不需要另装 Visual C++ 运行库。",
    ]
    for exe, found in sorted(imports.items()):
        out.append(f"  - `{exe}` 导入 {len(found['import'])} 个 DLL，延迟加载 {len(found['delay'])} 个，C 运行库 {len(found['c_runtime'])} 个")
    out += ["", "## 发布前的检查", ""]
    out.append("全部通过才会发布：")
    out.append("")
    out.append("- `cargo fmt --check`、`cargo clippy -D warnings`（控制器与桌面）")
    labels = {
        "cargo-test": "Rust 测试（控制器与桌面）",
        "python-guest": "客机脚本测试",
        "python-packaging": "打包脚本测试",
    }
    for suite, count in counts.items():
        out.append(f"- {labels.get(suite, suite)}：{count} 项通过")
    out.append(f"- 后台 `wsl-proxyctl.exe --version` 报 `{version}`，与 tag 一致")
    out.append("- 安装冒烟测试（在构建机上，安装到临时私有目录）：")
    out.append(f"  - 全新安装成功，安装目录里的后台报 `{smoke['installed_version']}`，共 {smoke['installed_files']} 个文件")
    if smoke.get("reinstall_unchanged"):
        out.append("  - 同一个包再装一次：没有改动任何文件（哈希和修改时间不变）")
    if smoke.get("tampered_refused"):
        out.append("  - 改过一个文件的包：安装被拒绝，安装目录不变")
    if smoke.get("uninstall_clean"):
        out.append("  - 卸载：程序文件全部删除，没有残留的事务、暂存或备份目录")
    out += [
        "",
        "没有在构建机上做的：真实 WSL 发行版上的接管（构建机没有 WSL）、从旧版本升级、`-Recover` 中断恢复。"
        "这些按 [M5 发布说明]" + (f"({repo}/blob/{args.tag}/docs/plans/m5/README.md)" if repo else "(docs/plans/m5/README.md)") + " 在本机验收。",
        "",
        f"## 变更（自 {previous or '首个提交'} 以来 {total} 个提交）",
        "",
    ]
    if repo and previous:
        out += [f"完整对比：{repo}/compare/{previous}...{args.tag}", ""]
    order = [label for _, label in GROUPS] + ["其他"]
    for label in dict.fromkeys(order):
        if label in grouped:
            out += [f"### {label}", "", *grouped[label], ""]
    out += [
        "## 安装、升级与卸载",
        "",
        "1. 核对上面的 SHA-256，把 ZIP 完整解压到一个新目录（不要解压到安装目录里）。",
        "2. 升级或卸载前，先在旧版里停止接管、恢复直连，再关闭窗口（托盘菜单「退出」）。",
        "3. 在普通 Windows PowerShell 里运行 `.\\install.ps1`（默认装到 `%LOCALAPPDATA%\\Programs\\WslProxy`，可用 `-InstallDir` 指定）；"
        "卸载运行 `.\\uninstall.ps1`。不需要管理员权限，不要为此改执行策略。",
        "4. 安装器拒绝降级、同版本不同构建、被改过的包、安装目录里来历不明的文件，以及接管中或窗口未关时的操作。"
        "卸载只删程序文件，配置库 `desktop.sqlite`（含明文住宅凭据）留在原目录。",
        "",
        "完整步骤、中断后的恢复和支持范围见 M5 发布说明。",
        "",
        "## 已知限制",
        "",
        "- 未签名：Windows 可能提示来源未知；SHA-256 只证明一致性，构建来源可以用上面的 `gh attestation verify` 核对。",
        license_limit(manifest["licenses"]),
        "- 目标发行版的 WSL 内核低于 6.18.58.1 时预检会阻断（决策 01）；升级 WSL 后能否通过没有实测。",
        "- 其余已知问题和未验证范围见 M5 发布说明与 `docs/decisions.md`。",
        "",
    ]
    Path(args.output).write_text("\n".join(out), encoding="utf-8")
    # Only the path: a CI console may not encode the Chinese text (cp1252).
    print(f"release notes written to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
