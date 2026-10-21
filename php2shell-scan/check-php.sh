#!/usr/bin/env bash
set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
    echo "Python 3 tidak ditemukan. Instal Python 3 lalu jalankan ulang." >&2
    exit 1
fi

python3 - "$@" <<'PY'
import argparse
import json
import os
import re
import subprocess
import sys


DEFAULT_CONFIG_DIRS = (
    "/etc/nginx",
    "/etc/apache2",
    "/etc/httpd",
    "/usr/local/apache/conf",
    "/usr/local/etc/nginx",
    "/opt/cpanel/ea-nginx",
)


def php_version_in(text):
    patterns = (
        r"(?i)ea-php(\d{2,3})",
        r"(?i)(?:^|[/_.-])php(\d+)\.(\d+)(?:[/_.-]|$)",
        r"(?i)(?:^|[/_.-])php(\d{2,3})(?:-fpm|[/_.-]|$)",
        r"(?i)/php/(\d+)\.(\d+)/",
    )
    for pattern in patterns:
        match = re.search(pattern, text)
        if not match:
            continue
        if pattern == patterns[0] or pattern == patterns[2]:
            digits = match.group(1)
            if len(digits) >= 2:
                return f"{int(digits[:-1])}.{int(digits[-1])}"
        else:
            return f"{int(match.group(1))}.{int(match.group(2))}"
    return None


def actual_version(label):
    if re.fullmatch(r"\d+\.\d+\.\d+", label):
        return label
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", label):
        return None

    candidates = [
        f"/usr/local/bin/{label}",
        f"/opt/cpanel/{label}/root/usr/bin/php",
        f"/usr/bin/{label}",
    ]
    minor_match = re.fullmatch(r"(\d+)\.(\d+)", label)
    if minor_match:
        candidates.extend((
            f"/usr/bin/php{label}",
            f"/usr/sbin/php-fpm{label}",
            f"/usr/sbin/php-fpm{minor_match.group(1)}{minor_match.group(2)}",
        ))
    for executable in candidates:
        if not os.path.isfile(executable) or not os.access(executable, os.X_OK):
            continue
        try:
            if "php-fpm" in os.path.basename(executable):
                result = subprocess.run(
                    [executable, "-v"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    timeout=5,
                    check=True,
                )
                version_match = re.search(r"\bPHP\s+(\d+\.\d+\.\d+)", result.stdout)
                if version_match:
                    return version_match.group(1)
                continue
            result = subprocess.run(
                [executable, "-r", "echo PHP_VERSION;"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=5,
                check=True,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        version = result.stdout.strip()
        if re.fullmatch(r"\d+\.\d+\.\d+", version):
            return version
    return None


def classify(version):
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", version or "")
    if not match:
        return "TIDAK DIKETAHUI"

    major, minor, patch = map(int, match.groups())
    if (major, minor) < (5, 4):
        return "TIDAK TERDAMPAK (berdasarkan batas versi proyek)"
    if (major, minor) == (8, 2):
        return "TERDAMPAK" if patch < 35 else "SUDAH DIPERBAIKI"
    if (major, minor) == (8, 3):
        return "TERDAMPAK" if patch < 36 else "SUDAH DIPERBAIKI"
    if (major, minor) == (8, 4):
        return "TERDAMPAK" if patch < 27 else "SUDAH DIPERBAIKI"
    if (major, minor) == (8, 5):
        return "TERDAMPAK" if patch < 12 else "SUDAH DIPERBAIKI"
    if (major, minor) < (8, 2):
        return "TERDAMPAK"
    return "PERLU VERIFIKASI ADVISORI"


def collect_whm_vhosts():
    command = shutil_which("whmapi1")
    if not command:
        return []
    try:
        result = subprocess.run(
            [command, "--output=json", "php_get_vhost_versions"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=30,
            check=True,
        )
        response = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        print(f"Peringatan: WHM API gagal ({exc}); mencoba membaca konfigurasi web server.", file=sys.stderr)
        return []

    entries = []

    def walk(node):
        if isinstance(node, dict):
            keys = {str(key).lower(): key for key in node}
            host_key = next(
                (keys[key] for key in ("vhost", "domain", "servername", "host") if key in keys),
                None,
            )
            version_key = next(
                (keys[key] for key in ("version", "php_version", "phpversion") if key in keys),
                None,
            )
            if host_key is not None and version_key is not None:
                host, version = node[host_key], node[version_key]
                if isinstance(host, str) and isinstance(version, str):
                    entries.append((host, version, "WHM API"))
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(response)
    return sorted(set(entries))


def shutil_which(command):
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(directory, command)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def strip_comments(text):
    output = []
    quote = None
    escaped = False
    comment = False
    for char in text:
        if comment:
            if char == "\n":
                comment = False
                output.append(char)
            else:
                output.append(" ")
            continue
        if escaped:
            output.append(char)
            escaped = False
            continue
        if char == "\\":
            output.append(char)
            escaped = True
            continue
        if quote:
            output.append(char)
            if char == quote:
                quote = None
            continue
        if char in ("'", '"'):
            quote = char
            output.append(char)
        elif char == "#":
            comment = True
            output.append(" ")
        else:
            output.append(char)
    return "".join(output)


def nginx_blocks(text):
    text = strip_comments(text)
    for match in re.finditer(r"\bserver\s*\{", text, re.IGNORECASE):
        start = match.end() - 1
        depth = 0
        quote = None
        escaped = False
        for index in range(start, len(text)):
            char = text[index]
            if escaped:
                escaped = False
                continue
            if char == "\\":
                escaped = True
                continue
            if quote:
                if char == quote:
                    quote = None
                continue
            if char in ("'", '"'):
                quote = char
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    yield text[start + 1:index]
                    break


def config_files(roots):
    seen = set()
    for root in roots:
        if not os.path.isdir(root):
            continue
        for current, dirs, files in os.walk(root):
            dirs[:] = [name for name in dirs if name not in ("proc", "sys", "dev")]
            for name in files:
                if not (name.endswith(".conf") or name in ("nginx.conf", "httpd.conf")):
                    continue
                path = os.path.realpath(os.path.join(current, name))
                if path in seen:
                    continue
                seen.add(path)
                try:
                    with open(path, encoding="utf-8", errors="replace") as config:
                        yield path, config.read()
                except OSError as exc:
                    print(f"Peringatan: tidak dapat membaca {path}: {exc}", file=sys.stderr)


def parse_configs(roots):
    files = list(config_files(roots))
    socket_versions = {}
    for path, text in files:
        path_version = php_version_in(path)
        if not path_version:
            continue
        for line in strip_comments(text).splitlines():
            match = re.match(r"\s*listen\s*=\s*(\S+)", line, re.IGNORECASE)
            if match:
                socket_versions[match.group(1).strip("'\";")] = path_version

    results = set()
    for path, original_text in files:
        text = strip_comments(original_text)
        for block in nginx_blocks(text):
            server_names = []
            for line in block.splitlines():
                match = re.match(r"\s*server_name\s+([^;]+);", line, re.IGNORECASE)
                if match:
                    server_names.extend(match.group(1).split())
            domains = [name for name in server_names if name != "_" and "$" not in name]
            if not domains:
                continue
            version = php_version_in(block)
            if not version:
                for endpoint in re.findall(r"(?im)^\s*fastcgi_pass\s+([^;\s]+)", block):
                    version = php_version_in(endpoint) or socket_versions.get(endpoint)
                    if version:
                        break
            for domain in domains:
                results.add((domain, version or "", path))

        for match in re.finditer(
            r"<VirtualHost\b[^>]*>(.*?)</VirtualHost\s*>",
            text,
            re.IGNORECASE | re.DOTALL,
        ):
            block = match.group(1)
            domains = []
            for line in block.splitlines():
                directive = re.match(r"\s*(ServerName|ServerAlias)\s+(.+?)\s*$", line, re.IGNORECASE)
                if directive:
                    domains.extend(directive.group(2).split())
            domains = [name for name in domains if "$" not in name]
            if not domains:
                continue
            version = php_version_in(block)
            for domain in domains:
                results.add((domain, version or "", path))
    return sorted(results)


def main():
    parser = argparse.ArgumentParser(
        description="Pemeriksaan read-only versi PHP per domain di cPanel/WHM, Nginx, atau Apache."
    )
    parser.add_argument(
        "--config-dir",
        action="append",
        dest="config_dirs",
        help="Direktori konfigurasi tambahan (dapat digunakan lebih dari sekali).",
    )
    args = parser.parse_args()

    whm_entries = collect_whm_vhosts()
    if whm_entries:
        rows = []
        for domain, label, source in whm_entries:
            version = actual_version(label)
            rows.append((domain, label, version, classify(version), source))
    else:
        roots = list(DEFAULT_CONFIG_DIRS)
        if args.config_dirs:
            roots.extend(args.config_dirs)
        parsed = parse_configs(roots)
        rows = []
        for domain, label, source in parsed:
            version = actual_version(label) if label != "" else None
            rows.append((domain, label or "-", version or "-", classify(version), source))

    if not rows:
        print("Tidak menemukan vhost dengan konfigurasi yang dapat dibaca.")
        print("Coba jalankan sebagai root atau tambahkan direktori dengan --config-dir.")
        return 1

    print(f"{'DOMAIN':36} {'LABEL':14} {'PHP':12} {'STATUS':43} SUMBER")
    print("-" * 130)
    for domain, label, version, status, source in rows:
        print(f"{domain[:36]:36} {label[:14]:14} {version:12} {status[:43]:43} {source}")
    print()
    print("Pemeriksaan ini hanya membaca konfigurasi; tidak mengirim request ke situs.")
    print("Status mengikuti batas versi yang dicantumkan README proyek; konfirmasikan dengan advisori resmi PHP/vendor.")
    print("Versi TIDAK DIKETAHUI perlu diperiksa manual, terutama jika PHP-FPM memakai TCP atau konfigurasi nonstandar.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
PY
