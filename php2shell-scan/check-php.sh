#!/usr/bin/env bash
set -uo pipefail

DEFAULT_CONFIG_DIRS=(
    /etc/nginx
    /etc/apache2
    /etc/httpd
    /usr/local/apache/conf
    /usr/local/etc/nginx
    /opt/cpanel/ea-nginx
)
CONFIG_DIRS=("${DEFAULT_CONFIG_DIRS[@]}")
DOMAINS=()
LABELS=()
VERSIONS=()
STATUSES=()
SOURCES=()

usage() {
    cat <<'EOF'
Pemeriksaan interaktif versi PHP per domain untuk cPanel/WHM, Nginx, dan Apache.

Penggunaan:
  sudo bash check-php.sh [--config-dir DIREKTORI ...]

Pure Bash + utilitas sistem (awk/find/grep). jq dipakai bila tersedia untuk
membaca WHM API; tanpa jq, skrip mencoba membaca konfigurasi web server.
EOF
}

while (($#)); do
    case "$1" in
        --config-dir)
            if (($# < 2)); then
                echo "Argumen --config-dir memerlukan path." >&2
                exit 2
            fi
            CONFIG_DIRS+=("$2")
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Argumen tidak dikenal: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

php_version_from_label() {
    local label="${1,,}" digits
    if [[ "$label" =~ ([0-9]+)\.([0-9]+)\.([0-9]+) ]]; then
        printf '%s.%s.%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"
    elif [[ "$label" =~ ^([0-9]+)\.([0-9]+)$ ]]; then
        printf '%d.%d\n' "$((10#${BASH_REMATCH[1]}))" "$((10#${BASH_REMATCH[2]}))"
    elif [[ "$label" =~ ea-php([0-9]{2,3}) ]]; then
        digits="${BASH_REMATCH[1]}"
        printf '%d.%d\n' "$((10#${digits:0:${#digits}-1}))" "$((10#${digits: -1}))"
    elif [[ "$label" =~ php([0-9]+)\.([0-9]+) ]]; then
        printf '%d.%d\n' "$((10#${BASH_REMATCH[1]}))" "$((10#${BASH_REMATCH[2]}))"
    elif [[ "$label" =~ php([0-9]{2,3})(-fpm|[^0-9]|$) ]]; then
        digits="${BASH_REMATCH[1]}"
        printf '%d.%d\n' "$((10#${digits:0:${#digits}-1}))" "$((10#${digits: -1}))"
    fi
}

resolve_version() {
    local label="$1" hint executable output digits
    hint="$(php_version_from_label "$label" || true)"

    if [[ "$label" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        printf '%s\n' "$label"
        return
    fi

    local candidates=()
    if [[ "$label" =~ ^ea-php([0-9]{2,3})$ ]]; then
        candidates+=("/opt/cpanel/$label/root/usr/bin/php" "/usr/local/bin/$label")
    elif [[ "$hint" =~ ^[0-9]+\.[0-9]+$ ]]; then
        candidates+=("/usr/bin/php$hint" "/usr/local/bin/php$hint")
        digits="${hint/./}"
        candidates+=("/usr/sbin/php-fpm$hint" "/usr/sbin/php-fpm$digits")
    fi

    for executable in "${candidates[@]}"; do
        [[ -x "$executable" ]] || continue
        if [[ "$(basename "$executable")" == *php-fpm* ]]; then
            output="$("$executable" -v 2>/dev/null | head -n 1 || true)"
            if [[ "$output" =~ PHP[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+) ]]; then
                printf '%s\n' "${BASH_REMATCH[1]}"
                return
            fi
        else
            output="$("$executable" -r 'echo PHP_VERSION;' 2>/dev/null || true)"
            if [[ "$output" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                printf '%s\n' "$output"
                return
            fi
        fi
    done

    [[ -n "$hint" ]] && printf '%s\n' "$hint"
}

classify_version() {
    local version="$1" major minor patch
    if [[ "$version" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
        major=$((10#${BASH_REMATCH[1]}))
        minor=$((10#${BASH_REMATCH[2]}))
        patch=$((10#${BASH_REMATCH[3]}))
    else
        echo "TIDAK DIKETAHUI"
        return
    fi

    if ((major < 5 || (major == 5 && minor < 4))); then
        echo "TIDAK TERDAMPAK (batas versi proyek)"
    elif ((major < 8 || (major == 8 && minor < 2))); then
        echo "TERDAMPAK"
    elif ((major == 8 && minor == 2)); then
        ((patch < 35)) && echo "TERDAMPAK" || echo "SUDAH DIPERBAIKI"
    elif ((major == 8 && minor == 3)); then
        ((patch < 36)) && echo "TERDAMPAK" || echo "SUDAH DIPERBAIKI"
    elif ((major == 8 && minor == 4)); then
        ((patch < 27)) && echo "TERDAMPAK" || echo "SUDAH DIPERBAIKI"
    elif ((major == 8 && minor == 5)); then
        ((patch < 12)) && echo "TERDAMPAK" || echo "SUDAH DIPERBAIKI"
    else
        echo "PERLU VERIFIKASI ADVISORI"
    fi
}

add_domain() {
    local domain="$1" label="$2" source="$3" version status i
    [[ -n "$domain" ]] || return
    version="$(resolve_version "$label")"
    status="$(classify_version "$version")"
    for i in "${!DOMAINS[@]}"; do
        if [[ "${DOMAINS[$i]}" == "$domain" ]]; then
            if [[ "${VERSIONS[$i]}" == "-" && "$version" != "" ]]; then
                LABELS[$i]="${label:-unknown}"
                VERSIONS[$i]="$version"
                STATUSES[$i]="$status"
                SOURCES[$i]="$source"
            elif [[ "${VERSIONS[$i]}" != "-" && "$version" != "" &&
                    "${VERSIONS[$i]}" != "$version" ]]; then
                LABELS[$i]="conflict"
                VERSIONS[$i]="conflict"
                STATUSES[$i]="KONFLIK VERSI"
                SOURCES[$i]="${SOURCES[$i]}, $source"
            fi
            return
        fi
    done
    DOMAINS+=("$domain")
    LABELS+=("${label:-unknown}")
    VERSIONS+=("${version:--}")
    STATUSES+=("$status")
    SOURCES+=("$source")
}

collect_whm() {
    local whmapi jq_cmd json domain label
    whmapi="$(command -v whmapi1 2>/dev/null || true)"
    jq_cmd="$(command -v jq 2>/dev/null || true)"
    if [[ -z "$jq_cmd" && -x /usr/local/cpanel/3rdparty/bin/jq ]]; then
        jq_cmd=/usr/local/cpanel/3rdparty/bin/jq
    fi
    [[ -n "$whmapi" && -n "$jq_cmd" ]] || return 1

    json="$("$whmapi" --output=json php_get_vhost_versions 2>/dev/null)" || {
        echo "Peringatan: WHM API tidak berhasil; mencoba konfigurasi lokal." >&2
        return 1
    }
    while IFS=$'\t' read -r domain label; do
        [[ -n "$domain" && -n "$label" ]] || continue
        add_domain "$domain" "$label" "WHM API"
    done < <(
        printf '%s\n' "$json" |
            "$jq_cmd" -r '
                .. | objects
                | select(
                    (.vhost? // .domain? // .servername? // .host?) != null
                    and (.version? // .php_version? // .phpversion?) != null
                )
                | [
                    (.vhost // .domain // .servername // .host),
                    (.version // .php_version // .phpversion)
                  ]
                | @tsv
            ' 2>/dev/null
    )
    ((${#DOMAINS[@]} > 0))
}

scan_configs() {
    local config domain endpoint label
    while IFS= read -r -d '' config; do
        while IFS=$'\t' read -r domain endpoint; do
            [[ -n "$domain" ]] || continue
            label="$(php_version_from_label "$endpoint" || true)"
            add_domain "$domain" "${label:-unknown}" "$config"
        done < <(
            awk '
                function flush_nginx(    names, endpoint, i, n, fields) {
                    if (block == "") return
                    names = ""
                    endpoint = ""
                    n = split(block, lines, "\n")
                    for (i = 1; i <= n; i++) {
                        line = lines[i]
                        sub(/#.*/, "", line)
                        if (line ~ /^[[:space:]]*server_name[[:space:]]/) {
                            sub(/^[[:space:]]*server_name[[:space:]]+/, "", line)
                            sub(/[;].*$/, "", line)
                            names = names " " line
                        }
                        if (line ~ /^[[:space:]]*fastcgi_pass[[:space:]]/) {
                            sub(/^[[:space:]]*fastcgi_pass[[:space:]]+/, "", line)
                            sub(/[;[:space:]].*$/, "", line)
                            endpoint = endpoint " " line
                        }
                    }
                    n = split(names, fields, /[[:space:]]+/)
                    for (i = 1; i <= n; i++)
                        if (fields[i] != "" && fields[i] != "_" && fields[i] !~ /\$/)
                            print fields[i] "\t" endpoint
                    block = ""
                }
                {
                    line = $0
                    sub(/#.*/, "", line)
                    if (!in_server && line ~ /^[[:space:]]*server[[:space:]]*\{/) {
                        in_server = 1
                        depth = 0
                        block = ""
                    }
                    if (in_server) {
                        block = block line "\n"
                        opens = gsub(/\{/, "{", line)
                        closes = gsub(/\}/, "}", line)
                        depth += opens - closes
                        if (depth <= 0) {
                            flush_nginx()
                            in_server = 0
                        }
                    }
                    if (tolower(line) ~ /^[[:space:]]*<virtualhost([[:space:]>])/) {
                        in_vhost = 1
                        apache = ""
                    }
                    if (in_vhost) {
                        apache = apache line "\n"
                        if (tolower(line) ~ /^[[:space:]]*<\/virtualhost[[:space:]]*>/) {
                            names = ""
                            endpoint = ""
                            n = split(apache, lines, "\n")
                            for (i = 1; i <= n; i++) {
                                current = lines[i]
                                sub(/#.*/, "", current)
                                if (current ~ /^[[:space:]]*(ServerName|ServerAlias)[[:space:]]/) {
                                    sub(/^[[:space:]]*(ServerName|ServerAlias)[[:space:]]+/, "", current)
                                    names = names " " current
                                }
                                if (current ~ /(SetHandler|ProxyPassMatch|proxy:unix:|php[0-9])/)
                                    endpoint = endpoint " " current
                            }
                            n = split(names, fields, /[[:space:]]+/)
                            for (i = 1; i <= n; i++)
                                if (fields[i] != "" && fields[i] !~ /\$/)
                                    print fields[i] "\t" endpoint
                            in_vhost = 0
                            apache = ""
                        }
                    }
                }
                END {
                    if (in_server) flush_nginx()
                }
            ' "$config"
        )
    done < <(
        for directory in "${CONFIG_DIRS[@]}"; do
            [[ -d "$directory" ]] || continue
            find "$directory" -type f \( -name '*.conf' -o -name nginx.conf -o -name httpd.conf \) -print0 2>/dev/null
        done
    )
}

server_summary() {
    local os_name="Tidak diketahui" php_cli="Tidak terpasang"
    if [[ -r /etc/os-release ]]; then
        os_name="$(. /etc/os-release; printf '%s' "${PRETTY_NAME:-${NAME:-Tidak diketahui}}")"
    fi
    if command -v php >/dev/null 2>&1; then
        php_cli="$(php -v 2>/dev/null | head -n 1 || echo 'Tidak dapat dibaca')"
    fi

    echo "Hostname       : $(hostname 2>/dev/null || uname -n)"
    echo "OS             : $os_name"
    echo "Kernel         : $(uname -sr 2>/dev/null || echo 'Tidak diketahui')"
    echo "PHP CLI        : $php_cli"
    if command -v whmapi1 >/dev/null 2>&1; then
        echo "Panel          : cPanel/WHM terdeteksi"
    else
        echo "Panel          : cPanel/WHM tidak terdeteksi"
    fi
    local found=0 service state
    for service in nginx httpd apache2; do
        if command -v systemctl >/dev/null 2>&1; then
            state="$(systemctl is-active "$service" 2>/dev/null || true)"
            if [[ "$state" == active ]]; then
                echo "Web server     : $service (active)"
                found=1
            fi
        fi
    done
    ((found)) || echo "Web server     : status layanan tidak terdeteksi"
    echo "Waktu scan     : $(date '+%Y-%m-%d %H:%M:%S %z')"
}

draw_bar() {
    local label="$1" count="$2" total="$3" bar="" i max=40
    if ((total > 0)); then
        max=$((count * 40 / total))
        ((count > 0 && max == 0)) && max=1
    else
        max=0
    fi
    for ((i = 0; i < max; i++)); do bar+="#"; done
    printf '  %-32s %5d  %s\n' "$label" "$count" "$bar"
}

render_report() {
    local total="${#DOMAINS[@]}" affected=0 fixed=0 unknown=0 not_affected=0
    local i status version count seen
    echo "========== LAPORAN PEMERIKSAAN PHP =========="
    echo "Tanggal         : $(date '+%Y-%m-%d %H:%M:%S %z')"
    server_summary
    echo "Total domain    : $total"
    echo
    printf '%-4s %-36s %-14s %-12s %-38s %s\n' "#" "DOMAIN" "LABEL" "PHP" "STATUS" "SUMBER"
    printf '%s\n' "----------------------------------------------------------------------------------------------------------------------------------------------------------------"
    for i in "${!DOMAINS[@]}"; do
        status="${STATUSES[$i]}"
        printf '%-4d %-36.36s %-14.14s %-12.12s %-38.38s %s\n' \
            "$((i + 1))" "${DOMAINS[$i]}" "${LABELS[$i]}" "${VERSIONS[$i]}" "$status" "${SOURCES[$i]}"
        case "$status" in
            TERDAMPAK) affected=$((affected + 1)) ;;
            SUDAH\ DIPERBAIKI) fixed=$((fixed + 1)) ;;
            "TIDAK TERDAMPAK"*) not_affected=$((not_affected + 1)) ;;
            *) unknown=$((unknown + 1)) ;;
        esac
    done

    echo
    echo "Ringkasan status domain:"
    draw_bar "Terdampak (patch dapat diverifikasi)" "$affected" "$total"
    draw_bar "Sudah diperbaiki (berdasarkan ambang proyek)" "$fixed" "$total"
    draw_bar "Tidak terdampak menurut batas proyek" "$not_affected" "$total"
    draw_bar "Tidak diketahui / konflik / perlu verifikasi" "$unknown" "$total"

    echo
    echo "Ringkasan versi PHP:"
    seen=" "
    for i in "${!DOMAINS[@]}"; do
        version="${VERSIONS[$i]}"
        [[ "$seen" == *" $version "* ]] && continue
        seen+="$version "
        count=0
        for status in "${VERSIONS[@]}"; do
            [[ "$status" == "$version" ]] && count=$((count + 1))
        done
        draw_bar "PHP $version" "$count" "$total"
    done

    echo
    echo "Catatan:"
    echo "- Status menggunakan batas versi yang tercatat di proyek; verifikasi dengan advisori resmi PHP/vendor."
    echo "- Label socket biasanya hanya mengungkap versi minor, bukan patch; statusnya sengaja tidak dipastikan."
    echo "- Pemeriksaan membaca konfigurasi lokal/WHM dan tidak mengirim request ke domain."
}

show_welcome() {
    echo "=============================================================="
    echo "       PHP VERSION / CVE EXPOSURE CHECK (READ-ONLY)"
    echo "=============================================================="
    echo "Ringkasan CVE menurut catatan proyek:"
    echo "  CVE-2026-109618 / CVE-2026-109619 dikaitkan dengan"
    echo "  session.upload_progress PHP dan beberapa jalur risiko."
    echo "  Jalur session injection + LFI memerlukan aplikasi yang memiliki"
    echo "  include/LFI; versi PHP saja tidak membuktikan situs dapat dieksploitasi."
    echo
    echo "Skrip akan memeriksa pemetaan domain-ke-PHP dari WHM API (jika"
    echo "tersedia) atau konfigurasi vhost Nginx/Apache. Skrip tidak melakukan"
    echo "eksploitasi dan tidak menguji aplikasi dari jaringan."
    echo
    echo "Ringkasan server:"
    server_summary
    echo
}

show_welcome
read -r -p "Lanjutkan scan konfigurasi sekarang? [y/N] " answer
case "${answer,,}" in
    y|yes|ya)
        ;;
    *)
        echo "Scan dibatalkan."
        exit 0
        ;;
esac

echo
echo "Memindai konfigurasi WHM/Nginx/Apache..."
if ! collect_whm; then
    scan_configs
fi

if ((${#DOMAINS[@]} == 0)); then
    echo "Tidak menemukan vhost/domain dengan konfigurasi yang dapat dibaca." >&2
    echo "Jalankan sebagai root atau tambahkan lokasi konfigurasi dengan --config-dir." >&2
    exit 1
fi

echo
render_report
echo
read -r -p "Simpan report ke file? [Y/n] " save_answer
case "${save_answer,,}" in
    n|no|tidak)
        echo "Report tidak disimpan."
        ;;
    *)
        report_file="php-cve-report-$(date '+%Y%m%d-%H%M%S').txt"
        if render_report >"$report_file"; then
            echo "Report disimpan: $report_file"
        else
            echo "Gagal menyimpan report: $report_file" >&2
            exit 1
        fi
        ;;
esac
