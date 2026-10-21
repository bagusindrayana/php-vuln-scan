#!/usr/bin/env bash
set -o pipefail

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
PHP_PATHS=()
UPLOAD_STATUSES=()
UPLOAD_SOURCES=()
SOURCES=()
FPM_VERSION_SCANNED=0
FPM_VERSION_RESULT=""
FPM_VERSION_PATH=""
RESOLVED_VERSION=""
RESOLVED_PATH=""
CLI_PHP_SCANNED=0
CLI_PHP_PATH=""
CLI_PHP_VERSION=""
CLI_PHP_STATUS=""
CLI_UPLOAD_PROGRESS=""
CLI_UPLOAD_SOURCE=""
APACHE_MOD_PHP_SCANNED=0
APACHE_MOD_PHP_DETECTED=0
TEMP_FIX_TARGETS=()
TEMP_FIX_APPLIED=()
SCAN_COMPLETED=0

declare -A VERSION_CACHE=()
declare -A PATH_CACHE=()
declare -A STATUS_CACHE=()
declare -A DOMAIN_INDEX=()
declare -A UPLOAD_STATUS_CACHE=()
declare -A UPLOAD_SOURCE_CACHE=()
declare -A TEMP_FIX_TARGET_SEEN=()

ui_color_enabled() {
    [[ -t 1 && -z "${NO_COLOR:-}" ]]
}

ui_style() {
    local code="$1" text="$2" enabled="${3:-0}"
    if [[ "$enabled" == 1 ]]; then
        printf '\033[%sm%s\033[0m' "$code" "$text"
    else
        printf '%s' "$text"
    fi
}

ui_heading() {
    local text="$1"
    if ui_color_enabled; then
        printf '\n\033[1;36m== %s ==\033[0m\n' "$text"
    else
        printf '\n== %s ==\n' "$text"
    fi
}

ui_info() {
    if ui_color_enabled; then
        printf '\033[0;37m%s\033[0m\n' "$*"
    else
        printf '%s\n' "$*"
    fi
}

ui_success() {
    if ui_color_enabled; then
        printf '\033[1;32m%s\033[0m\n' "$*"
    else
        printf '%s\n' "$*"
    fi
}

ui_warning() {
    if ui_color_enabled; then
        printf '\033[1;33m%s\033[0m\n' "$*"
    else
        printf '%s\n' "$*"
    fi
}

format_status() {
    local status="$1" enabled="${2:-0}" code=0
    case "$status" in
        AFFECTED) code=31 ;;
        FIXED) code=32 ;;
        NOT\ AFFECTED*) code=32 ;;
        VERSION\ CONFLICT|UNKNOWN*) code=33 ;;
        REQUIRES\ ADVISORY\ VERIFICATION) code=35 ;;
    esac
    if ((code)); then
        ui_style "1;${code}" "$status" "$enabled"
    else
        printf '%s' "$status"
    fi
}

format_upload_status() {
    local status="$1" enabled="${2:-0}" code=0
    case "$status" in
        ACTIVE) code=31 ;;
        DISABLED) code=32 ;;
        UNKNOWN) code=33 ;;
    esac
    if ((code)); then
        ui_style "1;${code}" "$status" "$enabled"
    else
        printf '%s' "$status"
    fi
}

print_table_status_cell() {
    local status="$1" width="$2" color="$3" text="$1" code=0 padding
    [[ "$text" == "NOT AFFECTED"* ]] && text="NOT AFFECTED"
    case "$status" in
        AFFECTED) code=31 ;;
        FIXED|"NOT AFFECTED"*) code=32 ;;
        VERSION\ CONFLICT|UNKNOWN*) code=33 ;;
        REQUIRES\ ADVISORY\ VERIFICATION) code=35 ;;
    esac
    if [[ "$color" == 1 && "$code" != 0 ]]; then
        printf '\033[1;%sm%s\033[0m' "$code" "$text"
    else
        printf '%s' "$text"
    fi
    padding=$((width - ${#text}))
    ((padding < 0)) && padding=0
    printf '%*s' "$padding" ''
}

print_table_upload_cell() {
    local status="$1" width="$2" color="$3" code=0 padding
    case "$status" in
        ACTIVE) code=31 ;;
        DISABLED) code=32 ;;
        UNKNOWN) code=33 ;;
    esac
    if [[ "$color" == 1 && "$code" != 0 ]]; then
        printf '\033[1;%sm%s\033[0m' "$code" "$status"
    else
        printf '%s' "$status"
    fi
    padding=$((width - ${#status}))
    ((padding < 0)) && padding=0
    printf '%*s' "$padding" ''
}

usage() {
    cat <<'EOF'
Interactive PHP version and exposure check per domain for cPanel/WHM, Nginx, and Apache.

Usage:
  sudo bash check-php.sh [--config-dir DIRECTORY ...]

Bash plus standard system utilities. WHM JSON is read with jq or Perl JSON::PP.

Menu:
  1. Scan domains and PHP versions
  2. Apply temporary session.upload_progress mitigation
  3. Update installed PHP 8.2+ packages
  4. View or save the report after a scan
  5. Exit
EOF
}

while (($#)); do
    case "$1" in
        --config-dir)
            if (($# < 2)); then
                echo "The --config-dir option requires a path." >&2
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
            echo "Unknown argument: $1" >&2
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

resolve_php() {
    local label="$1" hint executable output digits fpm_version
    RESOLVED_VERSION=""
    RESOLVED_PATH=""

    if [[ ${VERSION_CACHE[$label]+present} ]]; then
        RESOLVED_VERSION="${VERSION_CACHE[$label]}"
        RESOLVED_PATH="${PATH_CACHE[$label]-}"
        return
    fi

    hint="$(php_version_from_label "$label" || true)"

    if [[ "$label" == "apache-mod-php" ]]; then
        # Apache mod_php does not expose its PHP version in a vhost directive.
        # The default CLI binary is the best local fallback and is shown as such.
        detect_default_cli_php
        if [[ -n "$CLI_PHP_VERSION" ]]; then
            RESOLVED_VERSION="$CLI_PHP_VERSION"
            RESOLVED_PATH="$CLI_PHP_PATH (Apache mod_php fallback)"
        fi
    elif [[ "$label" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        RESOLVED_VERSION="$label"
    else
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
            if [[ "$executable" == *php-fpm* ]]; then
                output="$("$executable" -v 2>/dev/null | head -n 1 || true)"
                if [[ "$output" =~ PHP[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+) ]]; then
                    RESOLVED_VERSION="${BASH_REMATCH[1]}"
                    RESOLVED_PATH="$executable"
                    break
                fi
            else
                output="$("$executable" -r 'echo PHP_VERSION;' 2>/dev/null || true)"
                if [[ "$output" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    RESOLVED_VERSION="$output"
                    RESOLVED_PATH="$executable"
                    break
                fi
            fi
        done

        if [[ -z "$RESOLVED_VERSION" ]]; then
            fpm_version="$(running_fpm_version || true)"
            if [[ "$fpm_version" =~ ^([0-9]+\.[0-9]+)\.[0-9]+$ ]]; then
                if [[ -z "$hint" || "$hint" == "${BASH_REMATCH[1]}" ]]; then
                    RESOLVED_VERSION="$fpm_version"
                    RESOLVED_PATH="$FPM_VERSION_PATH"
                fi
            fi
        fi

        [[ -n "$RESOLVED_VERSION" || -z "$hint" ]] || RESOLVED_VERSION="$hint"
    fi

    VERSION_CACHE["$label"]="$RESOLVED_VERSION"
    PATH_CACHE["$label"]="$RESOLVED_PATH"
}

resolve_version() {
    resolve_php "$1"
    printf '%s\n' "$RESOLVED_VERSION"
}

running_fpm_version() {
    local pid comm executable output version versions=" " found="" seen_executables=" "
    if ((FPM_VERSION_SCANNED)); then
        [[ -n "$FPM_VERSION_RESULT" ]] && printf '%s\n' "$FPM_VERSION_RESULT"
        return
    fi
    FPM_VERSION_SCANNED=1

    command -v ps >/dev/null 2>&1 || return 1
    [[ -d /proc ]] || return 1

    while read -r pid comm; do
        [[ "$pid" =~ ^[0-9]+$ && "$comm" == *php-fpm* ]] || continue
        executable="$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)"
        [[ -x "$executable" ]] || continue
        case "$seen_executables" in
            *" $executable "*) continue ;;
        esac
        seen_executables+="$executable "
        output="$("$executable" -v 2>/dev/null | head -n 1 || true)"
        if [[ "$output" =~ PHP[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+) ]]; then
            version="${BASH_REMATCH[1]}"
            case "$versions" in
                *" $version "*) ;;
                *)
                    versions+="$version "
                    if [[ -n "$found" ]]; then
                        found="multiple"
                    else
                        found="$version"
                        FPM_VERSION_PATH="$executable"
                    fi
                    ;;
            esac
        fi
    done < <(ps -eo pid=,comm= 2>/dev/null)

    [[ "$found" != multiple ]] || return 1
    if [[ -n "$found" ]]; then
        FPM_VERSION_RESULT="$found"
        printf '%s\n' "$found"
    fi
}

classify_version() {
    local version="$1" major minor patch
    if [[ "$version" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
        major=$((10#${BASH_REMATCH[1]}))
        minor=$((10#${BASH_REMATCH[2]}))
        patch=$((10#${BASH_REMATCH[3]}))
    else
        echo "UNKNOWN"
        return
    fi

    if ((major < 5 || (major == 5 && minor < 4))); then
        echo "NOT AFFECTED (below project version boundary)"
    elif ((major < 8 || (major == 8 && minor < 2))); then
        echo "AFFECTED"
    elif ((major == 8 && minor == 2)); then
        ((patch < 35)) && echo "AFFECTED" || echo "FIXED"
    elif ((major == 8 && minor == 3)); then
        ((patch < 36)) && echo "AFFECTED" || echo "FIXED"
    elif ((major == 8 && minor == 4)); then
        ((patch < 27)) && echo "AFFECTED" || echo "FIXED"
    elif ((major == 8 && minor == 5)); then
        ((patch < 12)) && echo "AFFECTED" || echo "FIXED"
    else
        echo "REQUIRES ADVISORY VERIFICATION"
    fi
}

php_path_from_endpoint() {
    local endpoint="$1" path lower
    [[ -n "$endpoint" ]] || return
    lower="${endpoint,,}"

    if [[ "$lower" == *__apache_mod_php__* ||
          "$lower" == *application/x-httpd-php* ]]; then
        # resolve_php supplies the CLI path and explicitly labels it as a fallback.
        return
    fi

    if [[ "$endpoint" == *unix:* ]]; then
        path="${endpoint#*unix:}"
        path="${path%%|*}"
        path="${path%% *}"
        path="${path%%\"*}"
        path="${path%%;*}"
        printf 'unix:%s\n' "$path"
        return
    fi

    printf '%s\n' "$endpoint"
}

php_label_from_endpoint() {
    local endpoint="$1" lower
    lower="${endpoint,,}"
    if [[ "$lower" == *__apache_mod_php__* ||
          "$lower" == *application/x-httpd-php* ||
          "$lower" == *libphp*.so* ||
          "$lower" == *mod_php* ]]; then
        printf '%s\n' "apache-mod-php"
        return
    fi
    php_version_from_label "$endpoint" || true
}

find_php_fpm_executable() {
    local label="$1" endpoint="$2" resolved_path="$3"
    local hint digits executable
    local candidates=()

    if [[ "$resolved_path" == *php-fpm* && -x "${resolved_path%% (*}" ]]; then
        printf '%s\n' "${resolved_path%% (*}"
        return
    fi

    hint="$(php_version_from_label "$endpoint" || true)"
    if [[ "$label" =~ ^ea-php([0-9]{2,3})$ ]]; then
        digits="${BASH_REMATCH[1]}"
        candidates+=(
            "/opt/cpanel/$label/root/usr/sbin/php-fpm"
            "/opt/cpanel/$label/root/usr/bin/php-fpm"
        )
    elif [[ "$hint" =~ ^[0-9]+\.[0-9]+$ ]]; then
        digits="${hint/./}"
        candidates+=(
            "/usr/sbin/php-fpm$hint"
            "/usr/sbin/php-fpm$digits"
            "/usr/bin/php-fpm$hint"
            "/usr/bin/php-fpm$digits"
            "/usr/local/sbin/php-fpm$hint"
            "/usr/local/sbin/php-fpm$digits"
            "/opt/remi/php$digits/root/usr/sbin/php-fpm"
            "/opt/remi/php$digits/root/usr/bin/php-fpm"
        )
    fi

    for executable in "${candidates[@]}"; do
        [[ -x "$executable" ]] && { printf '%s\n' "$executable"; return; }
    done

    if [[ -n "$FPM_VERSION_PATH" && -x "$FPM_VERSION_PATH" ]]; then
        printf '%s\n' "$FPM_VERSION_PATH"
    fi
}

run_with_timeout() {
    if command -v timeout >/dev/null 2>&1; then
        timeout 5 "$@"
    else
        "$@"
    fi
}

probe_upload_progress() {
    local executable="$1" cache_key output value source
    UPLOAD_RESULT="UNKNOWN"
    UPLOAD_SOURCE=""
    executable="${executable%% (*}"
    cache_key="$executable"

    if [[ ${UPLOAD_STATUS_CACHE[$cache_key]+present} ]]; then
        UPLOAD_RESULT="${UPLOAD_STATUS_CACHE[$cache_key]}"
        UPLOAD_SOURCE="${UPLOAD_SOURCE_CACHE[$cache_key]-}"
        return
    fi

    if [[ ! -x "$executable" ]]; then
        UPLOAD_STATUS_CACHE["$cache_key"]="UNKNOWN"
        UPLOAD_SOURCE_CACHE["$cache_key"]="No executable found"
        UPLOAD_SOURCE="No executable found"
        return
    fi

    if [[ "$executable" == *php-fpm* ]]; then
        output="$(run_with_timeout "$executable" -i 2>/dev/null || true)"
        value="$(printf '%s\n' "$output" | awk '$1 == "session.upload_progress.enabled" {print $NF; exit}')"
        source="PHP-FPM: $executable"
    else
        value="$(run_with_timeout "$executable" -r 'echo ini_get("session.upload_progress.enabled");' 2>/dev/null || true)"
        source="PHP CLI/mod_php fallback: $executable"
    fi

    case "${value,,}" in
        1|on|true|yes) UPLOAD_RESULT="ACTIVE" ;;
        0|off|false|no) UPLOAD_RESULT="DISABLED" ;;
        *) UPLOAD_RESULT="UNKNOWN" ;;
    esac
    UPLOAD_SOURCE="$source"
    UPLOAD_STATUS_CACHE["$cache_key"]="$UPLOAD_RESULT"
    UPLOAD_SOURCE_CACHE["$cache_key"]="$UPLOAD_SOURCE"
}

check_upload_progress() {
    local label="$1" endpoint="$2" resolved_path="$3"
    local executable="" endpoint_lower
    endpoint_lower="${endpoint,,}"

    if [[ "$label" == "apache-mod-php" ||
          "$endpoint_lower" == *__apache_mod_php__* ||
          "$endpoint_lower" == *application/x-httpd-php* ]]; then
        executable="${resolved_path%% (*}"
    elif [[ "$endpoint_lower" == *fcgi* || "$endpoint_lower" == *fpm* ||
          "$endpoint_lower" == *unix:* || "$label" =~ ^ea-php[0-9]+$ ]]; then
        executable="$(find_php_fpm_executable "$label" "$endpoint" "$resolved_path" || true)"
    elif [[ -x "$resolved_path" ]]; then
        executable="$resolved_path"
    fi

    if [[ -n "$executable" ]]; then
        probe_upload_progress "$executable"
    else
        UPLOAD_RESULT="UNKNOWN"
        UPLOAD_SOURCE="No PHP runtime executable could be mapped"
    fi
}

show_scan_progress() {
    local current="$1" total="$2" filled=0 width=30 bar="" i percent
    ((total > 0)) || return
    percent=$((current * 100 / total))
    filled=$((current * width / total))
    for ((i = 0; i < filled; i++)); do bar+="#"; done
    for ((i = filled; i < width; i++)); do bar+="-"; done

    if ui_color_enabled; then
        printf '\r\033[2K  Scanning domains: [%s] %d/%d (%d%%)' "$bar" "$current" "$total" "$percent"
        ((current == total)) && printf '\n'
    elif ((current == 1 || current == total || current % 25 == 0)); then
        printf '  Scanning domains: %d/%d (%d%%)\n' "$current" "$total" "$percent"
    fi
}

show_collection_progress() {
    local current="$1"
    if ui_color_enabled; then
        printf '\r\033[2K  Collecting configuration records: %d file(s)' "$current"
    elif ((current == 1 || current % 25 == 0)); then
        printf '  Collecting configuration records: %d file(s)\n' "$current"
    fi
}

add_domain() {
    local domain="$1" label="$2" source="$3" path_hint="${4:-}"
    local version status path upload_status upload_source version_key i
    [[ -n "$domain" ]] || return

    resolve_php "$label"
    version="$RESOLVED_VERSION"
    path="${path_hint:-$RESOLVED_PATH}"
    check_upload_progress "$label" "$path_hint" "$RESOLVED_PATH"
    upload_status="$UPLOAD_RESULT"
    upload_source="$UPLOAD_SOURCE"
    version_key="${version:-__unknown__}"
    if [[ ${STATUS_CACHE[$version_key]+present} ]]; then
        status="${STATUS_CACHE[$version_key]}"
    else
        status="$(classify_version "$version")"
        STATUS_CACHE["$version_key"]="$status"
    fi

    if [[ ${DOMAIN_INDEX[$domain]+present} ]]; then
        i="${DOMAIN_INDEX[$domain]}"
        if [[ "${VERSIONS[$i]}" == "-" && -n "$version" ]]; then
            LABELS[$i]="${label:-unknown}"
            VERSIONS[$i]="$version"
            STATUSES[$i]="$status"
            UPLOAD_STATUSES[$i]="$upload_status"
            UPLOAD_SOURCES[$i]="$upload_source"
            SOURCES[$i]="$source"
        elif [[ "${VERSIONS[$i]}" != "-" && -n "$version" &&
                "${VERSIONS[$i]}" != "$version" ]]; then
            LABELS[$i]="conflict"
            VERSIONS[$i]="conflict"
            STATUSES[$i]="VERSION CONFLICT"
            SOURCES[$i]="${SOURCES[$i]}, $source"
        fi
        [[ -n "$path" && ( -z "${PHP_PATHS[$i]}" || "${PHP_PATHS[$i]}" == "-" ) ]] && PHP_PATHS[$i]="$path"
        if [[ "${UPLOAD_STATUSES[$i]}" == "UNKNOWN" && "$upload_status" != "UNKNOWN" ]]; then
            UPLOAD_STATUSES[$i]="$upload_status"
            UPLOAD_SOURCES[$i]="$upload_source"
        fi
        return
    fi

    i="${#DOMAINS[@]}"
    DOMAIN_INDEX["$domain"]="$i"
    DOMAINS+=("$domain")
    LABELS+=("${label:-unknown}")
    VERSIONS+=("${version:--}")
    STATUSES+=("$status")
    PHP_PATHS+=("${path:--}")
    UPLOAD_STATUSES+=("$upload_status")
    UPLOAD_SOURCES+=("$upload_source")
    SOURCES+=("$source")
}

parse_whm_json() {
    local jq_cmd="$1"
    if [[ -n "$jq_cmd" ]]; then
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
        '
        return
    fi

    if command -v perl >/dev/null 2>&1 &&
       perl -MJSON::PP -e 1 >/dev/null 2>&1; then
        perl -MJSON::PP -e '
            use strict;
            use warnings;

            sub walk {
                my ($node) = @_;
                if (ref($node) eq "HASH") {
                    my %normalized = map { lc($_) => $_ } keys %{$node};
                    my ($host_key) = grep { exists $normalized{$_} }
                        qw(vhost domain servername host);
                    my ($version_key) = grep { exists $normalized{$_} }
                        qw(version php_version phpversion);

                    if (defined($host_key) && defined($version_key)) {
                        my $host = $node->{$normalized{$host_key}};
                        my $version = $node->{$normalized{$version_key}};
                        if (!ref($host) && !ref($version)) {
                            print "$host\t$version\n";
                        }
                    }
                    walk($_) for values %{$node};
                } elsif (ref($node) eq "ARRAY") {
                    walk($_) for @{$node};
                }
            }

            local $/;
            my $json = <STDIN>;
            my $data = decode_json($json);
            walk($data);
        '
        return
    fi

    echo "Neither jq nor Perl JSON::PP is available to parse the WHM API JSON response." >&2
    echo "Install jq or ensure Perl JSON::PP is available; local configuration scanning is skipped." >&2
    return 1
}

collect_whm() {
    local whmapi jq_cmd json parsed domain label i total processed
    local whm_domains=() whm_labels=()
    whmapi="$(command -v whmapi1 2>/dev/null || true)"
    jq_cmd="$(command -v jq 2>/dev/null || true)"
    if [[ -z "$jq_cmd" && -x /usr/local/cpanel/3rdparty/bin/jq ]]; then
        jq_cmd=/usr/local/cpanel/3rdparty/bin/jq
    fi
    if [[ -z "$whmapi" ]]; then
        return 1
    fi
    if ! command -v timeout >/dev/null 2>&1; then
        echo "Info: the timeout utility is unavailable; skipping WHM API to avoid an unbounded wait." >&2
        return 1
    fi
    echo "  Fetching the domain list from the WHM API (30-second limit)..."
    json="$(timeout 30 "$whmapi" --output=json php_get_vhost_versions 2>/dev/null)" || {
        echo "Warning: the WHM API failed or exceeded 30 seconds; local configuration will be used." >&2
        return 1
    }
    parsed="$(printf '%s\n' "$json" | parse_whm_json "$jq_cmd")" || {
        echo "Failed to parse the WHM API JSON response." >&2
        return 1
    }
    while IFS=$'\t' read -r domain label; do
        [[ -n "$domain" && -n "$label" ]] || continue
        whm_domains+=("$domain")
        whm_labels+=("$label")
    done <<< "$parsed"
    total="${#whm_domains[@]}"
    if ((total == 0)); then
        echo "The WHM API responded, but its format produced no domain/version records." >&2
        echo "Falling back to local configuration scanning." >&2
        return 1
    fi
    echo "  Detected $total domain record(s); checking PHP runtime settings..."
    processed=0
    for i in "${!whm_domains[@]}"; do
        domain="${whm_domains[$i]}"
        label="${whm_labels[$i]}"
        add_domain "$domain" "$label" "WHM API"
        processed=$((processed + 1))
        show_scan_progress "$processed" "$total"
    done
    return 0
}

detect_apache_mod_php() {
    local control modules
    ((APACHE_MOD_PHP_SCANNED)) && return
    APACHE_MOD_PHP_SCANNED=1

    for control in apachectl apache2ctl httpd; do
        command -v "$control" >/dev/null 2>&1 || continue
        modules="$("$control" -M 2>/dev/null || true)"
        if [[ "$modules" =~ [Pp][Hh][Pp].*[Mm]odule ||
              "$modules" =~ [Ll]ib[Pp][Hh][Pp] ]]; then
            APACHE_MOD_PHP_DETECTED=1
            return
        fi
    done
}

scan_configs() {
    local config domain endpoint source label path_hint directory apache_mod_php
    local records_file file_count=0 total=0 processed=0
    declare -A scan_domain_seen=()
    declare -A processed_domain_seen=()
    detect_apache_mod_php
    apache_mod_php="$APACHE_MOD_PHP_DETECTED"
    records_file="$(mktemp "${TMPDIR:-/tmp}/check-php-records.XXXXXX" 2>/dev/null || true)"
    if [[ -z "$records_file" ]]; then
        ui_warning "Could not create a temporary scan record file."
        return 1
    fi

    for directory in "${CONFIG_DIRS[@]}"; do
        [[ -d "$directory" ]] || continue
        echo "  Reading configuration files under: $directory"
        while IFS= read -r -d '' config; do
            file_count=$((file_count + 1))
            show_collection_progress "$file_count"
            awk -v apache_mod_php="$apache_mod_php" '
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
                    lower_line = tolower(line)
                    if ((lower_line ~ /loadmodule/ && lower_line ~ /(php|libphp)/) ||
                        lower_line ~ /(addhandler|sethandler|addtype).*application\/x-httpd-php/)
                        apache_global_php = 1
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
                            if (endpoint == "" && (apache_global_php || apache_mod_php == 1))
                                endpoint = " __APACHE_MOD_PHP__"
                            else if (tolower(endpoint) ~ /application\/x-httpd-php/)
                                endpoint = " __APACHE_MOD_PHP__ " endpoint
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
            ' "$config" |
                while IFS=$'\t' read -r domain endpoint; do
                    [[ -n "$domain" ]] || continue
                    printf '%s\t%s\t%s\n' "$domain" "$endpoint" "$config"
                done >> "$records_file"
        done < <(
            find "$directory" \
                \( -type d \( -name logs -o -name cache -o -name tmp -o -name backup -o -name backups \) -prune \) -o \
                \( -type f \( -name '*.conf' -o -name nginx.conf -o -name httpd.conf \) -print0 \) \
                2>/dev/null
        )
    done

    ui_color_enabled && printf '\n'
    while IFS=$'\t' read -r domain endpoint source; do
        [[ -n "$domain" ]] || continue
        if [[ ${scan_domain_seen[$domain]+present} ]]; then
            continue
        fi
        scan_domain_seen["$domain"]=1
        total=$((total + 1))
    done < "$records_file"

    if ((total == 0)); then
        rm -f "$records_file"
        return 0
    fi
    echo "  Detected $total unique domain(s); checking PHP runtime settings..."
    while IFS=$'\t' read -r domain endpoint source; do
        [[ -n "$domain" ]] || continue
        label="$(php_label_from_endpoint "$endpoint" || true)"
        path_hint="$(php_path_from_endpoint "$endpoint" || true)"
        add_domain "$domain" "${label:-unknown}" "$source" "$path_hint"
        if [[ -z ${processed_domain_seen[$domain]+present} ]]; then
            processed_domain_seen["$domain"]=1
            processed=$((processed + 1))
            show_scan_progress "$processed" "$total"
        fi
    done < "$records_file"
    rm -f "$records_file"
}

detect_default_cli_php() {
    ((CLI_PHP_SCANNED)) && return
    CLI_PHP_SCANNED=1
    CLI_PHP_PATH="$(command -v php 2>/dev/null || true)"
    if [[ -z "$CLI_PHP_PATH" || ! -x "$CLI_PHP_PATH" ]]; then
        CLI_UPLOAD_PROGRESS="UNKNOWN"
        CLI_UPLOAD_SOURCE="No default CLI PHP executable found"
        return
    fi

    CLI_PHP_VERSION="$("$CLI_PHP_PATH" -r 'echo PHP_VERSION;' 2>/dev/null || true)"
    if [[ ! "$CLI_PHP_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        CLI_PHP_VERSION="$("$CLI_PHP_PATH" -v 2>/dev/null | head -n 1 || true)"
        if [[ "$CLI_PHP_VERSION" =~ PHP[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+) ]]; then
            CLI_PHP_VERSION="${BASH_REMATCH[1]}"
        else
            CLI_PHP_VERSION=""
        fi
    fi
    CLI_PHP_STATUS="$(classify_version "$CLI_PHP_VERSION")"
    probe_upload_progress "$CLI_PHP_PATH"
    CLI_UPLOAD_PROGRESS="$UPLOAD_RESULT"
    CLI_UPLOAD_SOURCE="$UPLOAD_SOURCE"
}

server_summary() {
    local os_name="Unknown" cli_status cli_upload_status color=0
    if [[ -r /etc/os-release ]]; then
        os_name="$(. /etc/os-release; printf '%s' "${PRETTY_NAME:-${NAME:-Unknown}}")"
    fi
    detect_default_cli_php

    echo "Hostname       : $(hostname 2>/dev/null || uname -n)"
    echo "Operating system: $os_name"
    echo "Kernel          : $(uname -sr 2>/dev/null || echo 'Unknown')"
    if [[ -n "$CLI_PHP_PATH" ]]; then
        echo "Default CLI PHP : ${CLI_PHP_VERSION:--}"
        echo "CLI PHP path    : $CLI_PHP_PATH"
        cli_status="${CLI_PHP_STATUS:-UNKNOWN}"
        ui_color_enabled && color=1
        printf 'CLI PHP status  : %s\n' "$(format_status "$cli_status" "$color")"
        cli_upload_status="${CLI_UPLOAD_PROGRESS:-UNKNOWN}"
        printf 'CLI upload.progress: %s\n' "$(format_upload_status "$cli_upload_status" "$color")"
        echo "CLI upload source : ${CLI_UPLOAD_SOURCE:--}"
    else
        echo "Default CLI PHP : not installed"
        echo "CLI PHP path    : -"
        echo "CLI PHP status  : UNKNOWN"
        echo "CLI upload.progress: UNKNOWN"
        echo "CLI upload source : -"
    fi
    if command -v whmapi1 >/dev/null 2>&1; then
        echo "Control panel   : cPanel/WHM detected"
    else
        echo "Control panel   : cPanel/WHM not detected"
    fi
    local found=0 service state
    for service in nginx httpd apache2; do
        if command -v systemctl >/dev/null 2>&1; then
            state="$(systemctl is-active "$service" 2>/dev/null || true)"
            if [[ "$state" == active ]]; then
                echo "Web server      : $service (active)"
                found=1
            fi
        fi
    done
    ((found)) || echo "Web server      : service status not detected"
    echo "Scan time       : $(date '+%Y-%m-%d %H:%M:%S %z')"
}

version_at_least_82() {
    local version="$1" major minor
    [[ "$version" =~ ^([0-9]+)\.([0-9]+) ]] || return 1
    major=$((10#${BASH_REMATCH[1]}))
    minor=$((10#${BASH_REMATCH[2]}))
    ((major > 8 || (major == 8 && minor >= 2)))
}

add_temp_fix_target() {
    local directory="$1"
    [[ -d "$directory" ]] || return
    if [[ ${TEMP_FIX_TARGET_SEEN[$directory]+present} ]]; then
        return
    fi
    TEMP_FIX_TARGET_SEEN["$directory"]=1
    TEMP_FIX_TARGETS+=("$directory/99-session-upload-progress-disable.ini")
}

discover_temp_fix_targets() {
    local root directory ini_dir
    TEMP_FIX_TARGETS=()
    TEMP_FIX_TARGET_SEEN=()

    for directory in \
        /etc/php.d \
        /usr/local/etc/php/conf.d \
        /etc/php/*/cli/conf.d \
        /etc/php/*/fpm/conf.d \
        /etc/php/*/apache2/conf.d \
        /etc/opt/remi/php*/php.d \
        /opt/remi/php*/root/etc/php.d \
        /opt/cpanel/ea-php*/root/etc/php.d; do
        add_temp_fix_target "$directory"
    done

    for root in /etc/php /etc/opt/remi /opt/remi; do
        [[ -d "$root" ]] || continue
        while IFS= read -r -d '' directory; do
            add_temp_fix_target "$directory"
        done < <(find "$root" -type d \( -name conf.d -o -name php.d \) -print0 2>/dev/null)
    done

    detect_default_cli_php
    if [[ -n "$CLI_PHP_PATH" ]]; then
        while IFS= read -r ini_dir; do
            add_temp_fix_target "$ini_dir"
        done < <(
            "$CLI_PHP_PATH" --ini 2>/dev/null |
                awk -F': ' '/Scan for additional \.ini files in:/ {print $2}'
        )
    fi
}

restart_runtime_services() {
    local service
    local services=()

    if ! command -v systemctl >/dev/null 2>&1; then
        ui_warning "systemctl is unavailable; restart PHP/web services manually for the change to take effect."
        return 1
    fi

    while IFS= read -r service; do
        [[ -n "$service" ]] || continue
        services+=("$service")
    done < <(
        systemctl list-units --type=service --state=active --no-legend 2>/dev/null |
            awk '$1 ~ /^(php.*fpm|httpd|apache2)\.service$/ {print $1}'
    )

    if ((${#services[@]} == 0)); then
        ui_warning "No active PHP-FPM or Apache/httpd service was found. Restart it manually if needed."
        return 1
    fi

    for service in "${services[@]}"; do
        ui_info "Restarting $service..."
        if systemctl restart "$service"; then
            ui_success "$service restarted."
        else
            ui_warning "Could not restart $service."
        fi
    done
}

offer_runtime_restart() {
    local answer
    read -r -p "Restart active PHP-FPM/Apache services now? [y/N] " answer
    case "${answer,,}" in
        y|yes) restart_runtime_services ;;
        *) ui_info "Services were not restarted; restart them before relying on the change." ;;
    esac
}

apply_temporary_fix() {
    local target directory temporary_file answer
    local applied=0 skipped=0
    local content='; Temporary mitigation managed by check-php.sh
; Disable PHP session upload progress until PHP packages are updated.
session.upload_progress.enabled = 0
'

    if ((EUID != 0)); then
        ui_warning "Temporary mitigation requires root privileges."
        return 1
    fi

    discover_temp_fix_targets
    if ((${#TEMP_FIX_TARGETS[@]} == 0)); then
        ui_warning "No PHP conf.d/php.d directory was found. No configuration was changed."
        return 1
    fi

    ui_heading "TEMPORARY MITIGATION"
    echo "The following drop-in files will disable session.upload_progress.enabled:"
    for target in "${TEMP_FIX_TARGETS[@]}"; do
        echo "  - $target"
    done
    read -r -p "Create or update these mitigation files? [y/N] " answer
    case "${answer,,}" in
        y|yes) ;;
        *) ui_info "Temporary mitigation cancelled."; return 0 ;;
    esac

    for target in "${TEMP_FIX_TARGETS[@]}"; do
        directory="${target%/*}"
        if [[ -e "$target" ]]; then
            if grep -Eq '^[[:space:]]*session\.upload_progress\.enabled[[:space:]]*=[[:space:]]*0([[:space:]]*;.*)?$' "$target" 2>/dev/null; then
                ui_info "Already disabled: $target"
                skipped=$((skipped + 1))
            else
                ui_warning "Skipped existing file with different content: $target"
                skipped=$((skipped + 1))
            fi
            continue
        fi

        temporary_file="$(mktemp "$target.tmp.XXXXXX" 2>/dev/null || true)"
        if [[ -z "$temporary_file" ]]; then
            ui_warning "Could not create a temporary file in $directory."
            continue
        fi
        if printf '%s' "$content" >"$temporary_file" && chmod 0644 "$temporary_file" && mv -f "$temporary_file" "$target"; then
            ui_success "Created: $target"
            TEMP_FIX_APPLIED+=("$target")
            applied=$((applied + 1))
        else
            rm -f "$temporary_file"
            ui_warning "Could not create: $target"
        fi
    done

    if ((applied > 0)); then
        echo "Applied files: $applied; skipped files: $skipped."
        offer_runtime_restart
    else
        ui_info "No new mitigation file was created."
    fi
}

collect_apt_php_packages() {
    local package name version major minor
    while IFS= read -r package; do
        [[ -n "$package" ]] || continue
        name="${package%%:*}"
        if [[ "$name" =~ ^php([0-9]+)\.([0-9]+)(-|$) ]]; then
            major=$((10#${BASH_REMATCH[1]}))
            minor=$((10#${BASH_REMATCH[2]}))
            ((major > 8 || (major == 8 && minor >= 2))) && printf '%s\n' "$package"
        elif [[ "$name" =~ ^php(-|$) || "$name" =~ ^libapache2-mod-php(-|$) ]]; then
            printf '%s\n' "$package"
        fi
    done < <(dpkg-query -W -f='${binary:Package}\n' 2>/dev/null | sort -u)
}

collect_rpm_php_packages() {
    local package major minor
    while IFS= read -r package; do
        [[ -n "$package" ]] || continue
        if [[ "$package" =~ ^php([0-9])([0-9])-php ]]; then
            major=$((10#${BASH_REMATCH[1]}))
            minor=$((10#${BASH_REMATCH[2]}))
            ((major > 8 || (major == 8 && minor >= 2))) && printf '%s\n' "$package"
        elif [[ "$package" =~ ^php(-|$) ]]; then
            printf '%s\n' "$package"
        fi
    done < <(rpm -qa --qf '%{NAME}\n' 2>/dev/null | sort -u)
}

update_php_packages() {
    local manager answer package_list package name major minor package_supports_82=0
    local packages=()

    if ((EUID != 0)); then
        ui_warning "PHP package updates require root privileges."
        return 1
    fi

    detect_default_cli_php

    if command -v apt-get >/dev/null 2>&1 && command -v dpkg-query >/dev/null 2>&1; then
        manager="apt"
        package_list="$(collect_apt_php_packages)"
    elif command -v dnf >/dev/null 2>&1 && command -v rpm >/dev/null 2>&1; then
        manager="dnf"
        package_list="$(collect_rpm_php_packages)"
    elif command -v yum >/dev/null 2>&1 && command -v rpm >/dev/null 2>&1; then
        manager="yum"
        package_list="$(collect_rpm_php_packages)"
    else
        ui_warning "No supported package manager was found. Supported managers: apt, dnf, and yum."
        return 1
    fi

    while IFS= read -r package; do
        [[ -n "$package" ]] && packages+=("$package")
    done <<< "$package_list"
    if ((${#packages[@]} == 0)); then
        ui_warning "No installed PHP 8.2+ packages were found for update."
        return 1
    fi

    if version_at_least_82 "$CLI_PHP_VERSION"; then
        package_supports_82=1
    else
        for package in "${packages[@]}"; do
            name="${package%%:*}"
            if [[ "$name" =~ ^php([0-9]+)\.([0-9]+)(-|$) ]]; then
                major=$((10#${BASH_REMATCH[1]}))
                minor=$((10#${BASH_REMATCH[2]}))
                if ((major > 8 || (major == 8 && minor >= 2))); then
                    package_supports_82=1
                fi
            elif [[ "$name" =~ ^php([0-9])([0-9])-php ]]; then
                major=$((10#${BASH_REMATCH[1]}))
                minor=$((10#${BASH_REMATCH[2]}))
                if ((major > 8 || (major == 8 && minor >= 2))); then
                    package_supports_82=1
                fi
            fi
        done
    fi
    if ((package_supports_82 == 0)); then
        ui_warning "No PHP 8.2+ runtime was detected. The update was cancelled."
        return 1
    fi

    ui_heading "PHP PACKAGE UPDATE"
    echo "Detected default CLI PHP: $CLI_PHP_VERSION"
    echo "Package manager: $manager"
    echo "Packages selected for upgrade:"
    for package in "${packages[@]}"; do
        echo "  - $package"
    done
    echo
    echo "The update may restart services through the package manager."
    read -r -p "Continue with the PHP package update? [y/N] " answer
    case "${answer,,}" in
        y|yes) ;;
        *) ui_info "PHP package update cancelled."; return 0 ;;
    esac

    case "$manager" in
        apt)
            apt-get update && apt-get install -y --only-upgrade "${packages[@]}"
            ;;
        dnf)
            dnf upgrade -y "${packages[@]}"
            ;;
        yum)
            yum update -y "${packages[@]}"
            ;;
    esac
    if (($? != 0)); then
        ui_warning "PHP package update failed. Review the package manager output above."
        return 1
    fi

    CLI_PHP_SCANNED=0
    detect_default_cli_php
    ui_success "PHP package update completed. Detected CLI PHP: ${CLI_PHP_VERSION:--}"
    SCAN_COMPLETED=0
    offer_runtime_restart
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
    local upload_active=0 upload_disabled=0 upload_unknown=0
    local i status version upload_status count seen color
    color=0
    ui_color_enabled && color=1
    ui_heading "PHP EXPOSURE REPORT"
    echo "Generated       : $(date '+%Y-%m-%d %H:%M:%S %z')"
    server_summary
    echo "Detected domains: $total"
    echo
    printf '%-4s %-28s %-14s %-14s %-38s %-18s %-42s %s\n' \
        "#" "DOMAIN / WEB" "LABEL" "PHP VERSION" "STATUS" "UPLOAD.PROGRESS" "PHP PATH / ENDPOINT" "SOURCE"
    printf '%s\n' "------------------------------------------------------------------------------------------------------------------------------------------------------------------------------"
    for i in "${!DOMAINS[@]}"; do
        status="${STATUSES[$i]}"
        upload_status="${UPLOAD_STATUSES[$i]}"
        printf '%-4d %-28.28s %-14.14s %-14.14s ' \
            "$((i + 1))" "${DOMAINS[$i]}" "${LABELS[$i]}" "${VERSIONS[$i]}"
        print_table_status_cell "$status" 38 "$color"
        printf ' '
        print_table_upload_cell "$upload_status" 18 "$color"
        printf ' %-42.42s %s\n' "${PHP_PATHS[$i]}" "${SOURCES[$i]}"
        case "$status" in
            AFFECTED) affected=$((affected + 1)) ;;
            FIXED) fixed=$((fixed + 1)) ;;
            "NOT AFFECTED"*) not_affected=$((not_affected + 1)) ;;
            *) unknown=$((unknown + 1)) ;;
        esac
        case "$upload_status" in
            ACTIVE) upload_active=$((upload_active + 1)) ;;
            DISABLED) upload_disabled=$((upload_disabled + 1)) ;;
            *) upload_unknown=$((upload_unknown + 1)) ;;
        esac
    done

    ui_heading "DOMAIN STATUS SUMMARY"
    draw_bar "Affected" "$affected" "$total"
    draw_bar "Fixed" "$fixed" "$total"
    draw_bar "Not affected" "$not_affected" "$total"
    draw_bar "Unknown / conflict / verify" "$unknown" "$total"

    ui_heading "SESSION.UPLOAD_PROGRESS SUMMARY"
    draw_bar "Active" "$upload_active" "$total"
    draw_bar "Disabled" "$upload_disabled" "$total"
    draw_bar "Unknown / runtime not mapped" "$upload_unknown" "$total"

    ui_heading "PHP VERSION SUMMARY"
    seen=" "
    for i in "${!DOMAINS[@]}"; do
        version="${VERSIONS[$i]}"
        [[ "$seen" == *" $version "* ]] && continue
        seen+="$version "
        count=0
        for status in "${VERSIONS[@]}"; do
            [[ "$status" == "$version" ]] && count=$((count + 1))
        done
        draw_bar "PHP ${version:--}" "$count" "$total"
    done

    ui_heading "NOTES"
    echo "- Status uses the project version thresholds; verify against the official PHP/vendor advisory."
    echo "- Socket labels usually reveal only the minor version, not the patch version."
    echo "- For Apache mod_php, the default CLI PHP path/version is used as a local fallback."
    echo "- UPLOAD.PROGRESS is checked from the mapped PHP CLI or PHP-FPM runtime and cached per executable."
    echo "- The check reads local/WHM configuration and does not send requests to domains."
}

show_welcome() {
    if ui_color_enabled; then
        printf '\033[1;36m+--------------------------------------------------------------+\033[0m\n'
        printf '\033[1;36m|       PHP VERSION / CVE EXPOSURE CHECK (READ-ONLY)        |\033[0m\n'
        printf '\033[1;36m+--------------------------------------------------------------+\033[0m\n'
    else
        echo "+--------------------------------------------------------------+"
        echo "|       PHP VERSION / CVE EXPOSURE CHECK (READ-ONLY)        |"
        echo "+--------------------------------------------------------------+"
    fi
    ui_heading "PROJECT CONTEXT"
    echo "CVE-2026-109618 / CVE-2026-109619 are associated with"
    echo "PHP session.upload_progress and related attack paths."
    echo "Session injection plus LFI requires an application with an"
    echo "include/LFI path; a PHP version alone does not prove exploitability."
    ui_heading "SCAN SCOPE"
    echo "The script maps domains/websites to PHP versions using the WHM API"
    echo "when available, or Nginx/Apache virtual-host configuration files."
    echo "It is read-only: no exploit and no network request to a domain is made."
    ui_heading "SERVER SUMMARY"
    server_summary
    echo
}

reset_scan_state() {
    DOMAINS=()
    LABELS=()
    VERSIONS=()
    STATUSES=()
    PHP_PATHS=()
    UPLOAD_STATUSES=()
    UPLOAD_SOURCES=()
    SOURCES=()
    VERSION_CACHE=()
    PATH_CACHE=()
    STATUS_CACHE=()
    DOMAIN_INDEX=()
    UPLOAD_STATUS_CACHE=()
    UPLOAD_SOURCE_CACHE=()
    FPM_VERSION_SCANNED=0
    FPM_VERSION_RESULT=""
    FPM_VERSION_PATH=""
    SCAN_COMPLETED=0
}

run_scan() {
    reset_scan_state
    ui_heading "SCANNING WHM / NGINX / APACHE"
    if command -v whmapi1 >/dev/null 2>&1; then
        if ! collect_whm; then
            scan_configs
        fi
    else
        scan_configs
    fi

    if ((${#DOMAINS[@]} == 0)); then
        echo "No domains could be read." >&2
        if command -v whmapi1 >/dev/null 2>&1; then
            echo "The WHM API produced no records; local configuration scanning also found no domains." >&2
            echo "Verify the WHM API, jq/Perl JSON::PP, and the configured paths." >&2
        else
            echo "Run as root or add a configuration location with --config-dir." >&2
        fi
        return 1
    fi

    SCAN_COMPLETED=1
    ui_success "Scan completed: ${#DOMAINS[@]} domain(s) detected."
    render_report
}

show_report() {
    local save_answer report_file
    if ((SCAN_COMPLETED == 0)); then
        ui_warning "Run option 1 (Scan) before opening a report."
        return 1
    fi

    render_report
    echo
    read -r -p "Save the report to a file? [Y/n] " save_answer
    case "${save_answer,,}" in
        n|no)
            echo "Report was not saved."
            ;;
        *)
            report_file="php-cve-report-$(date '+%Y%m%d-%H%M%S').txt"
            if render_report >"$report_file"; then
                ui_success "Report saved: $report_file"
            else
                ui_warning "Failed to save report: $report_file"
                return 1
            fi
            ;;
    esac
}

main_menu() {
    local choice
    while true; do
        ui_heading "MAIN MENU"
        echo "1. Scan domains and PHP versions"
        echo "2. Apply temporary fix (disable session.upload_progress)"
        echo "3. Update installed PHP 8.2+ packages"
        if ((SCAN_COMPLETED)); then
            echo "4. View/save report"
        else
            echo "4. View/save report (scan required)"
        fi
        echo "5. Exit"
        echo
        read -r -p "Select an option [1-5]: " choice || return 0
        case "$choice" in
            1) run_scan ;;
            2) apply_temporary_fix ;;
            3) update_php_packages ;;
            4) show_report ;;
            5) ui_info "Exiting."; return 0 ;;
            *) ui_warning "Invalid selection. Choose a number from 1 to 5." ;;
        esac
    done
}

show_welcome
main_menu
