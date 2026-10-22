#!/bin/bash
# Bounded, dependency-light PHP discovery. Bash 4+, GNU find/coreutils, awk,
# tar/gzip and flock (util-linux); no Python, jq, compiler or PHP execution.
# YARA text parsing follows the Apache-2.0 Rapid Response scanner approach.
set -euo pipefail
export LC_ALL=C
umask 077
engine= rules= output= archive= engine_sha256= archive_sha256=
enumeration_seconds=1200 scan_seconds=900 max_files=5000000 candidate_gb=30
max_file_mb=512 cpu_limit=10 include_build_text=0 include_broader_locations=0 include_nonstandard_names=0
roots=()
exclude_directories_hex=x
while (($#)); do
    (($# >= 2)) || { echo 'Missing argument' >&2; exit 2; }
    case "$1" in
        --engine) engine=$2;; --engine-sha256) engine_sha256=$2;; --rules) rules=$2;; --output) output=$2;;
        --archive) archive=$2;; --archive-sha256) archive_sha256=$2;; --root) roots+=("$2");;
        --enumeration-seconds) enumeration_seconds=$2;; --scan-seconds) scan_seconds=$2;;
        --max-files) max_files=$2;; --candidate-gb) candidate_gb=$2;; --max-file-mb) max_file_mb=$2;;
        --cpu-limit) cpu_limit=$2;; --include-build-text) include_build_text=$2;;
        --include-broader-locations) include_broader_locations=$2;; --include-nonstandard-names) include_nonstandard_names=$2;;
        --exclude-directories-hex) exclude_directories_hex=$2;;
        *) echo 'Unknown argument' >&2; exit 2;;
    esac
    shift 2
done
for name in enumeration_seconds scan_seconds max_files candidate_gb max_file_mb cpu_limit include_build_text include_broader_locations include_nonstandard_names; do
    [[ ${!name} =~ ^[0-9]{1,9}$ ]] || { echo "Invalid $name" >&2; exit 2; }
done
((enumeration_seconds>=1 && enumeration_seconds<=3600 && scan_seconds>=1 && scan_seconds<=3600 && max_files>=1 && max_files<=5000000 && candidate_gb>=1 && candidate_gb<=100 && max_file_mb>=1 && max_file_mb<=2048 && cpu_limit>=1 && cpu_limit<=99 && include_build_text<=1 && include_broader_locations<=1 && include_nonstandard_names<=1)) || exit 2
[[ $output = /* && $engine = /* && $rules = /* ]] || exit 2
missing=()
for command in find timeout stat od awk sort sha256sum tar gzip flock date mkdir mv chmod dirname mkfifo cp nice cat head tr; do
    command -v "$command" >/dev/null 2>&1 || missing+=("$command")
done
((${#missing[@]}==0)) || { printf 'Missing required utilities: %s\n' "${missing[*]}" >&2; exit 2; }
# Reject symlink output ancestors and insecure output ownership. Never change
# permissions on an unrelated directory and never follow an output redirect.
current=$output
while [[ $current != / ]]; do [[ ! -L $current ]] || exit 2; current=${current%/*}; [[ -n $current ]] || current=/; done
mkdir -p -- "$output"
[[ $(stat -c %u -- "$output") = "$EUID" ]] || exit 2
mode=$(stat -c %a -- "$output"); (( (8#$mode & 0022)==0 )) || { echo 'Output directory is writable by another account' >&2; exit 2; }
for leaf in scan.lock scan.log scan.log.new summary.txt summary.txt.new; do [[ ! -L $output/$leaf ]] || exit 2; done
exec 9>"$output/scan.lock"
flock -n 9 || exit 75
work=$(dirname -- "$engine")
[[ -d $work && ! -L $work ]] || exit 2
started=$(date -u '+%Y-%m-%d %H:%M:%S UTC'); start_seconds=$SECONDS
finished=0 find_pid= scan_pid=
failure() {
    result=$?
    trap - EXIT
    if [[ -n $find_pid ]]; then kill "$find_pid" 2>/dev/null || :; wait "$find_pid" 2>/dev/null || :; fi
    if [[ -n $scan_pid ]]; then kill "$scan_pid" 2>/dev/null || :; wait "$scan_pid" 2>/dev/null || :; fi
    if (( !finished )); then
        printf '\nScan failed (exit %s); previous finished results retained.\n' "$result" >>"$output/scan.log"
        if [[ -f $output/summary.txt ]]; then
            awk '/^LAST_SCAN=/{sub(/ \(Last attempt failed.*/, ""); print $0 " (Last attempt failed; see scan.log)"; next} {print}' "$output/summary.txt" >"$output/summary.txt.new"
        else printf 'DETECTED=FALSE\nLAST_SCAN=NO SCAN (Last attempt failed; see scan.log)\nDURATION=NO SCAN\n' >"$output/summary.txt.new"; fi
        mv -f -- "$output/summary.txt.new" "$output/summary.txt"
    fi
    exit "$result"
}
trap failure EXIT
trap 'exit 130' INT TERM
printf 'PHP scan started: %s\nStandard names: %s; build text: %s; broader locations: %s\n' "$started" "$((1-include_nonstandard_names))" "$include_build_text" "$include_broader_locations" >"$output/scan.log"
exec 2>>"$output/scan.log"
# Decode only validated byte pairs. Paths are never shell code, printf formats or
# evaluated expressions. GNU find gets quoted regex arguments with literal syntax
# escaped; only '*' is a wildcard. Directory pruning happens before any file read.
[[ ${#exclude_directories_hex} -le 8193 && $exclude_directories_hex =~ ^x([0-9a-fA-F]{2})*$ ]] || { echo 'Invalid encoded exclusions' >&2; exit 2; }
exclusion_text=
for ((i=1;i<${#exclude_directories_hex};i+=2)); do
    pair=${exclude_directories_hex:i:2}
    [[ $pair != 00 ]] || { echo 'NUL in exclusions' >&2; exit 2; }
    printf -v character '%b' "\\x$pair"; exclusion_text+=$character
done
[[ $exclusion_text != *[[:cntrl:]]* ]] || { echo 'Control character in exclusions' >&2; exit 2; }
custom_trees=(); custom_direct=(); custom_patterns=()
IFS=',' read -r -a exclusion_entries <<<"$exclusion_text"
for pattern in "${exclusion_entries[@]}"; do
    pattern="${pattern#"${pattern%%[![:space:]]*}"}"; pattern="${pattern%"${pattern##*[![:space:]]}"}"
    [[ -n $pattern ]] || continue
    ((${#custom_patterns[@]}<32)) || { echo 'At most 32 exclusions allowed' >&2; exit 2; }
    [[ $pattern = /* || $pattern = \*/* ]] || { echo 'Linux exclusions need an absolute path or leading */' >&2; exit 2; }
    [[ ! /$pattern/ =~ /\.\.?/ ]] || { echo 'Relative path segments are not allowed' >&2; exit 2; }
    while [[ $pattern = *//* ]]; do pattern=${pattern//\/\//\/}; done
    while [[ $pattern = *\*\** ]]; do pattern=${pattern//\*\*/\*}; done
    custom_patterns+=("$pattern")
    recursive=0; basis=$pattern
    if [[ $basis = */\* ]]; then recursive=1; basis=${basis%/\*}; fi
    while [[ $basis = */ ]]; do basis=${basis%/}; done
    expression=
    for ((i=0;i<${#basis};i++)); do
        character=${basis:i:1}
        case "$character" in
            '*') expression+='.*';;
            '.'|'['|']'|'('|')'|'{'|'}'|'+'|'?'|'^'|'$'|'|'|'\') expression+="\\$character";;
            *) expression+=$character;;
        esac
    done
    if ((recursive)); then custom_trees+=("$expression(/.*)?"); else custom_direct+=("$expression/[^/]+"); fi
    printf 'Custom directory exclusion: %s\n' "$pattern" >>"$output/scan.log"
done
hash() { sha256sum -- "$1" | awk '{print $1}'; }
[[ $(hash "$rules") = 0f68f1276f3d50db3dcba06fd1d8089e157fbc8e60bcca49ac1e7b2dde664615 ]] || { echo 'Rule hash mismatch' >&2; exit 2; }
if [[ ! -f $engine ]]; then
    [[ -f $archive && $(hash "$archive") = "$archive_sha256" ]] || { echo 'Archive hash mismatch' >&2; exit 2; }
    # Extract only the pinned executable to a controlled filename; no archive paths.
    tar -xOzf "$archive" yr >"$engine"
    chmod 700 -- "$engine"
fi
[[ $(hash "$engine") = "$engine_sha256" ]] || { echo 'Engine hash mismatch' >&2; exit 2; }
prune=(/proc /sys /dev /run /var/lib/docker /var/lib/containers /var/lib/containerd /var/lib/rancher /var/lib/lxc /var/lib/lxd /var/snap/lxd /.snapshots /timeshift "$output")
if [[ ${output##*/} = YARA_PHP ]]; then prune+=("${output%/*}/__BESData"); fi
if (( !include_broader_locations )); then prune+=(/boot /lost+found /var/log /var/cache /var/backups /var/crash); fi
if ((${#roots[@]}==0)); then
    # Enumerate only local filesystems and deduplicate bind mounts by device/root.
    # Octal-escaped mount paths are decoded by printf, never by eval.
    while IFS= read -r mount; do
        printf -v mount '%b' "$mount"
        case "$mount" in *$'\n'*|*$'\r'*|*$'\t'*) echo 'Unusual mount path excluded' >&2; continue;; esac
        roots+=("$mount")
    done < <(awk '{for(i=7;i<=NF;i++)if($i=="-"){fs=$(i+1);break} if(fs ~ /^(ext[234]|xfs|btrfs|zfs|f2fs|jfs|reiserfs|bcachefs|vfat|exfat|ntfs3)$/ || (fs=="tmpfs" && ($5=="/tmp" || $5=="/var/tmp"))) {key=$3 ":" $4; if(!seen[key]++)print $5}}' /proc/self/mountinfo)
fi
((${#roots[@]})) || { echo 'No supported local filesystem found' >&2; exit 2; }
name_expression=( '(' -iname 'php*' -o -iname 'libphp*' -o -iname 'mod_php*' -o -iname 'lsphp*' -o -iname 'frankenphp*' ')' )
((include_nonstandard_names)) && name_expression=()
prune_expression=( '(' -false )
for directory in "${prune[@]}"; do prune_expression+=( -o -path "$directory" ); done
prune_expression+=( -o -path '*/.local/share/containers' -o -name '.snapshots' )
for expression in "${custom_trees[@]}"; do prune_expression+=( -o '(' -type d -regex "$expression" ')' ); done
if ((!include_broader_locations)); then prune_expression+=( -o -path '*/.cache' -o -path '*/.npm/_cacache' -o -path '*/.nuget/packages' ); fi
prune_expression+=( ')' -prune -o )
direct_expression=()
for expression in "${custom_direct[@]}"; do direct_expression+=( '!' -regex "$expression" ); done
list=$work/candidates.txt; raw=$work/results.txt; errors=$work/engine.stderr; fifo=$work/find.pipe
: >"$list"; : >"$raw"; : >"$errors"
[[ ! -e $fifo && ! -L $fifo ]] || exit 2
mkfifo -- "$fifo"
mkdir -- "$work/staged"
declare -A original_paths
reasons=(); files=0; candidates=0; bytes=0; size_skipped=0; structural_skipped=0; read_errors=0
deadline=$((SECONDS+enumeration_seconds))
# A timeout covers blocked directory reads. Streaming NUL records preserves path
# bytes and avoids a huge on-disk inventory; the FIFO provides backpressure.
timeout -k 5 "$enumeration_seconds" find "${roots[@]}" -regextype posix-extended -xdev -ignore_readdir_race "${prune_expression[@]}" -type f "${name_expression[@]}" "${direct_expression[@]}" -printf '%s\0%p\0' >"$fifo" 2>"$work/find.stderr" &
find_pid=$!
while IFS= read -r -d '' -t "$enumeration_seconds" size && IFS= read -r -d '' -t 5 path; do
    if ((SECONDS>=deadline || files>=max_files)); then reasons+=('file search limit'); break; fi
    files=$((files+1)); leaf=${path##*/}; lower=${leaf,,}
    if ((!include_nonstandard_names)); then
        [[ $lower =~ ^(php|phpdbg|libphp|mod_php|lsphp|frankenphp)([0-9][0-9.]*([-_][a-z0-9_.-]+)?|[-_][a-z0-9_.-]+)?(ts|nts|apache[0-9_]*)?(\.exe|\.dll|\.so(\.[0-9]+)*)?$ ]] || continue
        case "$lower" in
            php-config|php_version.h) ((include_build_text)) || continue;;
            *.*) extension=${lower##*.}; [[ $extension = exe || $extension = dll || $extension = so || $extension =~ ^[0-9][a-z0-9_-]*$ ]] || continue;;
        esac
    fi
    if [[ $lower = php-config || $lower = php_version.h ]]; then ((include_build_text)) || continue; fi
    if ((!include_broader_locations)); then case "$lower" in *.db|*.sqlite|*.sqlite3|*.bak|*.dump|*.dmp|*.iso|*.vhd|*.vhdx|*.vmdk|*.wim|*.esd) continue;; esac; fi
    if ((size>=max_file_mb*1048576)); then size_skipped=$((size_skipped+1)); continue; fi
    # Stat/find never opens devices or FIFOs. Recheck after enumeration before
    # reading, because an application can replace its file during a scan.
    [[ -f $path && ! -L $path ]] || continue
    if ! header=$(timeout -k 1 2 od -An -tx1 -N20 -- "$path" 2>/dev/null | tr -d ' \n'); then
        [[ -e $path ]] && read_errors=$((read_errors+1)); continue
    fi
    binary=0
    case "$header" in
        7f454c46*)
            # ELF ET_REL/ET_CORE cannot be a live PHP executable/shared runtime.
            elf_type=${header:32:4}
            if [[ $elf_type = 0100 || $elf_type = 0001 || $elf_type = 0400 || $elf_type = 0004 ]]; then structural_skipped=$((structural_skipped+1)); continue; fi
            binary=1;;
        4d5a*|cefaedfe*|cffaedfe*|feedface*|feedfacf*|cafebabe*) binary=1;;
    esac
    if ((!binary)); then ((include_build_text && size<65536)) || continue; fi
    if ((bytes+size>candidate_gb*1073741824)); then reasons+=('total candidate size limit'); break; fi
    # YARA scan lists are UTF-8 and newline-separated. Stage unusual raw-byte
    # paths to ASCII names; preserve a reversible Bash-quoted path for reporting.
    scan_path=$path
    if [[ $path = *[!\ -\~]* ]]; then
        scan_path=$work/staged/$candidates
        if ! timeout -k 2 "$((deadline-SECONDS>0 ? deadline-SECONDS : 1))" cp --reflink=auto -- "$path" "$scan_path"; then read_errors=$((read_errors+1)); continue; fi
        printf -v quoted '%q' "$path"; original_paths["$scan_path"]=$quoted
    fi
    printf '%s\n' "$scan_path" >>"$list"
    candidates=$((candidates+1)); bytes=$((bytes+size))
done <"$fifo"
if ((${#reasons[@]})); then kill "$find_pid" 2>/dev/null || :; fi
find_rc=0; wait "$find_pid" || find_rc=$?; find_pid=
if ((find_rc!=0)); then reasons+=('file search incomplete'); fi
if [[ -s $work/find.stderr ]]; then reasons+=('unreadable locations'); fi
((size_skipped==0)) || reasons+=('file size limit')
((read_errors==0)) || reasons+=('unreadable files')
scan_start=$SECONDS
if ((candidates)); then
    runner=(nice -n 10)
    # Idle I/O is optional, never a prerequisite that can suppress detection.
    if command -v ionice >/dev/null 2>&1 && ionice -c 3 true 2>/dev/null; then runner+=(ionice -c 3); fi
    (ulimit -f 65536; exec timeout -k 5 "$((scan_seconds+15))" "${runner[@]}" "$engine" scan --scan-list --print-strings --output-format text --threads 2 --cpu-limit "$cpu_limit" --timeout "$scan_seconds" --max-matches-per-pattern 64 "$rules" "$list") >"$raw" 2>"$errors" &
    scan_pid=$!; scan_rc=0; wait "$scan_pid" || scan_rc=$?; scan_pid=
    ((scan_rc==0)) || reasons+=('YARA time/output/error limit')
    [[ ! -s $errors ]] || reasons+=('YARA warnings or unreadable files')
fi
# Parse the engine's documented text output, not shell code or executable PHP.
awk '
 /^PHP_/ {rule=$1; file=$0; sub(/^[^ ]+ /,"",file); seen[file]=1; if(rule=="PHP_Runtime_Version")core[file]=1; if(rule=="PHP_Build_Artifact")build[file]=1; next}
 /:\$(ver|pv|cfg_ver|hdr_ver): / {v=$0; gsub(/\\x00/,"",v); sub(/^[^ ]+ /,"",v); if(match(v,/[0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.+~_-]*/)) {v=substr(v,RSTART,RLENGTH); if(rule=="PHP_Runtime_Version")runtime[file SUBSEP v]=1; else evidence[file SUBSEP v]=1}}
 END {for(k in runtime){split(k,a,SUBSEP);print a[1] "\truntime\t" a[2]} for(k in evidence){split(k,a,SUBSEP);if(!core[a[1]])print a[1] "\tevidence\t" a[2]} for(f in seen)if(!core[f] && !build[f]) print f "\tunconfirmed\tunknown"}
' "$raw" | sort -u >"$work/versions.tsv"
vulnerable=0; unknown=0; findings=0
: >"$work/vulnerable.txt"
while IFS=$'\t' read -r path kind version; do
    [[ -n $path ]] || continue
    findings=$((findings+1))
    display=${original_paths[$path]-$path}
    printf 'Finding: %s | %s | PHP %s\n' "$display" "$kind" "$version" >>"$output/scan.log"
    if [[ $kind != runtime ]]; then
        # Build evidence is expected only in the opt-in mode. Unknown runtime
        # versions remain a visible qualification in the last-scan property.
        [[ $kind != unconfirmed ]] || unknown=$((unknown+1))
        continue
    fi
    [[ $version =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)(.*)$ ]] || { unknown=$((unknown+1)); continue; }
    major=${BASH_REMATCH[1]}; minor=${BASH_REMATCH[2]}; patch=${BASH_REMATCH[3]}; suffix=${BASH_REMATCH[4]}
    fixed=0 affected=0
    case "$major.$minor" in 8.2) fixed=35;; 8.3) fixed=36;; 8.4) fixed=27;; 8.5) fixed=12;; esac
    if ((fixed)); then
        if ((patch<fixed)) || { ((patch==fixed)) && [[ $suffix =~ ^(alpha|beta|RC|dev) ]]; }; then affected=1; fi
    elif (( (major==5 && minor>=4) || major==7 || (major==8 && minor<2) )); then affected=1
    else unknown=$((unknown+1)); fi
    if ((affected)); then
        vulnerable=$((vulnerable+1))
        printf '%s | PHP %s\n' "$display" "$version" >>"$work/vulnerable.txt"
    fi
done <"$work/versions.tsv"
((unknown==0)) || reasons+=('unconfirmed PHP version/runtime')
elapsed=$((SECONDS-start_seconds))
printf -v duration '%s hours, %s minutes, %s seconds' "$((elapsed/3600))" "$((elapsed%3600/60))" "$((elapsed%60))"
completed=$(date -u '+%Y-%m-%d %H:%M:%S UTC'); last_scan=$completed
if ((${#reasons[@]})); then last_scan+=" (Partial: $(IFS=', '; echo "${reasons[*]}"); see scan.log)"; fi
if ((vulnerable>100)); then last_scan+=' (first 100 paths shown; all paths in scan.log)'; fi
{
    printf '\nCompleted: %s\nDuration: %s\nFiles considered: %s\nCandidates: %s\nCandidate bytes: %s\nOver size limit: %s\nRead errors: %s\nStructural skips: %s\nFindings: %s\nUpstream-affected runtime paths: %s\n' "$completed" "$duration" "$files" "$candidates" "$bytes" "$size_skipped" "$read_errors" "$structural_skipped" "$findings" "$vulnerable"
    printf 'Limits: search %ss; YARA %ss; files %s; individual file %s MiB; candidate input %s GiB; CPU %s%%\n' "$enumeration_seconds" "$scan_seconds" "$max_files" "$max_file_mb" "$candidate_gb" "$cpu_limit"
    printf 'Result: %s\n' "$last_scan"
    printf 'TRUE means upstream-affected runtime detected; vendor backports and web exposure require verification. FALSE means none detected within this scope.\n'
    head -c 32768 -- "$work/find.stderr" "$errors"
} >>"$output/scan.log"
{
    if ((vulnerable)); then echo DETECTED=TRUE; else echo DETECTED=FALSE; fi
    printf 'LAST_SCAN=%s\nDURATION=%s\n' "$last_scan" "$duration"
    awk 'NR<=100 {if(length($0)>900)$0=substr($0,1,870) "...[full path in scan.log]"; print "VULNERABLE=" $0}' "$work/vulnerable.txt"
} >"$output/summary.txt.new"
mv -f -- "$output/summary.txt.new" "$output/summary.txt"
finished=1
if ((${#reasons[@]})); then exit 10; fi
