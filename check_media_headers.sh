#!/usr/bin/env bash
#
# check_media_headers.sh
#
# READ-ONLY check for video files that are blank, truncated or corrupt.
# It never modifies, moves, renames or deletes anything in the library.
# The only file it creates is the report (which it refuses to put inside the
# library). The deeper modes run ffprobe/ffmpeg, which only READ the files;
# ffmpeg output is discarded (-f null).
#
# Usage:
#   bash check_media_headers.sh [-m MODE] [-o REPORT_FILE] [-x SKIP_DIR]...
#                               [-l LIST_FILE] [LIBRARY_DIR]
#
# Modes (-m):
#   header   (default) Reads the first 8 bytes of each file. Very fast.
#            .mkv/.webm/.mka must start with the EBML magic 1a 45 df a3.
#            .mp4/.m4v/.mov/.m4a must have a known first box (normally "ftyp").
#            Also reports empty and unreadable files.
#   probe    header check, then ffprobe opens the file and reads EVERY packet
#            (no decoding). Needs a full read of each file, so it is limited by
#            disk speed. Catches truncation and container damage mid-file.
#   full     header check, then ffmpeg decodes EVERY video and audio frame and
#            throws the result away. The most thorough, but slow: it can take
#            minutes per file on a Raspberry Pi. Best used with -l on a few files.
#
# Other options:
#   -o FILE  Report file. Default: $HOME/bad_media_files.txt
#            Format: REASON<TAB>path<TAB>detail   (detail only in probe/full)
#   -x DIR   Skip an extra folder. Repeatable. Relative paths are taken as
#            inside LIBRARY_DIR; absolute paths are used as given.
#   -l FILE  Check only the files listed in FILE (one path per line) instead
#            of walking the library. A previous report works as FILE. The
#            skip rules do not apply to a listed file.
#   -h       Help.
#
# Default library: /mnt/Media
# Always skipped:  <LIBRARY_DIR>/Incoming and any .deletedByTMM folder
#
# Reasons in the report:
#   EMPTY / UNREADABLE   zero-byte file or file that can't be read
#   BAD_HEADER           container header missing or blank
#   PROBE_ERROR          ffprobe reported an error (probe mode)
#   DECODE_ERROR         ffmpeg reported an error while decoding (full mode)
#   TOOL_ERROR           ffprobe/ffmpeg could not be run
#
# Exit code: 0 = everything OK, 1 = problems found, 2 = setup/usage error
#
# Notes:
#   * header mode only looks at the start of each file. A file with a good
#     header but damage further in will pass; use probe or full for that.
#   * ffmpeg occasionally prints an error-level message for a file that still
#     plays fine. Read the detail column before deciding to replace a file.
#   * probe/full run at low CPU and disk priority (nice/ionice) when available,
#     so Jellyfin keeps working while a scan runs.

set -u

ROOT="/mnt/Media"
REPORT="$HOME/bad_media_files.txt"
MODE="header"
LIST=""
EXTRA_EXCLUDES=()

usage() {
  cat <<EOF
Usage: bash $0 [-m header|probe|full] [-o REPORT_FILE] [-x SKIP_DIR]... [-l LIST_FILE] [LIBRARY_DIR]
  -m MODE  header (default, fast) | probe (read every packet) | full (decode everything, slow)
  -o FILE  report file (default: $REPORT)
  -x DIR   skip an extra folder (repeatable)
  -l FILE  check only the files listed in FILE
Default library: $ROOT
Always skipped: <LIBRARY_DIR>/Incoming and .deletedByTMM folders
EOF
}

while getopts ":m:o:x:l:h" opt; do
  case "$opt" in
    m) MODE=$OPTARG ;;
    o) REPORT=$OPTARG ;;
    x) EXTRA_EXCLUDES+=("$OPTARG") ;;
    l) LIST=$OPTARG ;;
    h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
shift $((OPTIND - 1))
[ $# -ge 1 ] && ROOT=$1

case "$MODE" in
  header|probe|full) ;;
  *) echo "Unknown mode: $MODE (use header, probe or full)" >&2; exit 2 ;;
esac

root_real=$(realpath "$ROOT" 2>/dev/null)
if [ -z "$root_real" ] || [ ! -d "$root_real" ]; then
  echo "Library folder not found: $ROOT" >&2
  exit 2
fi

if [ -n "$LIST" ] && [ ! -r "$LIST" ]; then
  echo "List file not found or unreadable: $LIST" >&2
  exit 2
fi

# Find ffprobe / ffmpeg (Jellyfin's bundled build first) when needed.
find_tool() {
  if [ -x "/usr/lib/jellyfin-ffmpeg/$1" ]; then
    echo "/usr/lib/jellyfin-ffmpeg/$1"
  elif command -v "$1" >/dev/null 2>&1; then
    command -v "$1"
  fi
}
FFPROBE=""
FFMPEG=""
if [ "$MODE" = "probe" ]; then
  FFPROBE=$(find_tool ffprobe)
  if [ -z "$FFPROBE" ]; then
    echo "ffprobe not found (looked in /usr/lib/jellyfin-ffmpeg and PATH)." >&2
    exit 2
  fi
elif [ "$MODE" = "full" ]; then
  FFMPEG=$(find_tool ffmpeg)
  if [ -z "$FFMPEG" ]; then
    echo "ffmpeg not found (looked in /usr/lib/jellyfin-ffmpeg and PATH)." >&2
    exit 2
  fi
fi

# Low priority for the heavy modes, so playback isn't disturbed.
LOWPRI=()
if [ "$MODE" != "header" ]; then
  command -v nice >/dev/null 2>&1 && LOWPRI+=(nice -n 19)
  command -v ionice >/dev/null 2>&1 && LOWPRI+=(ionice -c3)
fi

# Folders to skip (absolute, normalised). Incoming is always on the list.
EXCLUDES=("$root_real/Incoming")
for x in "${EXTRA_EXCLUDES[@]+"${EXTRA_EXCLUDES[@]}"}"; do
  case "$x" in
    /*) EXCLUDES+=("$(realpath -m -- "$x")") ;;
    *)  EXCLUDES+=("$(realpath -m -- "$root_real/$x")") ;;
  esac
done

# Safety: never write the report inside the library being checked.
report_real=$(realpath -m "$REPORT")
case "$report_real" in
  "$root_real"/*)
    echo "Refusing to write the report inside the library ($report_real)." >&2
    echo "Pick a path outside it with -o." >&2
    exit 2
    ;;
esac

tmp=$(mktemp) || exit 2
errtmp=$(mktemp) || exit 2
trap 'rm -f "$tmp" "$errtmp"' EXIT

# One-line, tab-free, length-limited version of a tool's error output.
first_line() {
  printf '%s' "$1" | head -n 1 | tr -d '\t\r' | cut -c1-200
}

# Deep check. Sets REASON/DETAIL if the file fails. Mode-specific.
deep_check() {
  local f=$1 out rc
  REASON=""; DETAIL=""
  if [ "$MODE" = "probe" ]; then
    # Reads every packet without decoding; prints one count per stream.
    "${LOWPRI[@]+"${LOWPRI[@]}"}" "$FFPROBE" -v error -count_packets \
      -show_entries stream=nb_read_packets -of csv=p=0 -i "$f" \
      </dev/null >/dev/null 2>"$errtmp"
    rc=$?
    out=$(cat "$errtmp")
    if [ "$rc" -eq 126 ] || [ "$rc" -eq 127 ]; then
      REASON="TOOL_ERROR"; DETAIL="could not run ffprobe (exit $rc)"
    elif [ "$rc" -ne 0 ] || [ -n "$out" ]; then
      REASON="PROBE_ERROR"; DETAIL=$(first_line "${out:-ffprobe exit code $rc}")
    fi
  else
    # Decodes all video and audio, discards the result.
    "${LOWPRI[@]+"${LOWPRI[@]}"}" "$FFMPEG" -nostdin -v error -i "$f" \
      -map 0:v? -map 0:a? -f null - \
      </dev/null >/dev/null 2>"$errtmp"
    rc=$?
    out=$(cat "$errtmp")
    if [ "$rc" -eq 126 ] || [ "$rc" -eq 127 ]; then
      REASON="TOOL_ERROR"; DETAIL="could not run ffmpeg (exit $rc)"
    elif [ "$rc" -ne 0 ] || [ -n "$out" ]; then
      REASON="DECODE_ERROR"; DETAIL=$(first_line "${out:-ffmpeg exit code $rc}")
    fi
  fi
}

total=0
bad=0
skipped=0

echo "Mode: $MODE (read-only)"
if [ -n "$LIST" ]; then
  echo "Checking files listed in: $LIST"
else
  echo "Scanning $root_real"
  for ex in "${EXCLUDES[@]}"; do
    echo "Skipping: $ex"
  done
fi
[ "$MODE" = "full" ] && echo "Full mode decodes every file and can take a long time. Ctrl+C stops it; the report is only written at the end."

# Source of NUL-separated file paths: a list file, or find over the library.
file_stream() {
  if [ -n "$LIST" ]; then
    # Accept plain paths, or a previous report (REASON<TAB>path<TAB>detail).
    awk -F'\t' 'NF { print (NF >= 2 ? $2 : $1) }' "$LIST" | tr '\n' '\0'
  else
    find "$root_real" \
      -type d -name '.deletedByTMM' -prune -o \
      -type f \( -iname '*.mkv' -o -iname '*.webm' -o -iname '*.mka' \
              -o -iname '*.mp4' -o -iname '*.m4v' -o -iname '*.mov' -o -iname '*.m4a' \) \
      -print0
  fi
}

while IFS= read -r -d '' f; do
  # Skip anything inside an excluded folder (walk mode only).
  if [ -z "$LIST" ]; then
    skip=0
    for ex in "${EXCLUDES[@]}"; do
      if [[ "$f" == "$ex"/* ]]; then
        skip=1
        break
      fi
    done
    if [ "$skip" -eq 1 ]; then
      skipped=$((skipped + 1))
      continue
    fi
  fi

  total=$((total + 1))
  reason=""
  detail=""

  if [ ! -e "$f" ]; then
    reason="UNREADABLE"; detail="file not found"
  elif [ ! -r "$f" ]; then
    reason="UNREADABLE"
  elif [ ! -s "$f" ]; then
    reason="EMPTY"
  else
    case "${f##*.}" in
      [Mm][Kk][Vv]|[Ww][Ee][Bb][Mm]|[Mm][Kk][Aa])
        magic=$(head -c 4 -- "$f" 2>/dev/null | od -An -tx1 | tr -d ' \n')
        if [ -z "$magic" ]; then
          reason="UNREADABLE"
        elif [ "$magic" != "1a45dfa3" ]; then
          reason="BAD_HEADER"
        fi
        ;;
      *)
        # MP4 family: bytes 5-8 hold the first box type.
        # ftyp, moov, mdat, free, wide, skip
        box=$(head -c 8 -- "$f" 2>/dev/null | tail -c 4 | od -An -tx1 | tr -d ' \n')
        case "$box" in
          "") reason="UNREADABLE" ;;
          66747970|6d6f6f76|6d646174|66726565|77696465|736b6970) ;;
          *) reason="BAD_HEADER" ;;
        esac
        ;;
    esac

    # Header looks fine: go deeper if asked.
    if [ -z "$reason" ] && [ "$MODE" != "header" ]; then
      echo "[$total] checking: $f" >&2
      deep_check "$f"
      reason=$REASON
      detail=$DETAIL
    fi
  fi

  if [ -n "$reason" ]; then
    bad=$((bad + 1))
    printf '%s\t%s\t%s\n' "$reason" "$f" "$detail" >> "$tmp"
    if [ -n "$detail" ]; then
      printf '%-12s %s\n             -> %s\n' "$reason" "$f" "$detail"
    else
      printf '%-12s %s\n' "$reason" "$f"
    fi
  fi
done < <(file_stream)

sort -t "$(printf '\t')" -k2,2 "$tmp" > "$REPORT"

echo
echo "Checked: $total files"
[ -z "$LIST" ] && echo "Skipped: $skipped files in excluded folders"
echo "Problems: $bad"
echo "Report: $REPORT"

[ "$bad" -eq 0 ]
