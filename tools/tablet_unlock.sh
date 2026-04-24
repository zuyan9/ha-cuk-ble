#!/usr/bin/env bash
# Unlock the rooted Lenovo tablet used for AD1204U Mi Home captures.
#
# Default pattern follows the local bench note: an L shape starting at the
# top-middle dot and ending at the bottom-right dot. Override coordinates with:
#   PATTERN_POINTS="768,920 768,1280 768,1640 1152,1640" tools/tablet_unlock.sh

set -euo pipefail

serial="${ADB_SERIAL:-HA1R80YR}"
touch_device="${TOUCH_DEVICE:-/dev/input/event9}"

usage() {
  printf 'Usage: %s [-s DEVICE_ID]\n' "$0" >&2
}

while getopts ":s:h" opt; do
  case "$opt" in
    s) serial="$OPTARG" ;;
    h)
      usage
      exit 0
      ;;
    :)
      printf 'Option -%s requires an argument.\n' "$OPTARG" >&2
      usage
      exit 2
      ;;
    \?)
      printf 'Unknown option: -%s\n' "$OPTARG" >&2
      usage
      exit 2
      ;;
  esac
done

adb_cmd=(adb)
if [[ -n "$serial" ]]; then
  adb_cmd+=(-s "$serial")
fi

size_line="$("${adb_cmd[@]}" shell wm size 2>/dev/null | sed -n 's/^Physical size: //p' | tail -n 1 | tr -d '\r')"
if [[ ! "$size_line" =~ ^[0-9]+x[0-9]+$ ]]; then
  printf 'Could not read tablet size via adb shell wm size.\n' >&2
  exit 1
fi

width="${size_line%x*}"
height="${size_line#*x}"

if [[ -n "${PATTERN_POINTS:-}" ]]; then
  read -r -a points <<<"$PATTERN_POINTS"
else
  x_mid=$((width / 2))
  x_right=$((width * 3 / 4))
  y_top=$((height * 36 / 100))
  y_mid=$((height * 50 / 100))
  y_bottom=$((height * 64 / 100))
  points=(
    "${x_mid},${y_top}"
    "${x_mid},${y_mid}"
    "${x_mid},${y_bottom}"
    "${x_right},${y_bottom}"
  )
fi

if ((${#points[@]} < 2)); then
  printf 'PATTERN_POINTS must contain at least two x,y pairs.\n' >&2
  exit 2
fi

for point in "${points[@]}"; do
  if [[ ! "$point" =~ ^[0-9]+,[0-9]+$ ]]; then
    printf 'Bad point %q; expected x,y.\n' "$point" >&2
    exit 2
  fi
done

"${adb_cmd[@]}" shell input keyevent KEYCODE_WAKEUP >/dev/null
sleep 0.3
"${adb_cmd[@]}" shell input swipe "$((width / 2))" "$((height * 86 / 100))" "$((width / 2))" "$((height * 42 / 100))" 250 >/dev/null || true
sleep 0.3

{
  printf 'dev=%q\n' "$touch_device"
  cat <<'REMOTE'
send() {
  sendevent "$dev" "$1" "$2" "$3"
}
sync_frame() {
  send 0 0 0
}
down_at() {
  x="$1"
  y="$2"
  send 3 47 0       # ABS_MT_SLOT
  send 3 57 1204    # ABS_MT_TRACKING_ID
  send 3 48 8       # ABS_MT_TOUCH_MAJOR
  send 3 53 "$x"    # ABS_MT_POSITION_X
  send 3 54 "$y"    # ABS_MT_POSITION_Y
  send 1 330 1      # BTN_TOUCH
  send 1 325 1      # BTN_TOOL_FINGER
  sync_frame
}
move_to() {
  x="$1"
  y="$2"
  send 3 53 "$x"
  send 3 54 "$y"
  sync_frame
}
up_now() {
  send 3 57 -1
  send 1 330 0
  send 1 325 0
  sync_frame
}
REMOTE

  first="${points[0]}"
  printf 'down_at %q %q\n' "${first%,*}" "${first#*,}"
  printf 'sleep 0.08\n'
  for point in "${points[@]:1}"; do
    printf 'move_to %q %q\n' "${point%,*}" "${point#*,}"
    printf 'sleep 0.08\n'
  done
  printf 'up_now\n'
} | "${adb_cmd[@]}" shell "su -c 'sh'"
