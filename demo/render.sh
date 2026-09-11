#!/bin/bash
# render.sh — render demo.html frame by frame into demo.gif (and demo.mp4).
# Needs: playwright-cli (npm i -g @playwright/cli), python3, ffmpeg.
# Usage: bash demo/render.sh [fps] [out_dir_for_frames]
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
FPS="${1:-12}"
FR="${2:-/tmp/claude-1password-frames}"
PORT=8765
END_MS=$(grep -o 'end: *[0-9]*' "$HERE/demo.html" | grep -o '[0-9]*$')
N=$(( END_MS * FPS / 1000 ))
mkdir -p "$FR"; rm -f "$FR"/f_*.png

( cd "$HERE" && python3 -m http.server $PORT >/dev/null 2>&1 & echo $! > "$FR/http.pid" )
sleep 1
playwright-cli -s=gif close >/dev/null 2>&1
playwright-cli -s=gif open "http://127.0.0.1:$PORT/demo.html?t=0" >/dev/null 2>&1 || { echo "playwright-cli open failed"; exit 1; }
playwright-cli -s=gif resize 960 600 >/dev/null 2>&1

echo "rendering $N frames at $FPS fps..."
for ((i=0; i<N; i++)); do
  t=$(( i * 1000 / FPS ))
  playwright-cli -s=gif eval "window.setT($t)" >/dev/null 2>&1
  p=$(playwright-cli -s=gif screenshot 2>&1 | grep -o -E "[^ (]+\.png" | head -1)
  # the CLI prints a path relative to cwd with ../ segments; resolve it
  f=$(cd "$(dirname "$p")" 2>/dev/null && pwd)/$(basename "$p")
  [ -f "$f" ] || f="$p"
  [ -f "$f" ] && mv "$f" "$FR/$(printf 'f_%04d.png' "$i")" || echo "frame $i missing ($p)"
  [ $(( i % 24 )) -eq 0 ] && echo "  $i/$N"
done
playwright-cli -s=gif close >/dev/null 2>&1
kill "$(cat "$FR/http.pid")" 2>/dev/null

echo "encoding..."
ffmpeg -y -loglevel error -framerate "$FPS" -i "$FR/f_%04d.png" -vf "fps=$FPS,scale=960:-1:flags=lanczos,split[s0][s1];[s0]palettegen=max_colors=192:stats_mode=diff[p];[s1][p]paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle" -loop 0 "$HERE/demo.gif"
ffmpeg -y -loglevel error -framerate "$FPS" -i "$FR/f_%04d.png" -c:v libx264 -pix_fmt yuv420p -crf 20 -movflags +faststart "$HERE/demo.mp4"
ls -la "$HERE/demo.gif" "$HERE/demo.mp4" | awk '{print $5, $9}'
