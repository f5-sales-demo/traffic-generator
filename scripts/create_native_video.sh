#!/bin/bash
# Generate actual decodable synthetic media with the native FFmpeg encoder.
set -euo pipefail
output="${1:?synthetic video output required}"
command -v ffmpeg >/dev/null
command -v ffprobe >/dev/null
ffmpeg -nostdin -hide_banner -loglevel error -y \
  -f lavfi -i 'color=c=blue:s=160x120:r=10:d=1' \
  -an -c:v mpeg4 -pix_fmt yuv420p -movflags +faststart "$output"
ffmpeg -nostdin -hide_banner -loglevel error -xerror -i "$output" -f null -
ffprobe -v error -select_streams v:0 -show_entries stream=codec_name,width,height \
  -of json "$output" >"${output}.probe.json"
python3 - "${output}.probe.json" <<'PYCODE'
import json,sys
with open(sys.argv[1]) as stream:
    streams=json.load(stream)["streams"]
if len(streams)!=1 or streams[0]!={"codec_name":"mpeg4","width":160,"height":120}:
    raise ValueError("native synthetic video decode verification failed")
PYCODE
rm -f "${output}.probe.json"
