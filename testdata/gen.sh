#!/bin/sh
# Regenerates the fixtures. Run from this directory.
#
# Each one is read back by cpio before being kept: a fixture the reference tool
# cannot read is a fixture that proves nothing about the reference.
set -eu
tree=$(mktemp -d)
trap 'rm -rf "$tree"' EXIT
mkdir -p "$tree/sub"
printf 'the real bytes\n' > "$tree/real.txt"
printf 'nested\n' > "$tree/sub/nested.txt"
ln -s real.txt "$tree/link"

for fmt in newc odc bin; do
  (cd "$tree" && find . -print | COPYFILE_DISABLE=1 cpio -o -H "$fmt") > "$fmt.cpio" 2>/dev/null
  # ⛔ The premise: cpio must read its own output back before this is a fixture.
  cpio -i -t < "$fmt.cpio" >/dev/null 2>&1 || { echo "cpio cannot read $fmt.cpio"; exit 1; }
  echo "$fmt.cpio: $(wc -c < "$fmt.cpio") bytes"
done

# The other byte order, which no tool here writes. gen_swapped.py byte-swaps the
# 13 header words of each record and leaves the names and data alone.
python3 gen_swapped.py
