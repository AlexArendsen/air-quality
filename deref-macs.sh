#!/bin/bash
# Simple MAC address replacer script.
# Usage: ./deref-macs <path-to-lookup-file> <path-to-source-file>

sessionid="$RANDOM"
outp="/tmp/deref-macs-${sessionid}-out"
tmpp="/tmp/deref-macs-${sessionid}-tmp"
cp "$2" "${outp}"
cp "$2" "${tmpp}"
while IFS='' read -r l || [[ -n "$l" ]]; do
  mac=$(cut -d " " -f 1 <<< "$l")
  label=$(cut -d " " -f 2 <<< "$l")
  sed -e "s#$mac#$label#g" > ${tmpp} < ${outp}
  cp "${tmpp}" "${outp}"
done < "$1"

cat "${outp}"
rm "${tmpp}" "${outp}"
