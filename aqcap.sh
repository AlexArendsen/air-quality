#!/bin/bash
# Air Quality capture by Alex Arendsen

INTERFACE=wlp2s0  # Name of managed wifi interface, check using `ip link`
CARD=phy0         # Name of wifi hardware, check using `iw dev`
MONITOR=aqmon0    # Preferred name for monitor interface to create, pick anything you'd like

function capture() {
  iw "$CARD" set freq $1
  tcpdump -i "$MONITOR" -w "$sessiondir/$2" 2> /dev/null &
  echo "Capturing traffic on $3 for 5 seconds..." > /dev/stderr
  sleep 5
  pkill tcpdump
}

# Create capture directory
if [[ -z "$1" ]]; then
  echo "Error: No capture directory provided"
  exit 1
elif [[ -e "$1" ]]; then
  echo "Error: Directory \"$1\" already exists"
  exit 1
fi
mkdir "$1"
sessiondir="$1"

# Set managed interface down temporarily (allows channel changing)
ip link set "$INTERFACE" down

# Prepare monitor interface
iw "$CARD" interface add "$MONITOR" type monitor
ip link set "$MONITOR" up

# Do capturing
capture 2412 "channel-1" "Channel 1" # Capture on channel 1
capture 2437 "channel-6" "Channel 6" # Capture on channel 6
capture 2462 "channel-11" "Channel 11" # Capture on channel 11

# Cleanup (remove monitor and reset managed interface)
ip link set "$MONITOR" down
iw "$MONITOR" del
ip link set "$INTERFACE" up
