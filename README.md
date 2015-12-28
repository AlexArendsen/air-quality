# Air Quality

**Air Quality** analyzes monitor traffic captured in packet capture (PCAP)
files. It provides output enumerating nearby wireless access points, the
users of those access points, network usage for all transmitting parties,
and an analysis of channel usage.

Air Quality is meant for use on the 2.4GHz band, and will not work with
captures monitoring the 5GHz band.

**Important Notice**: Network monitoring ("packet sniffing", etc.) is an often
prohibited / restricted activity. Please observe the rules and regulations
corresponding to whatever network you are studying!

## Dependencies and Compatibility Notes

The only dependency for Air Quality is **libpcacp**. The bundled support
scripts have additional dependencies. Please refer to the corresponding section
in this document for more information.

Air Quality has only been tested on Linux. You are welcome to try the program
on Windows, OSX, or any other system, but I'm not making you any promises.

## Compilation and Usage

Link with `libpcap`:

    gcc -o aq air-quality.c -lpcap

Provide one or more PCAP files to use:

    ./aq foo.pcap [ bar.pcapng ] [ ... ]

## Support scripts

Air Quality itself simply reads PCAP files. I've written a couple of general
purpose support scripts for Bash to supplement the program:

### aqcap.sh

The **aqcap.sh** script automatically creates a monitor interface, captures
traffic across the 2.4GHz band (provided that your hardware permits network
monitoring), and saves the capture to three PCAP files, one for each of the
primary channels. These files can then be given to Air Quality for analysis.
These files aren't automatically deleted or anything, so if you don't want
them lingering on your machine, be sure to delete them yourself.

The script creates a new directory to store the PCAP files, the name for which
should be provided as the only argument (an existing directory cannot be used).
Before using the script, review the arguments at the top of the script and check
that they match the names given to your hardware and interface-- they probably don't.

aqcap.sh is a Bash script, and therefore requires Bash in addition to the
following commonly available packages:
* `iw` -- Wireless device configuration CLI meant to succeed `iwconfig`.
* `ip` -- Network interface management CLI (you probably already have it)
* `tcpdump` -- Network traffic capturing CLI.
You will likely need superuser privileges to run this script.

### deref-macs.sh

The **deref-macs.sh** script is used to replace MAC addresses within a text
file with more recognizable names defined in a lookup file. Please refer to the
included `lookup-example.macs` to learn how lookup files should be formatted
(it's very simple, don't worry).

Usage is also simple: the first argument is the path to the lookup file, and
the second argument is the path to the source text file containing MAC addresses
to be replaced (in this case you would use Air Quality's text output, but any
file can be used).

The script's only dependency is `sed`.
