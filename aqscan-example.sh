#!/bin/bash

LOOKUP="/path/to/lookup/file"

wrkdir="tmp-$RANDOM"
./aqcap.sh "${wrkdir}"
./aq ./${wrkdir}/channel-* > "${wrkdir}/scanout"
./deref-macs.sh "${LOOKUP}" "${wrkdir}/scanout"
rm -r "${wrkdir}"
