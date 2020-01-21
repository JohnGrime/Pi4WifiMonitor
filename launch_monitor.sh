#!/usr/bin/env bash

#
# Enable monitor mode on RPi4's native WiFi chipset (Broadcom 43455c0).
# Based on information from the following:
#	https://github.com/seemoo-lab/nexmon
#	https://github.com/seemoo-lab/nexmon/issues/344
#

#
# Shell script to bring up a wifi monitor interface ("mon0")
#

HERE=$(pwd)
NEXMON_DIR="${HERE}/nexmon"
PATCH_DIR="${NEXMON_DIR}/patches/bcm43455c0/7_45_189/nexmon"

#
# This script needs to be run as root, or using sudo!
#
if (( $EUID != 0 ))
then
	echo "This script needs to be run as root, or using sudo!"
	exit
fi

#
# Set up environment
#

cd "${NEXMON_DIR}"
source setup_env.sh

#
# Install new wifi driver that supports monitor mode
#

cd "${PATCH_DIR}"
make install-firmware

#
# Introduce a slight delay before the following commands
#

sleep 5

#
# Add a monitor interface, and bring it up.
#

iw phy `iw dev wlan0 info | gawk '/wiphy/ {printf "phy" $2}'` interface add mon0 type monitor
ifconfig mon0 up

#
# Check it has worked; we should see a "mon0" interface.
#

ifconfig -a

