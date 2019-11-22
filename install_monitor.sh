#!/usr/bin/env bash

#
# Enable monitor mode on RPi4's native WiFi chipset (Broadcom 43455c0).
# Based on information from the following:
#	https://github.com/seemoo-lab/nexmon
#	https://github.com/seemoo-lab/nexmon/issues/344
#

do_upgrade="yes" # Note: will reboot the system after upgrading software!
do_clone="yes"
do_libraries="yes"
do_flashpatches="yes"
do_firmware="yes"
do_nexutil="yes"
do_remove_supplicant="yes"

if (( $EUID != 0 ))
then
	echo "This script needs to be run as root, or using sudo!"
	exit
fi

# Update the platform, and ensure some core software is present
if [[ "${do_upgrade}" == "yes" ]]
then
	apt update

	apt install \
		raspberrypi-kernel-headers \
		git \
		libgmp3-dev \
		gawk \
		qpdf \
		bison \
		flex \
		make \
		libtool-bin \
		automake \
		texinfo

	apt dist-upgrade

	apt autoremove

	reboot
fi

# Get the new driver source code from Github, and disable reporting of statistics
if [[ "${do_clone}" == "yes" ]]
then
	git clone https://github.com/seemoo-lab/nexmon.git
	touch nexmon/DISABLE_STATISTICS
fi

# Build the required libraries
if [[ "${do_libraries}" == "yes" ]]
then
	if [[ ! -f /usr/lib/arm-linux-gnueabihf/libisl.so.10 ]]
	then
		old_dir=$(pwd)
		cd nexmon/buildtools/isl-0.10
		./configure
		make
		make install
		ln -s /usr/local/lib/libisl.so /usr/lib/arm-linux-gnueabihf/libisl.so.10
		cd ${old_dir}
	fi

	if [[ ! -f /usr/lib/arm-linux-gnueabihf/libmpfr.so.4 ]]
	then
		old_dir=$(pwd)
		cd nexmon/buildtools/mpfr-3.1.4
		autoreconf -f -i # only needed because of a flaw in the current nexmon git repository?
		./configure
		make
		make install
		ln -s /usr/local/lib/libmpfr.so /usr/lib/arm-linux-gnueabihf/libmpfr.so.4
		cd ${old_dir}
	fi
fi

# Compile flashpatches
if [[ "${do_flashpatches}" == "yes" ]]
then
	source nexmon/setup_env.sh

	old_dir=$(pwd)
	cd nexmon
	source setup_env.sh
	make
	cd ${old_dir}
fi

# Build the new firmware, and backup the old firmware
if [[ "${do_firmware}" == "yes" ]]
then
	source nexmon/setup_env.sh

	old_dir=$(pwd)
	cd nexmon/patches/bcm43455c0/7_45_189/nexmon
	make
	make backup-firmware
	cd ${old_dir}
fi

# Build the nexutil program
if [[ "${do_nexutil}" == "yes" ]]
then
	source nexmon/setup_env.sh

	old_dir=$(pwd)
	cd nexmon/utilities/nexutil/
	make && make install
	cd ${old_dir}
fi

# Optional - apparently provides better control over WiFi interface
if [[ "${do_remove_supplicant}" == "yes" ]]
then
	apt remove wpasupplicant
	apt autoremove
fi

# To connect to regular access points, first run "nexutil -m0"
# Consider e.g.: "apt install tshark", "sudo tshark -i mon0 -I"
