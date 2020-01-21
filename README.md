# Pi4Monitor

Scripts to install and initialise monitor mode on the Raspberry Pi v4's internal WiFi chipset. Uses code and information provided by the [Nexmon](https://github.com/seemoo-lab/nexmon) project, and tested under [Raspbian](https://www.raspberrypi.org/downloads/raspbian/) Buster.

## Installation and Setup

First ensure your Pi has up-to-date versions of the required software, and reboot:

```
apt update
apt install raspberrypi-kernel-headers git libgmp3-dev gawk qpdf bison flex make libtool-bin automake texinfo
apt dist-upgrade
apt autoremove
reboot
```

Then, download the two scripts (`install_monitor.sh` and `launch_monitor.sh`) into a convenient directory.

Next, run `install_monitor.sh` with superuser rights:

```
sudo ./install_monitor.sh
```

To bring up a monitor-mode interface (`mon0`), run `launch_monitor.sh` with superuser rights:

```
sudo ./launch_monitor.sh
```

The presence of the `mon0` interface can be checked via e.g. `ifconfig`, and can be used via e.g. [`tshark`](https://www.wireshark.org/docs/man-pages/tshark.html):

```
sudo tshark -i mon0 -I
```

Note that the `launch_monitor.sh` script must be run again after reboots etc.

## Example `pcap` code

The example code requires the `pcap` library and can be built as follows:

```
g++ -std=c++14 -Wall -Wextra -pedantic wifi_snoop.cpp -lpcap -lpthread
```

