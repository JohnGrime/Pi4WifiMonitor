# Pi4Monitor

Scripts to install and initialise monitor mode on the Raspberry Pi v4's internal WiFi chipset. Uses code and information provided by the [Nexmon](https://github.com/seemoo-lab/nexmon) project, and tested under [Raspbian](https://www.raspberrypi.org/downloads/raspbian/) Buster.

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

... and then run `launch_monitor.sh` with superuser rights:

```
sudo ./launch_monitor.sh
```

... which should bring up a `mon0` interface for you use (you can check this via e.g. `ifconfig`).

The `mon0` interface can be used via e.g. [`tshark`](https://www.wireshark.org/docs/man-pages/tshark.html):

```
sudo tshark -i mon0 -I
```
