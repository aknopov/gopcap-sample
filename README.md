[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

# Sample Code for Capturing Network Traffic

This project uses two libraries - GO ports of libPcap (google/gopacket) and netstat (sokurenko/go-netstat) to capture
valume of all network packets on all NIC adapters for a given process.

The process can be specified by a portion of its command line or by a PID. The program polls NetStat tables periodically to find ports opened by a process.

## Linux note

In order to run on Linux, the program either have to be run with `sudo` or the executable file should have certain capabilities - see [build script](./build.sh)