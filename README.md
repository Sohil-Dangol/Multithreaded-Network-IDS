# Multithreaded-Network-IDS

A multithreaded packet sniffer and intrusion detection system implemented in C using **libpcap**. The program captures live network traffic, analyses packets, and detects common network attacks including **SYN floods**, **ARP poisoning**, and **blacklisted URL access**.

The project focuses on efficient packet processing through the use of a thread pool, synchronisation techniques, and careful memory management.

## Features

- Live packet capture using `libpcap`
- Multithreaded packet analysis using a worker thread pool
- Detection of:
  - SYN flood attacks
  - ARP poisoning attempts
  - Blacklisted URL requests
- Packet parsing:
  - Ethernet headers
  - IPv4 headers
  - TCP headers
  - HTTP payloads
- Thread-safe shared data management using mutex locks
- Dynamic memory management with leak checking
- Graceful shutdown using signal handling

---

## Architecture

The program separates packet capture and packet analysis into different stages.

### Packet Capture

Captured packets are passed to the `dispatch()` function, which places them into a shared queue. This allows packet collection to continue without waiting for analysis to complete.
