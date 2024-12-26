# Covert Channel Implementation: Packet Bursting Using ARP

This project implements a covert timing channel using a covert storage channel that utilizes packet bursting and ARP (Address Resolution Protocol) to encode and decode binary messages. This covert channel operates by transmitting bursts of ARP packets, with different burst sizes representing binary bits.

## Overview
The covert channel consists of two primary functions:
1. **`send`**: Encodes a binary message into ARP packet bursts and transmits it.
2. **`receive`**: Captures ARP packet bursts, decodes them into binary bits, and reconstructs the original message.

The implementation uses `scapy` for packet crafting and sniffing.

## Features
- **Binary Message Encoding**: Messages are encoded as bursts of ARP packets, with different burst sizes representing binary `1` and `0`.
- **Message Decoding**: Captured ARP bursts are decoded into binary bits and reconstructed into characters.
- **Customizable Parameters**:
  - `burst_size_1` and `burst_size_0`: Define the burst sizes for binary `1` and `0`.
  - `idle_time`: Delay between bursts to ensure accurate decoding.
  - `idle_threshold`: Time threshold to identify the end of a burst during decoding.
- **Stop Condition**: The receiver stops decoding when the message ends with `"."`.

## Implementation

### `send` Function
The `send` function encodes a binary message into ARP packet bursts and transmits it:
- **Input Parameters**:
  - `interface`: Network interface to send packets (default: `eth0`).
  - `burst_size_1` and `burst_size_0`: Burst sizes for binary `1` and `0`.
  - `idle_time`: Delay between bursts.
  - `log_file_name`: Log file for the sent message.

### `receive` Function
The `receive` function captures ARP packets and decodes the transmitted message:
- **Input Parameters**:
  - `interface`: Network interface to capture packets (default: `eth0`).
  - `burst_size_1` and `burst_size_0`: Expected burst sizes for binary `1` and `0`. It must be same with sender for consistency.
  - `idle_threshold`: Time threshold to identify the end of a burst.
  - `log_file_name`: Log file for the received message.

## Covert Channel Capacity
The covert channel capacity was measured as follows:
1. A binary message of 128 bits (16 characters) was transmitted.
2. The transmission time was recorded from the first to the last packet.
3. Capacity was calculated as:
   ```
   Capacity (bps) = Total Bits / Transmission Time (seconds)
   ```
4. The measured capacity is **11.6264 bits per second**. 

## Limitations and Constraints
1. **Idle Time**:
   - The `idle_time` parameter must be tuned to balance capacity and decoding accuracy. A lower `idle_time` increases capacity but risks decoding errors.
   - The default `idle_time` is set to `0.1` seconds.
2. **Idle Threshold**:
   - The `idle_threshold` defines the maximum time gap to consider packets as part of the same burst.
   - Default `idle_threshold` is `0.05` seconds.
3. **Burst Sizes**:
   - The default burst sizes are:
     - `burst_size_1 = 2` for binary `1`.
     - `burst_size_0 = 1` for binary `0`.
   - Incorrect burst sizes may lead to decoding errors.

Note: When using WSL, the measured capacity is lower due to system overhead. And for the receiver to receive the packets correctly, we needed to raise the idle time to 0.5 and the idle threshold to 0.25.


## Authors
Berk Ulutaş 2522084

Mert Tokat 2644383



