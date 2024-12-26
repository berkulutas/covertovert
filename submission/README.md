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
  - `log_file_name`: Log file for the sent message. ("sending_log.log")

### `receive` Function
The `receive` function captures ARP packets and decodes the transmitted message:
- **Input Parameters**:
  - `interface`: Network interface to capture packets (default: `eth0`).
  - `burst_size_1` and `burst_size_0`: Expected burst sizes for binary `1` and `0`. It must be same with sender for consistency.
  - `idle_threshold`: Time threshold to identify the end of a burst.
  - `log_file_name`: Log file for the received message. ("received_log.log")

## Covert Channel Capacity
The covert channel capacity was measured as follows:
1. A binary message of 128 bits (16 characters) was transmitted.
2. The transmission time was recorded from the first to the last packet.
3. Capacity was calculated as:
   ```
   Capacity (bps) = Total Bits / Transmission Time (seconds)
   ```
4. The measured capacity is **7.75 bits per second** with the following parameters:

    | Parameter           | Value        |
    |---------------------|--------------|
    | **Send Parameters** |              |
    | Burst Size for `1`  | `2`            |
    | Burst Size for `0`  | `1`            |
    | Idle Time           | `0.1` seconds  |
    |                     |              |
    | **Receive Parameters** |          |
    | Burst Size for `1`  | `2`            |
    | Burst Size for `0`  | `1`            |
    | Idle Threshold      | `0.05` seconds |

## Limitations and Constraints
1. **Idle Time**:
   - The `idle_time` parameter must be tuned to balance capacity and decoding accuracy. A lower `idle_time` increases capacity but risks decoding errors.
2. **Idle Threshold**:
   - The `idle_threshold` defines the maximum time gap to consider packets as part of the same burst.
3. **Burst Sizes**:
   - The burst sizes chosen for bit 1 and bit 0 must be different from each other
   - Burst size parameters must be same in sender and receiver. Incorrect burst sizes may lead to decoding errors.
   - The burst sizes chosen for bit 1 and bit 0 must be different from each other 
4. **System-Specific Issues**:
   - On some systems, such as WSL, the measured capacity is lower due to system overhead. To mitigate this, we raised `idle_time` to `0.5 seconds` and `idle_threshold` to `0.25 seconds`.
5. **Idle Threshold Tuning**:
   - Through testing, we observed issues when `idle_threshold` was set below `0.025 seconds`. While this may vary depending on the system, to ensure reliability, we recommend keeping `idle_threshold` above `0.03 seconds`.
6. **Relationship Between Idle Time and Idle Threshold**:
   - `idle_time` should always be greater than `idle_threshold` to account for network delays. A safe value for `idle_time` is at least 1.5 times the `idle_threshold` value to minimize decoding errors and ensure accurate message reconstruction.


## Authors
Berk Ulutaş 2522084

Mert Tokat 2644383



