from scapy.all import sniff
from scapy.layers.l2 import Ether, ARP
import time

from CovertChannelBase import CovertChannelBase

class MyCovertChannel(CovertChannelBase):
    """
    A class that implements a covert channel using ARP packet bursts.

    This class extends CovertChannelBase and provides two main functionalities:
    - Sending messages encoded in ARP packet bursts.
    - Receiving and decoding messages from ARP packet bursts.
    """
    def __init__(self):
        """
        Initializes the covert channel by calling the parent class (CovertChannelBase) constructor.
        """
        super().__init__()
    def send(self, interface="eth0", burst_size_1 = 2, burst_size_0 = 1, idle_time=0.1, log_file_name="sending_log.log"):
        """
        - Generates a random binary message and sends it using packet bursts over ARP.
        """
        binary_message = self.generate_random_binary_message_with_logging(log_file_name, min_length=16, max_length=16) # TODO remove min max before submission
        
        # Start sending packets and measure time
        start = time.time()
        for bit in binary_message:
            burst_size = burst_size_1 if bit == '1' else burst_size_0
            for _ in range(burst_size):
                packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst="172.18.0.3") 
                print(packet.show())
                super().send(packet, interface)
            time.sleep(idle_time)  # Idle time between bursts

        # Send a last packet to convert last bits to char 
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst="172.18.0.3")
        super().send(packet, interface)

        # Measure time and calculate capacity
        end = time.time()
        capacity = len(binary_message) / (end - start)
        print(f"Capacity bits per second: {capacity}")

    def receive(self, interface="eth0", burst_size_1=2, burst_size_0=1, idle_threshold=0.05, log_file_name="received_log.log"):
        """
        Captures ARP packets, decodes bursts into characters using base class's method.
        Stops sniffing when the message ends with ".".
        """
        message = ""
        current_bits = ""
        burst_count = 0
        last_packet_time = None

        def process_packet(packet):
            """
            Processes each captured packet to decode binary bits and update the message.
            """
            nonlocal current_bits, message, burst_count, last_packet_time

            if ARP in packet:
                current_time = time.time()

                if last_packet_time and (current_time - last_packet_time > idle_threshold):
                    print(f"burst_count: {burst_count}")
                    # End of a burst
                    if burst_count == burst_size_1:
                        current_bits += '1'
                    elif burst_count == burst_size_0:
                        current_bits += '0'
                    burst_count = 0
                    print(current_bits)

                    # Convert 8 bits to a character when a byte is complete
                    if len(current_bits) == 8:
                        char = self.convert_eight_bits_to_character(current_bits)
                        message += char
                        print(f"Message so far: {message}")
                        current_bits = ""

                burst_count += 1
                last_packet_time = current_time         

        def stop_filter(packet):
            """
            Stops sniffing when the received message ends with a period ('.').
            """
            return message.endswith(".")

        # Start sniffing with stop_filter
        sniff(iface=interface, filter="arp and ether dst ff:ff:ff:ff:ff:ff", prn=process_packet, stop_filter=stop_filter)

        # Log the final message
        print(f"Received message: {message}")
        self.log_message(message, log_file_name)