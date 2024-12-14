from scapy.all import sniff
from scapy.layers.l2 import Ether, ARP
import time

from CovertChannelBase import CovertChannelBase

class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """
    def __init__(self):
        """
        - You can edit __init__.
        """
        super().__init__()
    def send(self, interface="eth0", burst_size_1 = 2, burst_size_0 = 1, idle_time=0.1, log_file_name="sending_log.log"):
        """
        - Generates a random binary message and sends it using packet bursts over ARP.
        """
        binary_message = self.generate_random_binary_message_with_logging(log_file_name, min_length=16, max_length=16) # TODO remove min max before submission
        
        for bit in binary_message:
            burst_size = burst_size_1 if bit == '1' else burst_size_0
            for _ in range(burst_size):
                packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst="172.18.0.3") 
                print(packet.show())
                super().send(packet, interface)
            time.sleep(idle_time)  # Idle time between bursts

        # send a last packet to convert last bits to char 
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst="172.18.0.3")
        super().send(packet, interface)

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
            return message.endswith(".")

        # Start sniffing with stop_filter
        sniff(iface=interface, filter="arp and ether dst ff:ff:ff:ff:ff:ff", prn=process_packet, stop_filter=stop_filter)

        # Log the final message
        print(f"Received message: {message}")
        self.log_message(message, log_file_name)