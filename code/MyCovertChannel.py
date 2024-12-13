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
    def send(self, interface="eth0", idle_time=0.1, log_file_name="sending_log.log"):  # TODO add config? 
        """
        - Generates a random binary message and sends it using packet bursts over ARP.
        """
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        
        for bit in binary_message:
            burst_size = 2 if bit == '1' else 1
            for _ in range(burst_size):
                packet = Ether(dst="ff:ff:ff:ff:ff:ff", type=0x0806) / ARP(pdst="172.18.0.3")  # TODO IP addr parameter or not ?

                ### scapy.layers.l2.ARP(_pkt, /, *, hwtype=1, ptype=2048, hwlen=None, plen=None, op=1, hwsrc=None, psrc=None, hwdst=None, pdst=None)
                print(packet.show())
                super().send(packet, interface)
            time.sleep(idle_time)  # Idle time between bursts

    def receive(self, interface="eth0", timeout=10, idle_threshold=0.05, log_file_name="received_log.log"):
        """
        - Captures ARP packets, decodes bursts into a binary message.
        """
        packets = sniff(iface=interface, timeout=timeout, ) # filter="arp")
        print(packets.summary())
        message = ""
        burst_count = 0
        last_packet_time = None

        for packet in packets:
            print(packet)
            # if ARP in packet:
            current_time = time.time()
            if last_packet_time and (current_time - last_packet_time > idle_threshold):
                # End of a burst
                if burst_count == 2:
                    message += '1'
                elif burst_count == 1:
                    message += '0'
                burst_count = 0
            burst_count += 1
            last_packet_time = current_time

        # Log the received message
        self.log_message(message, log_file_name)