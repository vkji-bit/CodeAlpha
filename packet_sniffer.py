#packet sniffer

from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print(f"\n[+] New Packet: {ip_layer.src} -> {ip_layer.dst}")
        
        # Check for TCP packets
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"   Protocol: TCP, Src Port: {tcp_layer.sport}, Dst Port: {tcp_layer.dport}")
        
        # Check for UDP packets
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"   Protocol: UDP, Src Port: {udp_layer.sport}, Dst Port: {udp_layer.dport}")

# Start sniffing (you might need to run this as root/administrator)
sniff(prn=packet_callback, filter="ip", count=0)  # Sniff indefinitely
