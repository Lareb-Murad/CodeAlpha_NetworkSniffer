from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        print("=" * 50)
        print(f"Source IP      : {src_ip}")
        print(f"Destination IP : {dst_ip}")

        if TCP in packet:
            print(f"Protocol       : TCP")
            print(f"Src Port       : {packet[TCP].sport}")
            print(f"Dst Port       : {packet[TCP].dport}")
        elif UDP in packet:
            print(f"Protocol       : UDP")
            print(f"Src Port       : {packet[UDP].sport}")
            print(f"Dst Port       : {packet[UDP].dport}")
        elif ICMP in packet:
            print(f"Protocol       : ICMP")

        if packet[IP].payload:
            print(f"Payload        : {bytes(packet[IP].payload)[:50]}")

print("Starting Network Sniffer... Press Ctrl+C to stop")
sniff(prn=packet_callback, store=0, count=20)