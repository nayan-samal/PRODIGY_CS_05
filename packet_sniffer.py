from scapy.all import sniff, IP, TCP, UDP


def packet_callback(packet):
    if packet.haslayer(IP):
        ip = packet[IP]

        proto = "Other"
        if packet.haslayer(TCP):
            proto = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif packet.haslayer(UDP):
            proto = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        else:
            sport = "-"
            dport = "-"

        print(f"{ip.src}:{sport} -> {ip.dst}:{dport} | {proto}")


print("Sniffing packets... Press Ctrl+C to stop")
sniff(prn=packet_callback, store=False)