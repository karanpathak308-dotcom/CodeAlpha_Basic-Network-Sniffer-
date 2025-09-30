import tkinter as tk
from tkinter import ttk
from scapy.all import sniff
from scapy.all import Raw

def capture_packet(packet):
    # Insert packet info into the table
    def capture_packet(packet):
        src, dst, proto = "N/A", "N/A", "N/A"
        payload = "No Payload"

    # IPv4 packets
    if packet.haslayer("IP"):
        src = packet["IP"].src
        dst = packet["IP"].dst
        proto = packet["IP"].proto  # protocol number (6=TCP, 17=UDP, etc.)

    # IPv6 packets
    elif packet.haslayer("IPv6"):
        src = packet["IPv6"].src
        dst = packet["IPv6"].dst
        proto = packet["IPv6"].nh  # next header field (like proto for IPv4)

    # TCP
    if packet.haslayer("TCP"):
        proto = "TCP"
    # UDP
    elif packet.haslayer("UDP"):
        proto = "UDP"
    # ICMP
    elif packet.haslayer("ICMPv6EchoRequest") or packet.haslayer("ICMP"):
        proto = "ICMP"
        
    payload = "No Payload"   # always define default first
    if packet.haslayer(Raw):
        try:
            payload = packet[Raw].load[:20].hex()
        except:
            payload = "Error extracting"



    # Insert clean values into table
    tree.insert("", "end", values=(src, dst, proto, f"{len(packet)} bytes, Payload: {payload}"))


root = tk.Tk()
root.title("Packet Sniffer")

# Treeview table
tree = ttk.Treeview(root, columns=("Source", "Destination", "Protocol", "Length"), show="headings")
tree.heading("Source", text="Source IP")
tree.heading("Destination", text="Destination IP")
tree.heading("Protocol", text="Protocol")
tree.heading("Length", text="Length")
tree.pack(fill="both", expand=True)

# Button to start sniffing
btn = tk.Button(root, text="Start Sniffing",
                command=lambda: sniff(prn=capture_packet, count=10))
btn.pack()

root.mainloop()
