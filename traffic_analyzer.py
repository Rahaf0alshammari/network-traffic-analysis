# أداة تحليل حركة مرور الشبكة بمعالجة التدفق - مطورة بواسطة رهف الشمري
# Network Traffic Analyzer with Stream Processing

from scapy.all import PcapReader, IP, TCP, UDP

def analyze_large_pcap(file_path):
    print(f"[*] Starting streaming analysis for: {file_path}\n")
    
    total_packets = 0
    alert_count = 0
    protocol_stats = {"TCP": 0, "UDP": 0, "Other": 0}
    
    print(f"{'No.':<6} {'Source IP':<18} {'Destination IP':<18} {'Protocol':<10} {'Security Status'}")
    print("-" * 75)

    try:
        # استخدمت PcapReader هنا عشان أقرا الحزم حزمة حزمة (Streaming) وبكذا أتجنب استهلاك الذاكرة العشوائية مع الملفات الضخمة
        with PcapReader(file_path) as pcap_stream:
            for pkt in pcap_stream:
                total_packets += 1
                
                if IP in pkt:
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    
                    proto = "Other"
                    status = "Normal"
                    
                    if TCP in pkt:
                        proto = "TCP"
                        protocol_stats["TCP"] += 1
                        # فحص البورتات غير الآمنة والخطرة (مثل Telnet على البورت 23)
                        if pkt[TCP].dport == 23 or pkt[TCP].sport == 23:
                            status = "[!] ALERT: Insecure Telnet Port!"
                            alert_count += 1
                    elif UDP in pkt:
                        proto = "UDP"
                        protocol_stats["UDP"] += 1
                    else:
                        protocol_stats["Other"] += 1

                    # أكتفي بعرض أول 20 حزمة فقط بالشاشة كعينة، بينما يستمر الفحص والإحصاء لكل الملف خلف الكواليس
                    if total_packets <= 20:
                        print(f"{total_packets:<6} {src_ip:<18} {dst_ip:<18} {proto:<10} {status}")
                else:
                    protocol_stats["Other"] += 1

    except FileNotFoundError:
        print(f"[-] Error: File '{file_path}' not found.")
        return

    print("-" * 75)
    print(f"\n[+] Analysis Complete!")
    print(f"    - Total Packets Processed     : {total_packets}")
    print(f"    - Security Alerts Found       : {alert_count}")
    print(f"    - Protocol Breakdown          : {protocol_stats}")

if __name__ == "__main__":
    analyze_large_pcap("sample.pcap")
    