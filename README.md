# Network Traffic Analysis Lab

A simple network analysis lab I built to practice capturing and analyzing network traffic using Wireshark and Nmap in a virtual environment.

## What I Used
* Kali Linux (UTM / Virtual Machine)
* Wireshark
* Nmap

## Lab Steps & What I Did

1. *Scanning the Network:* 
   I used Nmap to scan the local machine and check for open ports and running services.
   
2. *Capturing Packets:* 
   I ran Wireshark to monitor the traffic and filtered packets (like HTTP and TCP) to see how data flows through the network.

3. *Analyzing Credentials:* 
   I tested unencrypted protocols (HTTP / FTP) to see how plaintext credentials look inside captured packet payloads.

## Key Takeaways
* Unencrypted traffic easily exposes sensitive data.
* Enforcing HTTPS/TLS is critical for protecting data in transit.

---
Created by Rahaf Alshammari
