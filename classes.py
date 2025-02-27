from collections import defaultdict
from scapy.all import IP, TCP

class PacketCapture:
    def __init__(self):
        # Your code here
        pass

class TrafficAnalyzer:
    def __init__(self):
        self.connections = defaultdict(list)
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None
        })

    def analyze_packet(self, packet):
        if IP in packet and TCP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport

            flow_key = (ip_src, ip_dst, port_src, port_dst)

            # Update flow statistics
            stats = self.flow_stats[flow_key]
            stats['packet_count'] += 1
            stats['byte_count'] += len(packet)
            current_time = packet.time

            if not stats['start_time']:
                stats['start_time'] = current_time
            stats['last_time'] = current_time

            return self.extract_features(packet, stats)

    def extract_features(self, packet, stats):
        flow_duration = stats['last_time'] - stats['start_time']
        
        # Avoid division by zero
        if flow_duration > 0:
            packet_rate = stats['packet_count'] / flow_duration
            byte_rate = stats['byte_count'] / flow_duration
        else:
            packet_rate = 0
            byte_rate = 0

        return {
            'packet_size': len(packet),
            'flow_duration': flow_duration,
            'packet_rate': packet_rate,
            'byte_rate': byte_rate,
            'tcp_flags': packet[TCP].flags,
            'window_size': packet[TCP].window
        }

class DetectionEngine:
    def __init__(self):
        # Any necessary initialization
        pass

    def detect_threats(self, features):
        threats = []

        # Example conditions for detecting different types of threats
        if features['packet_rate'] > 1000:  # High packet rate could indicate a flood attack (e.g., DoS)
            threats.append("Flood attack (High packet rate detected)")

        if features['byte_rate'] > 50000:  # High byte rate could indicate a data exfiltration attempt
            threats.append("Data exfiltration attempt (High byte rate detected)")

        if features['tcp_flags'] == 'S':  # SYN flag detected - possible SYN flood
            threats.append("SYN flood detected (SYN flag detected in packet)")

        if features['window_size'] < 100:  # Low window size could indicate network reconnaissance
            threats.append("Possible port scanning (Low window size detected)")

        # Return the list of detected threats (empty if no threats)
        return threats


class AlertSystem:
    def __init__(self):
        # Your code here
        pass
