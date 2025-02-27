from classes import PacketCapture, TrafficAnalyzer, DetectionEngine, AlertSystem

class IntrusionDetectionSystem:
    def __init__(self, interface="eth0"):
        # Initialize the classes like PacketCapture, TrafficAnalyzer, etc.
        self.packet_capture = PacketCapture()
        self.traffic_analyzer = TrafficAnalyzer()
        self.detection_engine = DetectionEngine()
        self.alert_system = AlertSystem()

        self.interface = interface
