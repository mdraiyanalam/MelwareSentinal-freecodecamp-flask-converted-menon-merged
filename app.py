from flask import Flask, jsonify, render_template
from scapy.all import sniff
import threading

from classes import TrafficAnalyzer, DetectionEngine, AlertSystem

app = Flask(__name__)

# Initialize IDS components
traffic_analyzer = TrafficAnalyzer()
detection_engine = DetectionEngine()
alert_system = AlertSystem()

capturing = False  # Capture state
captured_packets = []  # Store packet summaries

# Function to process packets
def process_packet(packet):
    global captured_packets
    features = traffic_analyzer.analyze_packet(packet)
    if features:
        threats = detection_engine.detect_threats(features)
        if threats:
            print(f"Threats detected: {threats}")
            captured_packets.append({"summary": str(packet.summary())})  # Store summary
            return threats
    return []

# Background packet capture
def packet_capture():
    global capturing
    while capturing:
        sniff(prn=process_packet, count=10, store=False)

# Start capture
@app.route('/start_capture')
def start_capture():
    global capturing
    if not capturing:
        capturing = True
        thread = threading.Thread(target=packet_capture, daemon=True)
        thread.start()
        return jsonify({"message": "Packet capture started"})
    return jsonify({"message": "Capture already running"})

# Stop capture
@app.route('/stop_capture')
def stop_capture():
    global capturing
    capturing = False
    return jsonify({"message": "Packet capture stopped"})

# Get captured packets
@app.route('/get_packets')
def get_packets():
    return jsonify(captured_packets)

# System status
@app.route('/status')
def system_status():
    return jsonify({"status": "IDS is active"})

# Home page
@app.route('/')
def home():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
