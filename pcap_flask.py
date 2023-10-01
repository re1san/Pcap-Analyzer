import os
from flask import Flask, render_template, request, redirect, session
from flask_session import Session
from scapy.all import rdpcap
import json

app = Flask(__name__)
app.secret_key = 'key'
app.config['UPLOAD_FOLDER'] = 'uploads'

# Configure session to use filesystem
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

@app.route('/')
def index():
    return render_template('home.html')

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return redirect(request.url)
    
    file = request.files['file']
    
    if file.filename == '':
        return redirect(request.url)

    if file:
        filename = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filename)
        return render_template('home.html', filename=filename)

@app.route('/view_report/<filename>')
def view_report(filename):
    try:
        packets = rdpcap(filename)
        from pcap_analyzer import processor
        processed_packets, system_port, destination_port = processor(packets)
        session['processed_packets'] = processed_packets
        session['system_port'] = system_port
        session['destination_port'] = destination_port
        return render_template('report.html')
    except Exception as e:
        return f"Error: {e}"

@app.route("/data_link_layer/")
def data_link_layer():
    packets = session.get('processed_packets')
    numbers = []
    if packets:
        packets = packets.get("datalink_layer", [])
        numbers = [len(packets["ethernet"])-1, len(packets["STP"])-1, len(packets["ieee 802.11"])-1]
        numbers_json = json.dumps(numbers)
    return render_template("data_link_layer.html",packets=packets,numbers= numbers_json)

@app.route("/arp/")
def arp():
    packets = session.get('processed_packets')
    if packets:
        packets = packets.get("arp", [])
    return render_template("arp.html", packets=packets)

@app.route("/network_layer/")
def network_layer():
    packets = session.get('processed_packets')
    if packets:
        packets = packets.get("network_layer", [])
        print(packets["ipv4"][1])
        numbers = [len(packets["ipv4"])-1, len(packets["ipv6"])-1]
        numbers_json = json.dumps(numbers)
    return render_template("network_layer.html", packets=packets,numbers=numbers_json)

@app.route("/icmp/")
def icmp():
    packets = session.get('processed_packets')
    if packets:
        packets = packets.get("icmp", [])
    return render_template("icmp.html", packets=packets)

@app.route("/transport_layer/")
def transport_layer():
    packets = session.get('processed_packets')
    if packets:
        packets = packets.get("transport_layer", [])
        numbers = [len(packets["tcp"])-1, len(packets["udp"])-1]
        numbers_json = json.dumps(numbers)
    return render_template("transport_layer.html", packets=packets,numbers = numbers_json)

@app.route("/application_layer/")
def application_layer():
    system_port = session.get('system_port',{})
    destination_port = session.get('destination_port',{})
    return render_template("application_layer.html",system_port = system_port,destination_port = destination_port)

@app.route("/dns/")
def dns():
    packets = session.get('processed_packets')
    if packets:
        packets = packets.get("dns", [])
    return render_template("dns.html", packets=packets)

if __name__ == '__main__':
    app.run(debug=True)
