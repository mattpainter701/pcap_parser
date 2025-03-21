import os
import csv
import json
import datetime
import time
from flask import Flask, render_template, request, jsonify, redirect, url_for
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'outputs')
app.config['ALLOWED_EXTENSIONS'] = {'csv', 'json'}

# Ensure upload folder exists with proper permissions
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Add timestamp_to_datetime filter
@app.template_filter('timestamp_to_datetime')
def timestamp_to_datetime(timestamp):
    """Convert a Unix timestamp to a formatted date string."""
    dt = datetime.datetime.fromtimestamp(timestamp)
    return dt.strftime('%Y-%m-%d %H:%M:%S')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def parse_csv_file(file_path):
    """Parse a CSV file with network data and return structured data for visualization."""
    nodes = []
    edges = []
    
    # Track nodes by MAC address to avoid duplicates
    mac_nodes = {}
    ip_nodes = {}
    
    with open(file_path, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            mac = row['MAC Address']
            vendor = row['Vendor']
            ip = row['IP Address']
            tcp_ports = row['TCP Ports']
            udp_ports = row['UDP Ports']
            
            # Add MAC node if not already added
            if mac not in mac_nodes:
                mac_node_id = f"mac_{mac.replace(':', '_')}"
                mac_nodes[mac] = {
                    'id': mac_node_id,
                    'label': mac,
                    'title': f"{vendor}<br/>MAC: {mac}",
                    'group': 'mac',
                    'shape': 'square',
                    'color': {
                        'background': '#97C2FC',
                        'border': '#2B7CE9'
                    },
                    'font': {
                        'size': 12,
                        'face': 'arial'
                    },
                    'size': 25  # Size for D3-like consistent node sizing
                }
                nodes.append(mac_nodes[mac])
            
            # Add IP node if not already added
            if ip and ip not in ip_nodes:
                ip_node_id = f"ip_{ip.replace('.', '_')}"
                ip_nodes[ip] = {
                    'id': ip_node_id,
                    'label': ip,
                    'title': f"IP: {ip}",
                    'group': 'ip',
                    'shape': 'circle',
                    'color': {
                        'background': '#FB7E81',
                        'border': '#FA0010'
                    },
                    'font': {
                        'size': 12,
                        'face': 'arial'
                    },
                    'size': 20  # Size for D3-like consistent node sizing
                }
                nodes.append(ip_nodes[ip])
            
            # Add edge between MAC and IP
            if ip:
                edge_id = f"{mac_nodes[mac]['id']}_{ip_nodes[ip]['id']}"
                
                # Create a label with TCP/UDP ports if available
                ports_label = []
                if tcp_ports:
                    ports_label.append(f"TCP: {tcp_ports}")
                if udp_ports:
                    ports_label.append(f"UDP: {udp_ports}")
                
                edge_label = "<br>".join(ports_label) if ports_label else ""
                
                edge = {
                    'id': edge_id,
                    'from': mac_nodes[mac]['id'],
                    'to': ip_nodes[ip]['id'],
                    'title': edge_label,
                    'label': f"TCP/UDP" if ports_label else "",
                    'width': 2,
                    'length': 200,  # Fixed length similar to D3 examples
                    'color': {
                        'color': '#848484',
                        'highlight': '#848484'
                    }
                }
                
                # Only add the edge if it doesn't already exist
                if not any(e['id'] == edge_id for e in edges):
                    edges.append(edge)
    
    return {
        'nodes': nodes,
        'edges': edges
    }

def parse_json_file(file_path):
    """Parse a JSON file containing network data for visualization."""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            
        # Validate the JSON structure
        if not isinstance(data, dict):
            return {'nodes': [], 'edges': []}
            
        if 'nodes' not in data or not isinstance(data['nodes'], list):
            data['nodes'] = []
            
        if 'edges' not in data or not isinstance(data['edges'], list):
            data['edges'] = []
            
        return data
    except Exception as e:
        app.logger.error(f"Error parsing JSON file: {str(e)}")
        return {'nodes': [], 'edges': []}

@app.route('/')
def index():
    # Get list of JSON files in the outputs directory - refresh on each request
    files = []
    # Ensure the directory exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    for filename in os.listdir(app.config['UPLOAD_FOLDER']):
        if filename.endswith('.json'):  # Only include JSON files
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.isfile(file_path):  # Extra check to ensure it's a file
                files.append({
                    'name': filename,
                    'path': file_path,
                    'date': os.path.getmtime(file_path),
                    'type': 'json'
                })
    
    # Sort by date, newest first
    files.sort(key=lambda x: x['date'], reverse=True)
    
    return render_template('index.html', files=files)

@app.route('/visualize/<filename>')
def visualize(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(filename))
    if not os.path.exists(file_path):
        return redirect(url_for('index'))
    
    return render_template('visualize.html', filename=filename)

@app.route('/api/network_data/<filename>')
def network_data(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(filename))
    if not os.path.exists(file_path):
        return jsonify({'error': 'File not found', 'nodes': [], 'edges': []}), 404
    
    try:
        # Determine file type and parse accordingly
        if filename.endswith('.json'):
            data = parse_json_file(file_path)
        else:  # Default to CSV
            data = parse_csv_file(file_path)
        
        # Validate data structure
        if not isinstance(data, dict):
            data = {'nodes': [], 'edges': []}
        
        # Ensure nodes and edges are lists
        if 'nodes' not in data or not isinstance(data['nodes'], list):
            data['nodes'] = []
        if 'edges' not in data or not isinstance(data['edges'], list):
            data['edges'] = []
            
        return jsonify(data)
    except Exception as e:
        app.logger.error(f"Error processing file {filename}: {str(e)}")
        # Return an empty but valid structure in case of error
        return jsonify({
            'error': str(e),
            'nodes': [],
            'edges': []
        }), 500

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return redirect(url_for('index'))
    
    file = request.files['file']
    # Only allow JSON files
    if file.filename == '' or not file.filename.lower().endswith('.json'):
        return redirect(url_for('index'))
    
    # Ensure upload directory exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Secure filename to prevent path traversal
    filename = secure_filename(file.filename)
    output_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    # Check if file already exists and handle accordingly (avoid permission issues)
    if os.path.exists(output_path):
        try:
            os.remove(output_path)  # Remove existing file first
        except (OSError, PermissionError) as e:
            # If we can't remove, use a different name
            base, ext = os.path.splitext(filename)
            filename = f"{base}_{int(time.time())}{ext}"
            output_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    # Save the file with proper error handling
    try:
        file.save(output_path)
    except (OSError, PermissionError) as e:
        # Log the error and provide feedback
        app.logger.error(f"Error saving file: {e}")
        return jsonify({'error': str(e)}), 500
    
    return redirect(url_for('visualize', filename=filename))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000) 