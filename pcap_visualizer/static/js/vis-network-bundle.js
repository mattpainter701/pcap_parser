// First, define the vis object without attaching to window
const vis = {
    DataSet: class DataSet {
        constructor(data) {
            this.data = data || [];
            this.length = this.data.length;
        }
        
        forEach(callback) {
            this.data.forEach(callback);
        }
        
        update(item) {
            const index = this.data.findIndex(d => d.id === item.id);
            if (index !== -1) {
                this.data[index] = { ...this.data[index], ...item };
                // If we had a visualization rendered, we would update it here
            }
            return this;
        }
    },
    
    Network: class Network {
        constructor(container, data, options) {
            // Add error handling for null container
            if (!container) {
                console.error("Container element is null or undefined");
                throw new Error("Cannot initialize Network: container element is null or undefined");
            }
            
            this.container = container;
            this.data = data;
            this.options = options;
            this.events = {};
            
            // Check if data is valid
            if (!data || !data.nodes || !data.edges) {
                console.error("Invalid data format:", data);
                throw new Error("Cannot initialize Network: invalid data format");
            }
            
            // Clear the container
            this.container.innerHTML = '';
            
            // Create SVG element for visualization
            const width = this.container.clientWidth;
            const height = 600; // Fixed height as defined in CSS
            
            this.svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
            this.svg.setAttribute("width", width);
            this.svg.setAttribute("height", height);
            this.container.appendChild(this.svg);
            
            // Add zoom and pan controls
            this.setupZoomAndPan();
            
            // Create groups for links and nodes
            this.linksGroup = document.createElementNS("http://www.w3.org/2000/svg", "g");
            this.nodesGroup = document.createElementNS("http://www.w3.org/2000/svg", "g");
            
            this.svg.appendChild(this.linksGroup);
            this.svg.appendChild(this.nodesGroup);
            
            // Create a simple force-directed graph
            this.renderVisualization();
            
            // Dispatch stabilization event after a timeout
            setTimeout(() => {
                this._dispatchEvent("stabilizationIterationsDone");
            }, 500);
            
            this.gridSize = 20; // Default grid size
            this.snapToGrid = true;
            this.isDraggingNode = false;
            this.draggedNode = null;
            this.nodePositions = this.calculateOptimizedPositions(width, height);
            this.originalPositions = new WeakMap();
            
            // Add grid toggle button
            this.addGridToggle();
            // Add keyboard shortcuts
            this.addKeyboardControls();
            
            // Add transform state variables
            this.scale = 1;
            this.translateX = 0;
            this.translateY = 0;
            
            // Initialize grid
            this.drawGrid();
            
            // Add reset layout button
            this.addResetLayoutButton();
            
            // Add footer
            this.addFooter();
        }
        
        setupZoomAndPan() {
            // Replace let declarations with this references
            this.scale = 1;
            this.translateX = 0;
            this.translateY = 0;
            let isPanning = false;
            let startX, startY;
            
            // Create zoom buttons
            const zoomControls = document.createElement('div');
            zoomControls.style.position = 'absolute';
            zoomControls.style.top = '10px';
            zoomControls.style.left = '10px';
            zoomControls.style.zIndex = '100';
            zoomControls.style.display = 'flex';
            zoomControls.style.flexDirection = 'column';
            zoomControls.style.gap = '5px';
            
            const zoomInButton = document.createElement('button');
            zoomInButton.textContent = '+';
            zoomInButton.style.width = '30px';
            zoomInButton.style.height = '30px';
            zoomInButton.style.fontSize = '20px';
            zoomInButton.style.cursor = 'pointer';
            zoomInButton.style.backgroundColor = '#fff';
            zoomInButton.style.border = '1px solid #ccc';
            zoomInButton.style.borderRadius = '4px';
            
            const zoomOutButton = document.createElement('button');
            zoomOutButton.textContent = '-';
            zoomOutButton.style.width = '30px';
            zoomOutButton.style.height = '30px';
            zoomOutButton.style.fontSize = '20px';
            zoomOutButton.style.cursor = 'pointer';
            zoomOutButton.style.backgroundColor = '#fff';
            zoomOutButton.style.border = '1px solid #ccc';
            zoomOutButton.style.borderRadius = '4px';
            
            const resetZoomButton = document.createElement('button');
            resetZoomButton.textContent = '⟲';
            resetZoomButton.style.width = '30px';
            resetZoomButton.style.height = '30px';
            resetZoomButton.style.fontSize = '16px';
            resetZoomButton.style.cursor = 'pointer';
            resetZoomButton.style.backgroundColor = '#fff';
            resetZoomButton.style.border = '1px solid #ccc';
            resetZoomButton.style.borderRadius = '4px';
            
            zoomControls.appendChild(zoomInButton);
            zoomControls.appendChild(zoomOutButton);
            zoomControls.appendChild(resetZoomButton);
            
            this.container.appendChild(zoomControls);
            
            // Update transform function to use instance variables
            const updateTransform = () => {
                this.linksGroup.setAttribute('transform', 
                    `translate(${this.translateX},${this.translateY}) scale(${this.scale})`);
                this.nodesGroup.setAttribute('transform', 
                    `translate(${this.translateX},${this.translateY}) scale(${this.scale})`);
            };
            
            // Update zoom button handlers to modify this.scale
            zoomInButton.addEventListener('click', () => {
                this.scale = Math.min(this.scale * 1.2, 5);
                updateTransform();
            });
            
            zoomOutButton.addEventListener('click', () => {
                this.scale = Math.max(this.scale / 1.2, 0.2);
                updateTransform();
            });
            
            resetZoomButton.addEventListener('click', () => {
                this.scale = 1;
                this.translateX = 0;
                this.translateY = 0;
                updateTransform();
            });
            
            // Mouse wheel zoom
            this.svg.addEventListener('wheel', (e) => {
                e.preventDefault();
                const delta = e.deltaY > 0 ? 0.9 : 1.1;
                this.scale = Math.min(Math.max(this.scale * delta, 0.2), 5);
                updateTransform();
            });
            
            // Update pan handlers to use instance variables
            this.svg.addEventListener('mousedown', (e) => {
                // Only start panning if not clicking a node
                if (!e.target.closest('[data-id]')) {
                isPanning = true;
                    startX = e.clientX - this.translateX;
                    startY = e.clientY - this.translateY;
                this.svg.style.cursor = 'grabbing';
                }
            });
            
            this.svg.addEventListener('mousemove', (e) => {
                if (isPanning) {
                    this.translateX = e.clientX - startX;
                    this.translateY = e.clientY - startY;
                    updateTransform();
                }
            });
            
            this.svg.addEventListener('mouseup', () => {
                isPanning = false;
                this.svg.style.cursor = 'grab';
            });
            
            this.svg.addEventListener('mouseleave', () => {
                isPanning = false;
                this.svg.style.cursor = 'grab';
            });
            
            // Set initial cursor
            this.svg.style.cursor = 'grab';
        }
        
        renderVisualization() {
            const width = this.svg.getAttribute("width");
            const height = this.svg.getAttribute("height");
            
            // Calculate fresh positions for all nodes
            this.nodePositions = this.calculateOptimizedPositions(width, height);
            
            // Render edges and nodes with new positions
            this.renderEdges(this.nodePositions);
            this.renderNodes(this.nodePositions);
        }
        
        calculateOptimizedPositions(width, height) {
            const positions = {};
            const nodeData = this.data.nodes.data;
            
            // Group nodes by vendor for MAC addresses
            const vendorGroups = {};
            
            // Separate MAC and IP nodes
            const macNodes = nodeData.filter(node => node.group === 'mac');
            const ipNodes = nodeData.filter(node => node.group === 'ip');
            
            // Group MAC nodes by vendor
            macNodes.forEach(node => {
                let vendor = "Unknown";
                if (node.title) {
                    const titleMatch = node.title.match(/(.*?)<br\/>MAC: (.*)/);
                    if (titleMatch && titleMatch.length >= 3) {
                        vendor = titleMatch[1].trim();
                    }
                }
                
                if (!vendorGroups[vendor]) {
                    vendorGroups[vendor] = [];
                }
                vendorGroups[vendor].push(node);
            });
            
            // Calculate positions for MAC nodes by vendor group
            const vendorCount = Object.keys(vendorGroups).length;
            const macRadius = Math.min(width, height) * 0.45;
            let vendorIndex = 0;
            
            // Arrange MAC nodes in circles/arcs by vendor with better spacing
            for (const vendor in vendorGroups) {
                const nodes = vendorGroups[vendor];
                const vendorAngle = (vendorIndex / vendorCount) * 2 * Math.PI;
                const vendorX = width/2 + Math.cos(vendorAngle) * macRadius * 0.6;
                const vendorY = height/2 + Math.sin(vendorAngle) * macRadius * 0.6;
                
                // More space between nodes in the same vendor group
                const arcLength = Math.min(0.5, nodes.length * 0.05); // Limit arc size
                
                // Arrange nodes within vendor group in a small arc with more spacing
                nodes.forEach((node, i) => {
                    const nodeAngle = vendorAngle + ((i / (nodes.length - 1 || 1)) * arcLength - arcLength/2);
                    positions[node.id] = {
                        x: vendorX + Math.cos(nodeAngle) * (nodes.length > 1 ? 100 : 0),
                        y: vendorY + Math.sin(nodeAngle) * (nodes.length > 1 ? 100 : 0)
                    };
                });
                
                vendorIndex++;
            }
            
            // Group IP nodes by subnet
            const subnets = {};
            ipNodes.forEach(node => {
                const ip = node.label;
                const subnet = ip.split('.').slice(0, 3).join('.');
                if (!subnets[subnet]) {
                    subnets[subnet] = [];
                }
                subnets[subnet].push(node);
            });
            
            // Calculate positions for IP nodes by subnet with better spacing
            const subnetCount = Object.keys(subnets).length;
            const ipRadius = Math.min(width, height) * 0.45;
            let subnetIndex = 0;
            
            for (const subnet in subnets) {
                const nodes = subnets[subnet];
                const subnetAngle = (subnetIndex / subnetCount) * 2 * Math.PI;
                const subnetX = width/2 + Math.cos(subnetAngle) * ipRadius;
                const subnetY = height/2 + Math.sin(subnetAngle) * ipRadius;
                
                // More space between nodes in the same subnet
                const arcLength = Math.min(0.5, nodes.length * 0.05); // Limit arc size
                
                // Arrange nodes within subnet in a small arc with more spacing
                nodes.forEach((node, i) => {
                    const nodeAngle = subnetAngle + ((i / (nodes.length - 1 || 1)) * arcLength - arcLength/2);
                    positions[node.id] = {
                        x: subnetX + Math.cos(nodeAngle) * (nodes.length > 1 ? 80 : 0),
                        y: subnetY + Math.sin(nodeAngle) * (nodes.length > 1 ? 80 : 0)
                    };
                });
                
                subnetIndex++;
            }
            
            return positions;
        }
        
        renderEdges(nodePositions) {
            this.linksGroup.innerHTML = '';
            
            // Group edges by connection pairs to reduce visual clutter
            const connectionGroups = {};
            
            this.data.edges.data.forEach(edge => {
                const key = `${edge.from}_${edge.to}`;
                if (!connectionGroups[key]) {
                    connectionGroups[key] = {
                        from: edge.from,
                        to: edge.to,
                        protocols: {
                            tcp: new Set(),
                            udp: new Set()
                        },
                        edges: []
                    };
                }
                
                // Extract protocol and port info
                if (edge.title) {
                    const tcpMatch = edge.title.match(/TCP: ([\d,]+)/);
                    const udpMatch = edge.title.match(/UDP: ([\d,]+)/);
                    
                    if (tcpMatch) {
                        const tcpPorts = tcpMatch[1].split(',').map(p => parseInt(p.trim()));
                        tcpPorts.forEach(port => connectionGroups[key].protocols.tcp.add(port));
                    }
                    
                    if (udpMatch) {
                        const udpPorts = udpMatch[1].split(',').map(p => parseInt(p.trim()));
                        udpPorts.forEach(port => connectionGroups[key].protocols.udp.add(port));
                    }
                }
                
                connectionGroups[key].edges.push(edge);
            });
            
            // Create edges for each connection group
            Object.values(connectionGroups).forEach(group => {
                const sourcePos = nodePositions[group.from];
                const targetPos = nodePositions[group.to];
                
                if (!sourcePos || !targetPos) return;
                
                // Create the base connection line
                const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
                line.setAttribute("x1", sourcePos.x);
                line.setAttribute("y1", sourcePos.y);
                line.setAttribute("x2", targetPos.x);
                line.setAttribute("y2", targetPos.y);
                line.setAttribute("stroke", "#64748b");
                line.setAttribute("stroke-width", "1.5");
                
                // Add tooltip with all protocol details
                const tcpPorts = Array.from(group.protocols.tcp).sort((a, b) => a - b);
                const udpPorts = Array.from(group.protocols.udp).sort((a, b) => a - b);
                
                let tooltipText = '';
                if (tcpPorts.length > 0) {
                    tooltipText += `TCP: ${this.formatPortsWithServices(tcpPorts)}\n`;
                }
                if (udpPorts.length > 0) {
                    tooltipText += `UDP: ${this.formatPortsWithServices(udpPorts)}`;
                }
                
                if (tooltipText) {
                    const title = document.createElementNS("http://www.w3.org/2000/svg", "title");
                    title.textContent = tooltipText;
                    line.appendChild(title);
                }
                
                this.linksGroup.appendChild(line);
                
                // Add protocol labels
                const midX = (sourcePos.x + targetPos.x) / 2;
                const midY = (sourcePos.y + targetPos.y) / 2;
                
                const labelTypes = [];
                if (tcpPorts.length > 0) labelTypes.push("TCP");
                if (udpPorts.length > 0) labelTypes.push("UDP");
                
                if (labelTypes.length > 0) {
                    // Create a background for the text
                    const textBg = document.createElementNS("http://www.w3.org/2000/svg", "rect");
                    textBg.setAttribute("x", midX - 20);
                    textBg.setAttribute("y", midY - 10);
                    textBg.setAttribute("width", 40);
                    textBg.setAttribute("height", 20);
                    textBg.setAttribute("fill", "white");
                    textBg.setAttribute("rx", 5);
                    textBg.setAttribute("ry", 5);
                    textBg.setAttribute("stroke", "#64748b");
                    textBg.setAttribute("stroke-width", "0.5");
                    this.linksGroup.appendChild(textBg);
                    
                    const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
                    text.setAttribute("text-anchor", "middle");
                    text.setAttribute("dominant-baseline", "middle");
                    text.setAttribute("font-size", "10px");
                    text.setAttribute("fill", "#334155");
                    text.setAttribute("x", midX);
                    text.setAttribute("y", midY);
                    text.textContent = labelTypes.join("/");
                    this.linksGroup.appendChild(text);
                    
                    // Add service port labels if there are well-known ports
                    const wellKnownPorts = this.findWellKnownPorts([...tcpPorts, ...udpPorts]);
                    if (wellKnownPorts.length > 0) {
                        const portLabel = document.createElementNS("http://www.w3.org/2000/svg", "text");
                        portLabel.setAttribute("x", midX);
                        portLabel.setAttribute("y", midY + 18);
                        portLabel.setAttribute("text-anchor", "middle");
                        portLabel.setAttribute("font-size", "9px");
                        portLabel.setAttribute("fill", "#1e40af");
                        portLabel.textContent = wellKnownPorts.slice(0, 3).join(", ");
                        this.linksGroup.appendChild(portLabel);
                    }
                }
            });
        }
        
        findWellKnownPorts(ports) {
            // Map of well-known ports to service names
            const wellKnownServices = {
                20: "FTP-data",
                21: "FTP",
                22: "SSH",
                23: "Telnet",
                25: "SMTP",
                53: "DNS",
                80: "HTTP",
                110: "POP3",
                143: "IMAP",
                443: "HTTPS",
                445: "SMB",
                993: "IMAPS",
                995: "POP3S",
                3389: "RDP",
                8080: "HTTP-ALT",
                8443: "HTTPS-ALT"
            };
            
            return ports
                .filter(port => wellKnownServices[port])
                .map(port => `${wellKnownServices[port]}(${port})`);
        }
        
        formatPortsWithServices(ports) {
            if (ports.length <= 5) {
                return ports.join(", ");
            } else {
                const shownPorts = ports.slice(0, 5);
                return `${shownPorts.join(", ")} (+ ${ports.length - 5} more)`;
            }
        }
        
        renderNodes(nodePositions) {
            // Store previous positions before clearing
            const previousPositions = new Map();
            this.nodesGroup.childNodes.forEach(nodeGroup => {
                const id = nodeGroup.dataset.id;
                const transform = nodeGroup.getAttribute('transform');
                if (transform) {
                    const match = transform.match(/translate\(([\d.]+),([\d.]+)\)/);
                    if (match) {
                        previousPositions.set(id, {
                            x: parseFloat(match[1]),
                            y: parseFloat(match[2])
                        });
                    }
                }
            });

            // Clear existing nodes
            this.nodesGroup.innerHTML = '';
            
            // Merge previous positions with new calculations
            const mergedPositions = { ...nodePositions };
            previousPositions.forEach((pos, id) => {
                mergedPositions[id] = pos;
            });

            // Render nodes using merged positions
            this.data.nodes.data.forEach(node => {
                const pos = mergedPositions[node.id];
                if (!pos) return;
                
                const group = document.createElementNS("http://www.w3.org/2000/svg", "g");
                group.setAttribute("transform", `translate(${pos.x},${pos.y})`);
                
                // Set group data attributes
                group.dataset.id = node.id;
                group.dataset.group = node.group;
                
                // Create node shape based on group
                if (node.group === 'mac') {
                    // Rectangle for MAC with computer icon
                    const rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
                    rect.setAttribute("x", -50);
                    rect.setAttribute("y", -20);
                    rect.setAttribute("width", 100);
                    rect.setAttribute("height", 40);
                    rect.setAttribute("rx", 5);
                    rect.setAttribute("fill", "#4f46e5");
                    rect.setAttribute("stroke", "#3730a3");
                    rect.setAttribute("stroke-width", "2");
                    group.appendChild(rect);
                    
                    // Add computer icon
                    const iconGroup = document.createElementNS("http://www.w3.org/2000/svg", "g");
                    iconGroup.setAttribute("transform", "translate(-40, 0) scale(0.03)");
                    
                    // Simple computer icon
                    const monitor = document.createElementNS("http://www.w3.org/2000/svg", "path");
                    monitor.setAttribute("d", "M0 64v384h576V64H0zm544 352H32V96h512v320z");
                    monitor.setAttribute("fill", "#ffffff");
                    
                    const stand = document.createElementNS("http://www.w3.org/2000/svg", "path");
                    stand.setAttribute("d", "M224 448h128v32H224z");
                    stand.setAttribute("fill", "#ffffff");
                    
                    const base = document.createElementNS("http://www.w3.org/2000/svg", "path");
                    base.setAttribute("d", "M192 480h192v32H192z");
                    base.setAttribute("fill", "#ffffff");
                    
                    iconGroup.appendChild(monitor);
                    iconGroup.appendChild(stand);
                    iconGroup.appendChild(base);
                    group.appendChild(iconGroup);
                    
                    // Extract vendor name and MAC from title
                    let vendorName = "Unknown";
                    let macAddress = node.label;
                    
                    if (node.title) {
                        const titleMatch = node.title.match(/(.*?)<br\/>MAC: (.*)/);
                        if (titleMatch && titleMatch.length >= 3) {
                            vendorName = titleMatch[1].trim();
                            macAddress = titleMatch[2].trim();
                        }
                    }
                    
                    // Get last 4 characters of MAC address
                    const last4 = macAddress.slice(-5);
                    
                    // Create a better label with vendor name and last 4 of MAC
                    const label = `${vendorName}: ${last4}`;
                    
                    // Add node label
                    const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
                    text.setAttribute("text-anchor", "middle");
                    text.setAttribute("dominant-baseline", "middle");
                    text.setAttribute("font-size", "11px");
                    text.setAttribute("fill", "#333333"); // Dark gray for better visibility
                    text.setAttribute("x", 10); // Shift text to the right of the icon
                    text.setAttribute("y", 0);
                    text.textContent = label;
                    group.appendChild(text);
                    
                } else {
                    // Circle for IP with network icon
                    const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
                    circle.setAttribute("r", 20);
                    circle.setAttribute("fill", "#10b981");
                    circle.setAttribute("stroke", "#047857");
                    circle.setAttribute("stroke-width", "2");
                    group.appendChild(circle);
                    
                    // Add network/IP icon - simple globe
                    const iconGroup = document.createElementNS("http://www.w3.org/2000/svg", "g");
                    iconGroup.setAttribute("transform", "translate(-8, -8) scale(0.018)");
                    
                    // Simple globe icon
                    const globe = document.createElementNS("http://www.w3.org/2000/svg", "path");
                    globe.setAttribute("d", "M256 8C119 8 8 119 8 256s111 248 248 248 248-111 248-248S393 8 256 8zm57.1 350.1L224.9 294c-3.1-2.3-4.9-5.9-4.9-9.7V116c0-6.6 5.4-12 12-12h48c6.6 0 12 5.4 12 12v137.7l63.5 46.2c5.4 3.9 6.5 11.4 2.6 16.8l-28.2 38.8c-3.9 5.3-11.4 6.5-16.8 2.6z");
                    globe.setAttribute("fill", "#ffffff");
                    
                    iconGroup.appendChild(globe);
                    group.appendChild(iconGroup);
                    
                    // Add node label
                    const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
                    text.setAttribute("text-anchor", "middle");
                    text.setAttribute("dominant-baseline", "middle");
                    text.setAttribute("font-size", "12px");
                    text.setAttribute("fill", "#333333"); // Dark gray for better visibility
                    text.setAttribute("y", 30); // Position label below the circle
                    text.textContent = node.label;
                    group.appendChild(text);
                }
                
                // Add node title/tooltip
                if (node.title) {
                    const title = document.createElementNS("http://www.w3.org/2000/svg", "title");
                    title.textContent = node.title;
                    group.appendChild(title);
                }
                
                // Make nodes interactive
                group.style.cursor = 'pointer';
                group.addEventListener('mouseover', () => {
                    if (node.group === 'mac') {
                        const rect = group.querySelector('rect');
                        rect.setAttribute("fill", "#818cf8");
                        rect.setAttribute("stroke-width", "3");
                    } else {
                        const circle = group.querySelector('circle');
                        circle.setAttribute("fill", "#34d399");
                        circle.setAttribute("stroke-width", "3");
                    }
                });
                
                group.addEventListener('mouseout', () => {
                    if (node.group === 'mac') {
                        const rect = group.querySelector('rect');
                        rect.setAttribute("fill", "#4f46e5");
                        rect.setAttribute("stroke-width", "2");
                    } else {
                        const circle = group.querySelector('circle');
                        circle.setAttribute("fill", "#10b981");
                        circle.setAttribute("stroke-width", "2");
                    }
                });
                
                // Add drag handlers
                group.addEventListener('mousedown', (e) => this.startDrag(node, e));
                
                this.nodesGroup.appendChild(group);
            });
        }
        
        on(event, callback) {
            if (!this.events[event]) {
                this.events[event] = [];
            }
            this.events[event].push(callback);
            return this;
        }
        
        once(event, callback) {
            if (!this.events[event]) {
                this.events[event] = [];
            }
            const wrappedCallback = (params) => {
                callback(params);
                this.events[event] = this.events[event].filter(cb => cb !== wrappedCallback);
            };
            this.events[event].push(wrappedCallback);
            return this;
        }
        
        _dispatchEvent(event, params = {}) {
            if (this.events[event]) {
                this.events[event].forEach(callback => callback(params));
            }
        }
        
        focus(nodeId, options = {}) {
            // Stub method for focusing on a node
            console.log(`Focusing on node: ${nodeId}`);
            return this;
        }
        
        setOptions(options) {
            this.options = { ...this.options, ...options };
            
            // Track the current layout mode
            if (options.layout) {
                if (options.layout.hierarchical && options.layout.hierarchical.enabled === true) {
                    this.currentLayoutMode = 'hierarchical';
                    this.renderHierarchicalLayout();
                } else if (options.layout.hierarchical && options.layout.hierarchical.enabled === false) {
                    this.currentLayoutMode = 'force-directed';
                    this.renderForceDirectedLayout();
                }
            } else if (options.physics && options.physics.enabled) {
                this.renderForceDirectedLayout();
            }
            
            if (options.grid) {
                this.gridSize = options.grid.size || 20;
                this.snapToGrid = options.grid.snap !== undefined ? options.grid.snap : true;
                this.drawGrid();
            }
            
            return this;
        }
        
        renderHierarchicalLayout() {
            console.log("Rendering hierarchical layout");
            
            const width = this.svg.getAttribute("width");
            const height = this.svg.getAttribute("height");
            
            // Reset view transformations
            this.scale = 1;
            this.translateX = 0;
            this.translateY = 0;
            
            // Clear any existing force-directed layout
            this.linksGroup.innerHTML = '';
            this.nodesGroup.innerHTML = '';
            
            // Reset node positions from scratch
            const positions = {};
            const nodeData = this.data.nodes.data;
            
            // Separate MAC and IP nodes
            const macNodes = nodeData.filter(node => node.group === 'mac');
            const ipNodes = nodeData.filter(node => node.group === 'ip');
            
            // Calculate margins and usable space
            const margin = 50;
            const usableWidth = width - (margin * 2);
            const usableHeight = height - (margin * 2);
            
            // Calculate vertical spacing
            const macSpacing = Math.min(80, usableHeight / (macNodes.length + 1));
            const ipSpacing = Math.min(80, usableHeight / (ipNodes.length + 1));
            
            // Position MAC nodes on the left
            macNodes.forEach((node, i) => {
                positions[node.id] = {
                    x: margin + (usableWidth * 0.25),
                    y: margin + ((i + 1) * macSpacing)
                };
            });
            
            // Position IP nodes on the right
            ipNodes.forEach((node, i) => {
                positions[node.id] = {
                    x: margin + (usableWidth * 0.75),
                    y: margin + ((i + 1) * ipSpacing)
                };
            });
            
            // Completely replace node positions
            this.nodePositions = positions;
            
            // Render with new positions
            this.renderEdges(positions);
            this.renderNodes(positions);
            
            // Update transform
            this.linksGroup.setAttribute('transform', 
                `translate(${this.translateX},${this.translateY}) scale(${this.scale})`);
            this.nodesGroup.setAttribute('transform', 
                `translate(${this.translateX},${this.translateY}) scale(${this.scale})`);
        }
        
        renderForceDirectedLayout() {
            console.log("Rendering force-directed layout");
            
            // Clear any existing hierarchical layout
            this.linksGroup.innerHTML = '';
            this.nodesGroup.innerHTML = '';
            
            // Calculate fresh force-directed positions for all nodes
            const width = this.svg.getAttribute("width");
            const height = this.svg.getAttribute("height");
            
            this.nodePositions = this.calculateOptimizedPositions(width, height);
            
            // Render with new positions
            this.renderEdges(this.nodePositions);
            this.renderNodes(this.nodePositions);
            
            // Update transform
            this.linksGroup.setAttribute('transform', 
                `translate(${this.translateX},${this.translateY}) scale(${this.scale})`);
            this.nodesGroup.setAttribute('transform', 
                `translate(${this.translateX},${this.translateY}) scale(${this.scale})`);
        }

        // Add new method for grid background
        drawGrid() {
            const gridGroup = document.createElementNS("http://www.w3.org/2000/svg", "g");
            const width = this.svg.getAttribute("width");
            const height = this.svg.getAttribute("height");
            
            // Draw vertical lines
            for (let x = 0; x <= width; x += this.gridSize) {
                const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
                line.setAttribute("x1", x);
                line.setAttribute("y1", 0);
                line.setAttribute("x2", x);
                line.setAttribute("y2", height);
                line.setAttribute("stroke", "#e2e8f0");
                line.setAttribute("stroke-width", "0.5");
                gridGroup.appendChild(line);
            }

            // Draw horizontal lines
            for (let y = 0; y <= height; y += this.gridSize) {
                const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
                line.setAttribute("x1", 0);
                line.setAttribute("y1", y);
                line.setAttribute("x2", width);
                line.setAttribute("y2", y);
                line.setAttribute("stroke", "#e2e8f0");
                line.setAttribute("stroke-width", "0.5");
                gridGroup.appendChild(line);
            }

            this.svg.insertBefore(gridGroup, this.linksGroup);
        }

        // Update the drag handling methods
        startDrag(node, event) {
            event.stopPropagation(); // Prevent SVG pan
            this.isDraggingNode = true;
            this.draggedNode = node;
            
            // Store initial mouse position
            const rect = this.svg.getBoundingClientRect();
            this.dragStartX = event.clientX;
            this.dragStartY = event.clientY;
            
            // Store initial node position
            const nodeElement = this.nodesGroup.querySelector(`[data-id="${node.id}"]`);
            const transform = nodeElement.getAttribute('transform');
            const match = transform.match(/translate\(([\d.]+),([\d.]+)\)/);
            if (match) {
                this.dragInitialX = parseFloat(match[1]);
                this.dragInitialY = parseFloat(match[2]);
            }
            
            // Add document-level event listeners for drag
            document.addEventListener('mousemove', this.handleDragMove);
            document.addEventListener('mouseup', this.handleDragEnd);
            
            this.svg.style.cursor = 'grabbing';
        }

        // Add method to handle coordinate transformations
        transformCoordinate(x, y) {
            return {
                x: (x - this.translateX) / this.scale,
                y: (y - this.translateY) / this.scale
            };
        }

        // Update handleDragMove to properly update edges
        handleDragMove = (event) => {
            if (!this.isDraggingNode) return;
            
            event.preventDefault();
            
            // Calculate the distance moved
            const dx = (event.clientX - this.dragStartX) / this.scale;
            const dy = (event.clientY - this.dragStartY) / this.scale;
            
            // Calculate new position
            let newX = this.dragInitialX + dx;
            let newY = this.dragInitialY + dy;
            
            if (this.snapToGrid) {
                newX = Math.round(newX / this.gridSize) * this.gridSize;
                newY = Math.round(newY / this.gridSize) * this.gridSize;
            }
            
            // Update node position
            const nodeElement = this.nodesGroup.querySelector(`[data-id="${this.draggedNode.id}"]`);
            if (nodeElement) {
                nodeElement.setAttribute('transform', `translate(${newX},${newY})`);
                // Store the position in the original coordinate space
                this.nodePositions[this.draggedNode.id] = { x: newX, y: newY };
                // Update edges with the new position
                this.renderEdges(this.nodePositions);
            }
        }

        handleDragEnd = (event) => {
            if (!this.isDraggingNode) return;
            
            // Remove document-level event listeners
            document.removeEventListener('mousemove', this.handleDragMove);
            document.removeEventListener('mouseup', this.handleDragEnd);
            
            this.isDraggingNode = false;
            this.draggedNode = null;
            this.svg.style.cursor = 'grab';
            
            this._dispatchEvent("dragEnd", { 
                node: this.draggedNode, 
                positions: this.nodePositions 
            });
        }

        // Add grid toggle controls
        addGridToggle() {
            const gridToggle = document.createElement('button');
            gridToggle.textContent = 'Grid';
            gridToggle.style.position = 'absolute';
            gridToggle.style.top = '120px';
            gridToggle.style.left = '10px';
            gridToggle.addEventListener('click', () => {
                this.gridSize = this.gridSize === 20 ? 40 : 20;
                this.drawGrid();
                this.renderVisualization();
            });
            this.container.appendChild(gridToggle);
        }

        // Add keyboard controls
        addKeyboardControls() {
            document.addEventListener('keydown', (e) => {
                if (e.ctrlKey && e.key === 'g') {
                    this.drawGrid();
                }
                if (e.ctrlKey && e.key === 's') {
                    this.snapToGrid = !this.snapToGrid;
                }
            });
        }

        // Add a method to create a reset layout button
        addResetLayoutButton() {
            const resetLayoutBtn = document.createElement('button');
            resetLayoutBtn.textContent = 'Reset Layout';
            resetLayoutBtn.style.position = 'absolute';
            resetLayoutBtn.style.top = '160px';
            resetLayoutBtn.style.left = '10px';
            resetLayoutBtn.style.width = '100px';
            resetLayoutBtn.style.height = '30px';
            resetLayoutBtn.style.fontSize = '12px';
            resetLayoutBtn.style.cursor = 'pointer';
            resetLayoutBtn.style.backgroundColor = '#fff';
            resetLayoutBtn.style.border = '1px solid #ccc';
            resetLayoutBtn.style.borderRadius = '4px';
            
            resetLayoutBtn.addEventListener('click', () => {
                console.log("Resetting layout, current mode:", this.currentLayoutMode);
                
                // Reset transformation
                this.scale = 1;
                this.translateX = 0;
                this.translateY = 0;
                
                // Reset based on current layout mode
                if (this.currentLayoutMode === 'hierarchical') {
                    this.renderHierarchicalLayout();
                } else {
                    // Use renderForceDirectedLayout instead of renderVisualization 
                    // to maintain connection consistency
                    this.renderForceDirectedLayout();
                }
            });
            
            this.container.appendChild(resetLayoutBtn);
        }

        // Add method for creating a footer
        addFooter() {
            const footer = document.createElement('div');
            footer.textContent = '2025 Matts PCAP Network Visualizer';
            footer.style.position = 'absolute';
            footer.style.bottom = '5px';
            footer.style.right = '10px';
            footer.style.fontSize = '12px';
            footer.style.color = '#64748b';
            footer.style.fontWeight = '500';
            footer.style.padding = '5px';
            footer.style.backgroundColor = 'rgba(255, 255, 255, 0.7)';
            footer.style.borderRadius = '4px';
            
            this.container.appendChild(footer);
        }
    }
};

// Then export it for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = vis;
} else if (typeof define === 'function' && define.amd) {
    define(['vis'], function() { return vis; });
} else {
    // Finally, attach to window for global usage
    window.vis = vis;
}

// Make sure it's immediately available
if (typeof window !== 'undefined') {
    window.vis = vis;
} 