/**
 * Data Flow Visualization for Healthcare AI Compliance Platform
 * Uses D3.js to create interactive network diagrams showing data flow between AI agents
 */

// Global variables for data flow visualization
let dataFlowSvg;
let dataFlowSimulation;
let dataFlowNodes = [];
let dataFlowLinks = [];
let nodeElements;
let linkElements;
let labelElements;

// Visualization dimensions
const DATA_FLOW_WIDTH = 1200;
const DATA_FLOW_HEIGHT = 500;
const NODE_RADIUS = 25;

// Color scheme for different AI agent types
const NODE_COLORS = {
    'Medical Imaging AI': '#ff6b6b',
    'Clinical Decision Support': '#4ecdc4',
    'Healthcare NLP AI': '#45b7d1',
    'Drug Discovery AI': '#96ceb4',
    'EHR AI Assistant': '#feca57',
    'Patient Monitoring AI': '#ff9ff3',
    'default': '#a8a8a8'
};

// Initialize data flow visualization
function initializeDataFlowVisualization() {
    setupDataFlowSVG();
    loadDataFlowData();
}

/**
 * Setup the SVG container for data flow visualization
 */
function setupDataFlowSVG() {
    const container = document.getElementById('dataFlowVisualization');
    if (!container) return;

    // Clear any existing content
    container.innerHTML = '';

    // Create SVG element
    dataFlowSvg = d3.select('#dataFlowVisualization')
        .append('svg')
        .attr('width', '100%')
        .attr('height', DATA_FLOW_HEIGHT)
        .attr('viewBox', `0 0 ${DATA_FLOW_WIDTH} ${DATA_FLOW_HEIGHT}`)
        .style('background', 'var(--bs-dark)')
        .style('border-radius', '0.375rem');

    // Add zoom behavior
    const zoom = d3.zoom()
        .scaleExtent([0.1, 4])
        .on('zoom', function(event) {
            dataFlowSvg.select('g').attr('transform', event.transform);
        });

    dataFlowSvg.call(zoom);

    // Create main group for all elements
    const mainGroup = dataFlowSvg.append('g');

    // Add arrow markers for links
    dataFlowSvg.append('defs').selectAll('marker')
        .data(['PHI', 'PII', 'Clinical Data', 'General'])
        .enter()
        .append('marker')
        .attr('id', d => `arrow-${d.replace(/\s+/g, '')}`)
        .attr('viewBox', '0 -5 10 10')
        .attr('refX', NODE_RADIUS + 5)
        .attr('refY', 0)
        .attr('markerWidth', 6)
        .attr('markerHeight', 6)
        .attr('orient', 'auto')
        .append('path')
        .attr('d', 'M0,-5L10,0L0,5')
        .attr('fill', d => getDataTypeColor(d));

    // Setup force simulation
    dataFlowSimulation = d3.forceSimulation()
        .force('link', d3.forceLink().id(d => d.id).distance(150))
        .force('charge', d3.forceManyBody().strength(-400))
        .force('center', d3.forceCenter(DATA_FLOW_WIDTH / 2, DATA_FLOW_HEIGHT / 2))
        .force('collision', d3.forceCollide().radius(NODE_RADIUS + 10));
}

/**
 * Load data flow data from API
 */
function loadDataFlowData() {
    fetch('/api/data-flow')
        .then(response => response.json())
        .then(data => {
            dataFlowNodes = data.nodes;
            dataFlowLinks = data.links;
            updateDataFlowVisualization();
        })
        .catch(error => {
            console.error('Error loading data flow data:', error);
            // Load mock data if API fails
            loadMockDataFlowData();
        });
}

/**
 * Load mock data for demonstration
 */
function loadMockDataFlowData() {
    dataFlowNodes = [
        {
            id: 1,
            name: 'Medical Imaging AI',
            type: 'Medical Imaging AI',
            protocol: 'grpc',
            risk_level: 'medium'
        },
        {
            id: 2,
            name: 'Clinical Decision Support',
            type: 'Clinical Decision Support',
            protocol: 'rest_api',
            risk_level: 'low'
        },
        {
            id: 3,
            name: 'EHR Assistant',
            type: 'EHR AI Assistant',
            protocol: 'websocket',
            risk_level: 'high'
        },
        {
            id: 4,
            name: 'Patient Monitor',
            type: 'Patient Monitoring AI',
            protocol: 'mqtt',
            risk_level: 'medium'
        },
        {
            id: 5,
            name: 'Drug Discovery',
            type: 'Drug Discovery AI',
            protocol: 'kubernetes',
            risk_level: 'low'
        },
        {
            id: 6,
            name: 'Healthcare NLP',
            type: 'Healthcare NLP AI',
            protocol: 'docker',
            risk_level: 'medium'
        }
    ];

    dataFlowLinks = [
        {
            source: 1,
            target: 2,
            data_type: 'Clinical Data',
            volume: 85,
            encryption: 'TLS',
            compliance: 'compliant'
        },
        {
            source: 2,
            target: 3,
            data_type: 'PHI',
            volume: 120,
            encryption: 'TLS',
            compliance: 'compliant'
        },
        {
            source: 4,
            target: 2,
            data_type: 'PHI',
            volume: 200,
            encryption: 'TLS',
            compliance: 'non-compliant'
        },
        {
            source: 3,
            target: 5,
            data_type: 'General',
            volume: 45,
            encryption: 'None',
            compliance: 'non-compliant'
        },
        {
            source: 6,
            target: 2,
            data_type: 'Clinical Data',
            volume: 95,
            encryption: 'TLS',
            compliance: 'compliant'
        },
        {
            source: 1,
            target: 6,
            data_type: 'PII',
            volume: 60,
            encryption: 'AES',
            compliance: 'compliant'
        }
    ];

    updateDataFlowVisualization();
}

/**
 * Update the data flow visualization
 */
function updateDataFlowVisualization() {
    if (!dataFlowSvg || !dataFlowNodes.length) return;

    const mainGroup = dataFlowSvg.select('g');

    // Update links
    linkElements = mainGroup.selectAll('.link')
        .data(dataFlowLinks)
        .enter()
        .append('line')
        .attr('class', 'link')
        .attr('stroke', d => getDataTypeColor(d.data_type))
        .attr('stroke-width', d => Math.max(2, d.volume / 30))
        .attr('stroke-dasharray', d => d.compliance === 'non-compliant' ? '5,5' : 'none')
        .attr('marker-end', d => `url(#arrow-${d.data_type.replace(/\s+/g, '')})`)
        .style('opacity', 0.7);

    // Update nodes
    nodeElements = mainGroup.selectAll('.node')
        .data(dataFlowNodes)
        .enter()
        .append('circle')
        .attr('class', 'node')
        .attr('r', NODE_RADIUS)
        .attr('fill', d => NODE_COLORS[d.type] || NODE_COLORS.default)
        .attr('stroke', d => getRiskLevelColor(d.risk_level))
        .attr('stroke-width', 3)
        .style('cursor', 'pointer')
        .call(d3.drag()
            .on('start', dragstarted)
            .on('drag', dragged)
            .on('end', dragended))
        .on('mouseover', handleNodeMouseOver)
        .on('mouseout', handleNodeMouseOut)
        .on('click', handleNodeClick);

    // Add node labels
    labelElements = mainGroup.selectAll('.label')
        .data(dataFlowNodes)
        .enter()
        .append('text')
        .attr('class', 'label')
        .attr('text-anchor', 'middle')
        .attr('dy', NODE_RADIUS + 15)
        .style('fill', 'white')
        .style('font-size', '12px')
        .style('font-weight', 'bold')
        .style('pointer-events', 'none')
        .text(d => d.name.length > 15 ? d.name.substring(0, 15) + '...' : d.name);

    // Add protocol icons
    const iconElements = mainGroup.selectAll('.icon')
        .data(dataFlowNodes)
        .enter()
        .append('text')
        .attr('class', 'icon')
        .attr('text-anchor', 'middle')
        .attr('dy', 4)
        .style('fill', 'white')
        .style('font-size', '14px')
        .style('font-family', 'Font Awesome 6 Free')
        .style('font-weight', '900')
        .style('pointer-events', 'none')
        .text(d => getProtocolIcon(d.protocol));

    // Start simulation
    dataFlowSimulation
        .nodes(dataFlowNodes)
        .on('tick', ticked);

    dataFlowSimulation.force('link')
        .links(dataFlowLinks);

    // Add legend
    addDataFlowLegend();
}

/**
 * Animation function for force simulation
 */
function ticked() {
    if (linkElements) {
        linkElements
            .attr('x1', d => d.source.x)
            .attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x)
            .attr('y2', d => d.target.y);
    }

    if (nodeElements) {
        nodeElements
            .attr('cx', d => d.x)
            .attr('cy', d => d.y);
    }

    if (labelElements) {
        labelElements
            .attr('x', d => d.x)
            .attr('y', d => d.y);
    }

    if (dataFlowSvg.selectAll('.icon').node()) {
        dataFlowSvg.selectAll('.icon')
            .attr('x', d => d.x)
            .attr('y', d => d.y);
    }
}

/**
 * Drag event handlers
 */
function dragstarted(event, d) {
    if (!event.active) dataFlowSimulation.alphaTarget(0.3).restart();
    d.fx = d.x;
    d.fy = d.y;
}

function dragged(event, d) {
    d.fx = event.x;
    d.fy = event.y;
}

function dragended(event, d) {
    if (!event.active) dataFlowSimulation.alphaTarget(0);
    d.fx = null;
    d.fy = null;
}

/**
 * Node interaction handlers
 */
function handleNodeMouseOver(event, d) {
    // Highlight node and connected links
    d3.select(this)
        .transition()
        .duration(200)
        .attr('r', NODE_RADIUS * 1.2)
        .attr('stroke-width', 5);

    // Show tooltip
    showDataFlowTooltip(event, d);

    // Highlight connected links
    linkElements
        .style('opacity', link => 
            link.source.id === d.id || link.target.id === d.id ? 1 : 0.2
        );
}

function handleNodeMouseOut(event, d) {
    // Reset node appearance
    d3.select(this)
        .transition()
        .duration(200)
        .attr('r', NODE_RADIUS)
        .attr('stroke-width', 3);

    // Hide tooltip
    hideDataFlowTooltip();

    // Reset link opacity
    linkElements.style('opacity', 0.7);
}

function handleNodeClick(event, d) {
    // Show detailed information about the node
    showNodeDetailsModal(d);
}

/**
 * Show tooltip for data flow nodes
 */
function showDataFlowTooltip(event, d) {
    const tooltip = d3.select('body')
        .append('div')
        .attr('class', 'data-flow-tooltip')
        .style('position', 'absolute')
        .style('background', 'rgba(0, 0, 0, 0.9)')
        .style('color', 'white')
        .style('padding', '10px')
        .style('border-radius', '5px')
        .style('font-size', '12px')
        .style('pointer-events', 'none')
        .style('z-index', 1000);

    tooltip.html(`
        <strong>${d.name}</strong><br/>
        Type: ${d.type}<br/>
        Protocol: ${d.protocol}<br/>
        Risk Level: ${d.risk_level}<br/>
        Connected Links: ${getConnectedLinksCount(d)}
    `)
    .style('left', (event.pageX + 10) + 'px')
    .style('top', (event.pageY - 10) + 'px');
}

/**
 * Hide tooltip
 */
function hideDataFlowTooltip() {
    d3.selectAll('.data-flow-tooltip').remove();
}

/**
 * Show detailed modal for node
 */
function showNodeDetailsModal(node) {
    const modalHtml = `
        <div class="modal fade" id="nodeDetailsModal" tabindex="-1">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">
                            <i class="fas fa-robot me-2"></i>
                            ${node.name} - Data Flow Details
                        </h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="row">
                            <div class="col-md-6">
                                <h6>Agent Information</h6>
                                <table class="table table-sm">
                                    <tr><td><strong>Name:</strong></td><td>${node.name}</td></tr>
                                    <tr><td><strong>Type:</strong></td><td>${node.type}</td></tr>
                                    <tr><td><strong>Protocol:</strong></td><td>${node.protocol}</td></tr>
                                    <tr><td><strong>Risk Level:</strong></td><td>
                                        <span class="badge bg-${getRiskLevelBadgeColor(node.risk_level)}">
                                            ${node.risk_level}
                                        </span>
                                    </td></tr>
                                </table>
                            </div>
                            <div class="col-md-6">
                                <h6>Data Flow Connections</h6>
                                <div id="connectionsList"></div>
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                        <button type="button" class="btn btn-primary" onclick="focusOnNode(${node.id})">
                            <i class="fas fa-crosshairs me-2"></i>Focus on Node
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `;

    // Remove existing modal if present
    const existingModal = document.getElementById('nodeDetailsModal');
    if (existingModal) {
        existingModal.remove();
    }

    // Add modal to DOM
    document.body.insertAdjacentHTML('beforeend', modalHtml);

    // Populate connections list
    const connectionsList = document.getElementById('connectionsList');
    const connections = getNodeConnections(node);
    
    if (connections.length > 0) {
        const connectionsHtml = connections.map(conn => `
            <div class="mb-2 p-2 border rounded">
                <div class="d-flex justify-content-between">
                    <span><strong>${conn.direction === 'incoming' ? '← From' : '→ To'}:</strong> ${conn.targetName}</span>
                    <span class="badge bg-info">${conn.data_type}</span>
                </div>
                <small class="text-muted">
                    Volume: ${conn.volume} | Encryption: ${conn.encryption} | 
                    <span class="badge bg-${conn.compliance === 'compliant' ? 'success' : 'danger'}">
                        ${conn.compliance}
                    </span>
                </small>
            </div>
        `).join('');
        connectionsList.innerHTML = connectionsHtml;
    } else {
        connectionsList.innerHTML = '<p class="text-muted">No data flow connections</p>';
    }

    // Show modal
    const modal = new bootstrap.Modal(document.getElementById('nodeDetailsModal'));
    modal.show();
}

/**
 * Add legend to data flow visualization
 */
function addDataFlowLegend() {
    const legend = dataFlowSvg.append('g')
        .attr('class', 'legend')
        .attr('transform', 'translate(20, 20)');

    // Data type legend
    const dataTypes = ['PHI', 'PII', 'Clinical Data', 'General'];
    const dataTypeLegend = legend.append('g')
        .attr('class', 'data-type-legend');

    dataTypeLegend.append('text')
        .attr('x', 0)
        .attr('y', 0)
        .style('fill', 'white')
        .style('font-weight', 'bold')
        .style('font-size', '14px')
        .text('Data Types:');

    dataTypes.forEach((type, i) => {
        const legendItem = dataTypeLegend.append('g')
            .attr('transform', `translate(0, ${20 + i * 20})`);

        legendItem.append('line')
            .attr('x1', 0)
            .attr('x2', 20)
            .attr('y1', 0)
            .attr('y2', 0)
            .attr('stroke', getDataTypeColor(type))
            .attr('stroke-width', 3);

        legendItem.append('text')
            .attr('x', 25)
            .attr('y', 4)
            .style('fill', 'white')
            .style('font-size', '12px')
            .text(type);
    });

    // Risk level legend
    const riskLevels = ['low', 'medium', 'high'];
    const riskLegend = legend.append('g')
        .attr('class', 'risk-legend')
        .attr('transform', 'translate(150, 0)');

    riskLegend.append('text')
        .attr('x', 0)
        .attr('y', 0)
        .style('fill', 'white')
        .style('font-weight', 'bold')
        .style('font-size', '14px')
        .text('Risk Levels:');

    riskLevels.forEach((level, i) => {
        const legendItem = riskLegend.append('g')
            .attr('transform', `translate(0, ${20 + i * 20})`);

        legendItem.append('circle')
            .attr('r', 8)
            .attr('fill', NODE_COLORS.default)
            .attr('stroke', getRiskLevelColor(level))
            .attr('stroke-width', 3);

        legendItem.append('text')
            .attr('x', 15)
            .attr('y', 4)
            .style('fill', 'white')
            .style('font-size', '12px')
            .text(level.charAt(0).toUpperCase() + level.slice(1));
    });
}

/**
 * Utility functions
 */
function getDataTypeColor(dataType) {
    const colors = {
        'PHI': '#ff4757',
        'PII': '#ffa502',
        'Clinical Data': '#3742fa',
        'General': '#7bed9f'
    };
    return colors[dataType] || '#a8a8a8';
}

function getRiskLevelColor(riskLevel) {
    const colors = {
        'low': '#2ed573',
        'medium': '#ffa502',
        'high': '#ff4757',
        'critical': '#8b0000'
    };
    return colors[riskLevel] || '#a8a8a8';
}

function getRiskLevelBadgeColor(riskLevel) {
    const colors = {
        'low': 'success',
        'medium': 'warning',
        'high': 'danger',
        'critical': 'dark'
    };
    return colors[riskLevel] || 'secondary';
}

function getProtocolIcon(protocol) {
    const icons = {
        'kubernetes': '\uf1b3', // fa-ship
        'docker': '\uf395',      // fa-docker (would need Font Awesome brand)
        'rest_api': '\uf0ac',    // fa-globe
        'grpc': '\uf1e0',        // fa-share-alt
        'websocket': '\uf362',   // fa-exchange-alt
        'mqtt': '\uf012',        // fa-satellite
        'graphql': '\uf1c0'      // fa-database
    };
    return icons[protocol] || '\uf013'; // fa-cog
}

function getConnectedLinksCount(node) {
    return dataFlowLinks.filter(link => 
        link.source.id === node.id || link.target.id === node.id
    ).length;
}

function getNodeConnections(node) {
    const connections = [];
    
    dataFlowLinks.forEach(link => {
        if (link.source.id === node.id) {
            const targetNode = dataFlowNodes.find(n => n.id === link.target.id);
            connections.push({
                direction: 'outgoing',
                targetName: targetNode ? targetNode.name : 'Unknown',
                data_type: link.data_type,
                volume: link.volume,
                encryption: link.encryption,
                compliance: link.compliance
            });
        } else if (link.target.id === node.id) {
            const sourceNode = dataFlowNodes.find(n => n.id === link.source.id);
            connections.push({
                direction: 'incoming',
                targetName: sourceNode ? sourceNode.name : 'Unknown',
                data_type: link.data_type,
                volume: link.volume,
                encryption: link.encryption,
                compliance: link.compliance
            });
        }
    });
    
    return connections;
}

/**
 * Focus on specific node
 */
function focusOnNode(nodeId) {
    const node = dataFlowNodes.find(n => n.id === nodeId);
    if (!node) return;

    // Center the view on the node
    const transform = d3.zoomIdentity
        .translate(DATA_FLOW_WIDTH / 2 - node.x, DATA_FLOW_HEIGHT / 2 - node.y)
        .scale(1.5);

    dataFlowSvg.transition()
        .duration(750)
        .call(d3.zoom().transform, transform);

    // Highlight the node temporarily
    const nodeElement = nodeElements.filter(d => d.id === nodeId);
    nodeElement
        .transition()
        .duration(200)
        .attr('r', NODE_RADIUS * 1.5)
        .transition()
        .duration(200)
        .attr('r', NODE_RADIUS);
}

/**
 * Reset data flow visualization
 */
function resetDataFlow() {
    if (dataFlowSvg) {
        dataFlowSvg.transition()
            .duration(750)
            .call(d3.zoom().transform, d3.zoomIdentity);
    }
    
    // Restart simulation
    if (dataFlowSimulation) {
        dataFlowSimulation.alpha(0.3).restart();
    }
}

/**
 * Export data flow visualization
 */
function exportDataFlow() {
    const svgElement = document.querySelector('#dataFlowVisualization svg');
    if (!svgElement) return;

    // Create canvas and convert SVG to image
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    const svgData = new XMLSerializer().serializeToString(svgElement);
    
    const img = new Image();
    img.onload = function() {
        canvas.width = img.width;
        canvas.height = img.height;
        ctx.drawImage(img, 0, 0);
        
        // Download the image
        const link = document.createElement('a');
        link.download = `healthcare_ai_data_flow_${new Date().toISOString().split('T')[0]}.png`;
        link.href = canvas.toDataURL();
        link.click();
    };
    
    img.src = 'data:image/svg+xml;base64,' + btoa(svgData);
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Small delay to ensure other components are loaded
    setTimeout(initializeDataFlowVisualization, 1000);
});
