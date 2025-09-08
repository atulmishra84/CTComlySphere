/**
 * Model Registry Dashboard JavaScript
 * Handles model registry visualization, lineage tracking, and compliance management
 */

// Global variables
let complianceChart;
let lineageVisualization;
let currentModels = [];
let currentDeployments = [];

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    initializeModelRegistry();
    loadRegistryData();
    initializeCharts();
    setupEventListeners();
});

/**
 * Initialize the model registry dashboard
 */
function initializeModelRegistry() {
    console.log('Initializing model registry dashboard...');
    
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

/**
 * Load registry data from the API
 */
function loadRegistryData() {
    // Load models data
    fetch('/api/model-registry/models')
        .then(response => response.json())
        .then(data => {
            currentModels = data.models || [];
            updateModelsTable();
        })
        .catch(error => {
            console.error('Error loading models:', error);
            showAlert('Failed to load models data', 'danger');
        });
    
    // Load deployments data
    fetch('/api/model-registry/deployments')
        .then(response => response.json())
        .then(data => {
            currentDeployments = data.deployments || [];
            updateDeploymentsGrid();
        })
        .catch(error => {
            console.error('Error loading deployments:', error);
        });
}

/**
 * Initialize charts and visualizations
 */
function initializeCharts() {
    initializeComplianceChart();
}

/**
 * Initialize compliance overview chart
 */
function initializeComplianceChart() {
    const ctx = document.getElementById('complianceChart');
    if (!ctx) return;
    
    const chartCtx = ctx.getContext('2d');
    
    complianceChart = new Chart(chartCtx, {
        type: 'doughnut',
        data: {
            labels: ['HIPAA Compliant', 'FDA Cleared', 'GDPR Compliant', 'Non-Compliant'],
            datasets: [{
                data: [65, 45, 55, 35],
                backgroundColor: [
                    'var(--bs-success)',
                    'var(--bs-primary)', 
                    'var(--bs-info)',
                    'var(--bs-danger)'
                ],
                borderWidth: 2,
                borderColor: 'var(--bs-dark)'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 20,
                        usePointStyle: true,
                        color: 'var(--bs-body-color)'
                    }
                },
                tooltip: {
                    backgroundColor: 'var(--bs-dark)',
                    titleColor: 'var(--bs-light)',
                    bodyColor: 'var(--bs-light)',
                    borderColor: 'var(--bs-secondary)',
                    borderWidth: 1
                }
            },
            cutout: '60%'
        }
    });
}

/**
 * Setup event listeners
 */
function setupEventListeners() {
    // Search functionality
    const modelSearch = document.getElementById('modelSearch');
    if (modelSearch) {
        modelSearch.addEventListener('input', filterModels);
    }
    
    // Stage filter
    const stageFilter = document.getElementById('stageFilter');
    if (stageFilter) {
        stageFilter.addEventListener('change', filterModels);
    }
    
    // Lineage model selector
    const lineageModelSelect = document.getElementById('lineageModelSelect');
    if (lineageModelSelect) {
        lineageModelSelect.addEventListener('change', updateLineageView);
    }
}

/**
 * Filter models based on search and stage filter
 */
function filterModels() {
    const searchTerm = document.getElementById('modelSearch').value.toLowerCase();
    const stageFilter = document.getElementById('stageFilter').value;
    
    const filteredModels = currentModels.filter(model => {
        const matchesSearch = model.model_name.toLowerCase().includes(searchTerm) ||
                             (model.description && model.description.toLowerCase().includes(searchTerm));
        const matchesStage = !stageFilter || model.stage === stageFilter;
        
        return matchesSearch && matchesStage;
    });
    
    updateModelsTable(filteredModels);
}

/**
 * Update the models table with filtered data
 */
function updateModelsTable(models = currentModels) {
    const tbody = document.getElementById('modelsTableBody');
    if (!tbody) return;
    
    tbody.innerHTML = '';
    
    models.forEach(model => {
        const row = createModelTableRow(model);
        tbody.appendChild(row);
    });
}

/**
 * Create a table row for a model
 */
function createModelTableRow(model) {
    const row = document.createElement('tr');
    
    row.innerHTML = `
        <td>
            <div class="d-flex align-items-center">
                <i class="fas fa-cube text-primary me-2"></i>
                <div>
                    <div class="fw-semibold">${model.model_name}</div>
                    ${model.description ? `<small class="text-muted">${model.description.substring(0, 50)}${model.description.length > 50 ? '...' : ''}</small>` : ''}
                </div>
            </div>
        </td>
        <td><span class="badge bg-secondary">v${model.version}</span></td>
        <td>${getStageBadge(model.stage)}</td>
        <td>${model.framework ? `<span class="badge bg-info">${model.framework}</span>` : '<span class="text-muted">Unknown</span>'}</td>
        <td>${getComplianceBadges(model)}</td>
        <td>${model.accuracy ? `<div class="text-success">${(model.accuracy * 100).toFixed(1)}% accuracy</div>` : '<span class="text-muted">No metrics</span>'}</td>
        <td><small class="text-muted">${new Date(model.created_at).toLocaleDateString()}</small></td>
        <td>
            <div class="btn-group btn-group-sm" role="group">
                <button class="btn btn-outline-primary" onclick="viewModelDetails(${model.id})">
                    <i class="fas fa-eye"></i>
                </button>
                <button class="btn btn-outline-info" onclick="viewModelLineage(${model.id})">
                    <i class="fas fa-project-diagram"></i>
                </button>
                <div class="btn-group" role="group">
                    <button class="btn btn-outline-secondary dropdown-toggle" data-bs-toggle="dropdown">
                        <i class="fas fa-ellipsis-v"></i>
                    </button>
                    <ul class="dropdown-menu">
                        <li><a class="dropdown-item" href="#" onclick="deployModel(${model.id})">Deploy</a></li>
                        <li><a class="dropdown-item" href="#" onclick="updateCompliance(${model.id})">Update Compliance</a></li>
                        <li><a class="dropdown-item" href="#" onclick="archiveModel(${model.id})">Archive</a></li>
                    </ul>
                </div>
            </div>
        </td>
    `;
    
    return row;
}

/**
 * Get stage badge HTML
 */
function getStageBadge(stage) {
    switch(stage) {
        case 'Production':
            return '<span class="badge bg-success">Production</span>';
        case 'Staging':
            return '<span class="badge bg-warning">Staging</span>';
        case 'Archived':
            return '<span class="badge bg-secondary">Archived</span>';
        default:
            return '<span class="badge bg-light text-dark">None</span>';
    }
}

/**
 * Get compliance badges HTML
 */
function getComplianceBadges(model) {
    let badges = '';
    if (model.hipaa_compliant) badges += '<span class="badge bg-success me-1" title="HIPAA Compliant">HIPAA</span>';
    if (model.fda_cleared) badges += '<span class="badge bg-primary me-1" title="FDA Cleared">FDA</span>';
    if (model.processes_phi) badges += '<span class="badge bg-warning me-1" title="Processes PHI">PHI</span>';
    return badges || '<span class="text-muted">None</span>';
}

/**
 * Update deployments grid
 */
function updateDeploymentsGrid() {
    const grid = document.getElementById('deploymentsGrid');
    if (!grid) return;
    
    grid.innerHTML = '';
    
    currentDeployments.forEach(deployment => {
        const card = createDeploymentCard(deployment);
        grid.appendChild(card);
    });
}

/**
 * Create deployment card
 */
function createDeploymentCard(deployment) {
    const col = document.createElement('div');
    col.className = 'col-xl-4 col-lg-6 mb-4';
    
    col.innerHTML = `
        <div class="card border-0 shadow-sm">
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-start mb-3">
                    <div>
                        <h6 class="card-title mb-1">${deployment.model_name}</h6>
                        <small class="text-muted">v${deployment.model_version}</small>
                    </div>
                    <div class="text-end">
                        ${getDeploymentStatusBadge(deployment.deployment_status)}
                    </div>
                </div>
                
                <div class="row g-3 mb-3">
                    <div class="col-6">
                        <div class="text-center">
                            <div class="h5 mb-0 text-primary">${deployment.request_count || 0}</div>
                            <small class="text-muted">Requests</small>
                        </div>
                    </div>
                    <div class="col-6">
                        <div class="text-center">
                            <div class="h5 mb-0 text-info">${Math.round(deployment.average_response_time || 0)}ms</div>
                            <small class="text-muted">Avg Response</small>
                        </div>
                    </div>
                </div>
                
                <div class="mb-3">
                    <small class="text-muted d-block">Environment</small>
                    <span class="badge bg-secondary">${deployment.environment}</span>
                </div>
                
                ${deployment.endpoint_url ? `
                <div class="mb-3">
                    <small class="text-muted d-block">Endpoint</small>
                    <code class="small">${deployment.endpoint_url}</code>
                </div>
                ` : ''}
                
                <div class="d-flex gap-2">
                    <button class="btn btn-outline-primary btn-sm flex-fill" onclick="testDeployment('${deployment.deployment_id}')">
                        <i class="fas fa-play"></i> Test
                    </button>
                    <button class="btn btn-outline-info btn-sm" onclick="viewDeploymentLogs('${deployment.deployment_id}')">
                        <i class="fas fa-file-alt"></i> Logs
                    </button>
                </div>
            </div>
        </div>
    `;
    
    return col;
}

/**
 * Get deployment status badge
 */
function getDeploymentStatusBadge(status) {
    switch(status) {
        case 'active':
            return '<span class="badge bg-success">Active</span>';
        case 'pending':
            return '<span class="badge bg-warning">Pending</span>';
        default:
            return '<span class="badge bg-danger">Failed</span>';
    }
}

/**
 * Sync model registry with external sources
 */
function syncModelRegistry() {
    showAlert('Starting model registry synchronization...', 'info');
    
    fetch('/api/model-registry/sync', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'}
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showAlert(`Sync completed: ${data.models_synced} models synchronized`, 'success');
            setTimeout(() => location.reload(), 2000);
        } else {
            showAlert(`Sync failed: ${data.error}`, 'danger');
        }
    })
    .catch(error => {
        console.error('Sync error:', error);
        showAlert('Registry sync failed. Please try again.', 'danger');
    });
}

/**
 * View model details
 */
function viewModelDetails(modelId) {
    fetch(`/api/model-registry/models/${modelId}`)
        .then(response => response.json())
        .then(data => {
            displayModelDetails(data.model);
        })
        .catch(error => {
            console.error('Error loading model details:', error);
            showAlert('Failed to load model details', 'danger');
        });
}

/**
 * Display model details in modal
 */
function displayModelDetails(model) {
    const content = document.getElementById('modelDetailsContent');
    
    content.innerHTML = `
        <div class="row">
            <div class="col-md-6">
                <h6>Basic Information</h6>
                <table class="table table-sm">
                    <tr><td><strong>Name:</strong></td><td>${model.model_name}</td></tr>
                    <tr><td><strong>Version:</strong></td><td>v${model.version}</td></tr>
                    <tr><td><strong>Stage:</strong></td><td>${model.stage}</td></tr>
                    <tr><td><strong>Framework:</strong></td><td>${model.framework || 'Unknown'}</td></tr>
                    <tr><td><strong>Type:</strong></td><td>${model.model_type || 'Unknown'}</td></tr>
                </table>
            </div>
            <div class="col-md-6">
                <h6>Performance Metrics</h6>
                <table class="table table-sm">
                    <tr><td><strong>Accuracy:</strong></td><td>${model.accuracy ? (model.accuracy * 100).toFixed(2) + '%' : 'N/A'}</td></tr>
                    <tr><td><strong>Precision:</strong></td><td>${model.precision ? (model.precision * 100).toFixed(2) + '%' : 'N/A'}</td></tr>
                    <tr><td><strong>Recall:</strong></td><td>${model.recall ? (model.recall * 100).toFixed(2) + '%' : 'N/A'}</td></tr>
                    <tr><td><strong>F1 Score:</strong></td><td>${model.f1_score ? model.f1_score.toFixed(3) : 'N/A'}</td></tr>
                </table>
            </div>
        </div>
        
        <div class="row mt-4">
            <div class="col-12">
                <h6>Compliance Status</h6>
                <div class="d-flex gap-2 mb-3">
                    ${model.hipaa_compliant ? '<span class="badge bg-success">HIPAA Compliant</span>' : '<span class="badge bg-secondary">HIPAA Pending</span>'}
                    ${model.fda_cleared ? '<span class="badge bg-primary">FDA Cleared</span>' : '<span class="badge bg-secondary">FDA Pending</span>'}
                    ${model.gdpr_compliant ? '<span class="badge bg-info">GDPR Compliant</span>' : '<span class="badge bg-secondary">GDPR Pending</span>'}
                    ${model.processes_phi ? '<span class="badge bg-warning">Processes PHI</span>' : ''}
                </div>
                
                ${model.description ? `
                <h6>Description</h6>
                <p class="text-muted">${model.description}</p>
                ` : ''}
                
                <div class="row">
                    <div class="col-md-6">
                        <h6>Training Information</h6>
                        <ul class="list-unstyled">
                            <li><strong>Dataset:</strong> ${model.training_dataset || 'Unknown'}</li>
                            <li><strong>Training Samples:</strong> ${model.training_samples || 'Unknown'}</li>
                            <li><strong>Validation Samples:</strong> ${model.validation_samples || 'Unknown'}</li>
                            <li><strong>Duration:</strong> ${model.training_duration ? model.training_duration.toFixed(1) + ' hours' : 'Unknown'}</li>
                        </ul>
                    </div>
                    <div class="col-md-6">
                        <h6>Deployment</h6>
                        <ul class="list-unstyled">
                            <li><strong>Status:</strong> ${model.deployment_status || 'Not deployed'}</li>
                            <li><strong>Endpoint:</strong> ${model.serving_endpoint || 'N/A'}</li>
                            <li><strong>Last Deployed:</strong> ${model.last_deployed ? new Date(model.last_deployed).toLocaleDateString() : 'Never'}</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    const modal = new bootstrap.Modal(document.getElementById('modelDetailsModal'));
    modal.show();
}

/**
 * View model lineage
 */
function viewModelLineage(modelId) {
    const select = document.getElementById('lineageModelSelect');
    select.value = modelId;
    
    // Switch to lineage tab
    const lineageTab = document.getElementById('lineage-tab');
    lineageTab.click();
    
    // Update lineage view
    updateLineageView();
}

/**
 * Update lineage visualization
 */
function updateLineageView() {
    const modelId = document.getElementById('lineageModelSelect').value;
    if (!modelId) {
        displayLineagePlaceholder();
        return;
    }
    
    fetch(`/api/model-registry/models/${modelId}/lineage`)
        .then(response => response.json())
        .then(data => {
            displayLineageVisualization(data.lineage);
        })
        .catch(error => {
            console.error('Error loading lineage:', error);
            showAlert('Failed to load model lineage', 'danger');
        });
}

/**
 * Display lineage placeholder
 */
function displayLineagePlaceholder() {
    const container = document.getElementById('lineageVisualization');
    container.innerHTML = `
        <div class="d-flex align-items-center justify-content-center h-100">
            <div class="text-center">
                <i class="fas fa-project-diagram fa-3x text-muted mb-3"></i>
                <h5 class="text-muted">Select a model to view its lineage</h5>
                <p class="text-muted">Explore data sources, dependencies, and model evolution.</p>
            </div>
        </div>
    `;
}

/**
 * Display lineage visualization using D3.js
 */
function displayLineageVisualization(lineageData) {
    const container = document.getElementById('lineageVisualization');
    container.innerHTML = '';
    
    const width = container.clientWidth;
    const height = 500;
    
    const svg = d3.select('#lineageVisualization')
        .append('svg')
        .attr('width', width)
        .attr('height', height);
    
    // Create sample lineage data if not provided
    const nodes = [
        {id: 'data', name: 'Training Data', type: 'data', x: 100, y: 250},
        {id: 'features', name: 'Feature Engineering', type: 'process', x: 250, y: 250},
        {id: 'model', name: lineageData.model_name || 'Model', type: 'model', x: 400, y: 250},
        {id: 'deployment', name: 'Deployment', type: 'deployment', x: 550, y: 250}
    ];
    
    const links = [
        {source: 'data', target: 'features'},
        {source: 'features', target: 'model'},
        {source: 'model', target: 'deployment'}
    ];
    
    // Draw links
    svg.selectAll('.link')
        .data(links)
        .enter()
        .append('line')
        .attr('class', 'link')
        .attr('x1', d => nodes.find(n => n.id === d.source).x)
        .attr('y1', d => nodes.find(n => n.id === d.source).y)
        .attr('x2', d => nodes.find(n => n.id === d.target).x)
        .attr('y2', d => nodes.find(n => n.id === d.target).y)
        .style('stroke', '#6c757d')
        .style('stroke-width', 2);
    
    // Draw nodes
    const nodeGroups = svg.selectAll('.node')
        .data(nodes)
        .enter()
        .append('g')
        .attr('class', 'node')
        .attr('transform', d => `translate(${d.x}, ${d.y})`);
    
    nodeGroups.append('circle')
        .attr('r', 30)
        .style('fill', d => {
            switch(d.type) {
                case 'data': return 'var(--bs-info)';
                case 'process': return 'var(--bs-warning)';
                case 'model': return 'var(--bs-primary)';
                case 'deployment': return 'var(--bs-success)';
                default: return 'var(--bs-secondary)';
            }
        })
        .style('stroke', '#fff')
        .style('stroke-width', 2);
    
    nodeGroups.append('text')
        .text(d => d.name)
        .attr('text-anchor', 'middle')
        .attr('y', 45)
        .style('font-size', '12px')
        .style('fill', 'var(--bs-body-color)');
}

/**
 * Deploy model
 */
function deployModel(modelId) {
    showAlert('Model deployment feature coming soon!', 'info');
}

/**
 * Update model compliance
 */
function updateCompliance(modelId) {
    showAlert('Compliance update feature coming soon!', 'info');
}

/**
 * Archive model
 */
function archiveModel(modelId) {
    if (confirm('Are you sure you want to archive this model?')) {
        fetch(`/api/model-registry/models/${modelId}/archive`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'}
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showAlert('Model archived successfully', 'success');
                loadRegistryData();
            } else {
                showAlert('Failed to archive model', 'danger');
            }
        })
        .catch(error => {
            console.error('Archive error:', error);
            showAlert('Failed to archive model', 'danger');
        });
    }
}

/**
 * Test deployment
 */
function testDeployment(deploymentId) {
    showAlert('Testing deployment...', 'info');
    
    fetch(`/api/model-registry/deployments/${deploymentId}/test`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'}
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showAlert('Deployment test successful', 'success');
        } else {
            showAlert(`Deployment test failed: ${data.error}`, 'danger');
        }
    })
    .catch(error => {
        console.error('Test error:', error);
        showAlert('Deployment test failed', 'danger');
    });
}

/**
 * View deployment logs
 */
function viewDeploymentLogs(deploymentId) {
    showAlert('Deployment logs feature coming soon!', 'info');
}

/**
 * Run compliance scan
 */
function runComplianceScan() {
    showAlert('Starting compliance scan...', 'info');
    
    fetch('/api/model-registry/compliance/scan', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'}
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showAlert('Compliance scan completed', 'success');
            setTimeout(() => location.reload(), 2000);
        } else {
            showAlert('Compliance scan failed', 'danger');
        }
    })
    .catch(error => {
        console.error('Scan error:', error);
        showAlert('Compliance scan failed', 'danger');
    });
}

/**
 * Generate compliance report
 */
function generateComplianceReport() {
    window.open('/api/model-registry/compliance/report', '_blank');
}

/**
 * Show alert message
 */
function showAlert(message, type = 'info') {
    const alertContainer = document.createElement('div');
    alertContainer.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
    alertContainer.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
    alertContainer.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(alertContainer);
    
    // Auto-dismiss after 5 seconds
    setTimeout(() => {
        if (alertContainer.parentNode) {
            alertContainer.remove();
        }
    }, 5000);
}