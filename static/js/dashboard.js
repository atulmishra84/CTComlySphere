/**
 * Dashboard JavaScript for CT ComplySphere Visibility & Governance Platform
 * Handles dashboard interactions, chart updates, and real-time data
 */

// Global variables
let riskTrendChart;
let refreshInterval;

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeDashboard();
    startAutoRefresh();
});

/**
 * Initialize dashboard components
 */
function initializeDashboard() {
    initializeCharts();
    initializeEventListeners();
    updateLastRefreshTime();
}

/**
 * Initialize all dashboard charts
 */
function initializeCharts() {
    // Risk Distribution Chart is initialized in the template
    // Additional chart configurations can be added here
    
    // Update chart colors to match theme
    Chart.defaults.color = 'rgba(255, 255, 255, 0.8)';
    Chart.defaults.borderColor = 'rgba(255, 255, 255, 0.1)';
}

/**
 * Initialize event listeners
 */
function initializeEventListeners() {
    // Scan modal form validation
    const scanForm = document.querySelector('#scanModal form');
    if (scanForm) {
        scanForm.addEventListener('submit', handleScanFormSubmit);
    }
    
    // Protocol selection handlers
    const protocolCheckboxes = document.querySelectorAll('input[name="protocols"]');
    protocolCheckboxes.forEach(checkbox => {
        checkbox.addEventListener('change', updateScanEstimate);
    });
    
    // Real-time updates toggle
    const realtimeToggle = document.getElementById('realtimeUpdates');
    if (realtimeToggle) {
        realtimeToggle.addEventListener('change', toggleRealTimeUpdates);
    }
    
    // Quick action buttons
    initializeQuickActions();
}

/**
 * Handle scan form submission
 */
function handleScanFormSubmit(event) {
    const form = event.target;
    const selectedProtocols = form.querySelectorAll('input[name="protocols"]:checked');
    
    if (selectedProtocols.length === 0) {
        event.preventDefault();
        showAlert('Please select at least one protocol to scan.', 'warning');
        return false;
    }
    
    // Show loading state
    const submitButton = form.querySelector('button[type="submit"]');
    const originalText = submitButton.innerHTML;
    submitButton.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Starting Scan...';
    submitButton.disabled = true;
    
    // Reset button after form submission
    setTimeout(() => {
        submitButton.innerHTML = originalText;
        submitButton.disabled = false;
    }, 3000);
}

/**
 * Update scan estimate based on selected protocols
 */
function updateScanEstimate() {
    const selectedProtocols = document.querySelectorAll('input[name="protocols"]:checked');
    const estimateElement = document.getElementById('scanEstimate');
    
    if (estimateElement) {
        const estimatedTime = selectedProtocols.length * 30; // 30 seconds per protocol
        const estimatedAgents = selectedProtocols.length * 5; // 5 agents per protocol average
        
        estimateElement.innerHTML = `
            <small class="text-muted">
                Estimated: ${estimatedTime}s scan time, ~${estimatedAgents} agents to discover
            </small>
        `;
    }
}

/**
 * Initialize quick action buttons
 */
function initializeQuickActions() {
    // Quick scan button
    const quickScanBtn = document.getElementById('quickScan');
    if (quickScanBtn) {
        quickScanBtn.addEventListener('click', function() {
            startQuickScan(['kubernetes', 'docker', 'rest_api']);
        });
    }
    
    // Emergency scan button
    const emergencyScanBtn = document.getElementById('emergencyScan');
    if (emergencyScanBtn) {
        emergencyScanBtn.addEventListener('click', function() {
            if (confirm('Start emergency scan? This will scan all protocols immediately.')) {
                startEmergencyScan();
            }
        });
    }
    
    // Export data button
    const exportBtn = document.getElementById('exportData');
    if (exportBtn) {
        exportBtn.addEventListener('click', exportDashboardData);
    }
}

/**
 * Start quick scan with default protocols
 */
function startQuickScan(protocols) {
    showAlert('Starting quick scan...', 'info');
    
    // Simulate scan start
    fetch('/scan/start', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
            'protocols': protocols
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showAlert('Quick scan started successfully!', 'success');
            startScanProgress();
        } else {
            showAlert('Failed to start quick scan: ' + data.error, 'danger');
        }
    })
    .catch(error => {
        showAlert('Error starting quick scan: ' + error.message, 'danger');
    });
}

/**
 * Start emergency scan
 */
function startEmergencyScan() {
    showAlert('Starting emergency scan across all protocols...', 'warning');
    
    // Update UI to show emergency state
    document.body.classList.add('emergency-scan');
    
    // Start scan with all protocols
    const allProtocols = ['kubernetes', 'docker', 'rest_api', 'grpc', 'websocket', 'mqtt', 'graphql'];
    startQuickScan(allProtocols);
    
    // Remove emergency state after 30 seconds
    setTimeout(() => {
        document.body.classList.remove('emergency-scan');
    }, 30000);
}

/**
 * Show scan progress
 */
function startScanProgress() {
    // Create progress bar
    const progressHtml = `
        <div class="alert alert-info" id="scanProgress">
            <div class="d-flex align-items-center">
                <div class="spinner-border spinner-border-sm me-3" role="status"></div>
                <div class="flex-grow-1">
                    <strong>Scanning in progress...</strong>
                    <div class="progress mt-2" style="height: 6px;">
                        <div class="progress-bar progress-bar-striped progress-bar-animated" 
                             style="width: 0%" id="scanProgressBar"></div>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    // Insert progress bar after page header
    const pageHeader = document.querySelector('.row.mb-4');
    if (pageHeader) {
        pageHeader.insertAdjacentHTML('afterend', progressHtml);
    }
    
    // Simulate progress
    let progress = 0;
    const progressBar = document.getElementById('scanProgressBar');
    const progressInterval = setInterval(() => {
        progress += Math.random() * 15;
        if (progress >= 100) {
            progress = 100;
            clearInterval(progressInterval);
            
            // Remove progress bar and refresh page
            setTimeout(() => {
                const progressElement = document.getElementById('scanProgress');
                if (progressElement) {
                    progressElement.remove();
                }
                location.reload();
            }, 2000);
        }
        
        if (progressBar) {
            progressBar.style.width = progress + '%';
        }
    }, 1000);
}

/**
 * Toggle real-time updates
 */
function toggleRealTimeUpdates(event) {
    const enabled = event.target.checked;
    
    if (enabled) {
        startAutoRefresh();
        showAlert('Real-time updates enabled', 'success');
    } else {
        stopAutoRefresh();
        showAlert('Real-time updates disabled', 'info');
    }
}

/**
 * Start auto-refresh functionality
 */
function startAutoRefresh() {
    stopAutoRefresh(); // Clear any existing interval
    
    refreshInterval = setInterval(() => {
        refreshDashboardData();
    }, 30000); // Refresh every 30 seconds
}

/**
 * Stop auto-refresh functionality
 */
function stopAutoRefresh() {
    if (refreshInterval) {
        clearInterval(refreshInterval);
        refreshInterval = null;
    }
}

/**
 * Refresh dashboard data
 */
function refreshDashboardData() {
    // Update metrics cards
    updateMetricsCards();
    
    // Update recent activity
    updateRecentActivity();
    
    // Update last refresh time
    updateLastRefreshTime();
}

/**
 * Update metrics cards with latest data
 */
function updateMetricsCards() {
    // Simulate updating metrics
    const metricsCards = document.querySelectorAll('.card h3.card-title');
    metricsCards.forEach(card => {
        // Add subtle animation to show update
        card.style.transition = 'all 0.3s ease';
        card.style.transform = 'scale(1.05)';
        setTimeout(() => {
            card.style.transform = 'scale(1)';
        }, 300);
    });
}

/**
 * Update recent activity section
 */
function updateRecentActivity() {
    const activitySection = document.querySelector('#recentActivity');
    if (activitySection) {
        // Add visual indicator of refresh
        activitySection.style.opacity = '0.7';
        setTimeout(() => {
            activitySection.style.opacity = '1';
        }, 500);
    }
}

/**
 * Update last refresh time
 */
function updateLastRefreshTime() {
    const now = new Date();
    const timeString = now.toLocaleTimeString();
    
    let refreshIndicator = document.getElementById('lastRefresh');
    if (!refreshIndicator) {
        // Create refresh indicator if it doesn't exist
        refreshIndicator = document.createElement('small');
        refreshIndicator.id = 'lastRefresh';
        refreshIndicator.className = 'text-muted position-fixed bottom-0 end-0 m-3';
        document.body.appendChild(refreshIndicator);
    }
    
    refreshIndicator.innerHTML = `
        <i class="fas fa-sync-alt me-1"></i>
        Last updated: ${timeString}
    `;
}

/**
 * Export dashboard data
 */
function exportDashboardData() {
    const dashboardData = {
        timestamp: new Date().toISOString(),
        metrics: extractMetricsData(),
        compliance: extractComplianceData(),
        riskDistribution: extractRiskData()
    };
    
    const blob = new Blob([JSON.stringify(dashboardData, null, 2)], { 
        type: 'application/json' 
    });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `healthcare_ai_dashboard_${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    showAlert('Dashboard data exported successfully', 'success');
}

/**
 * Extract metrics data from dashboard
 */
function extractMetricsData() {
    const metrics = {};
    
    // Extract values from metric cards
    document.querySelectorAll('.card h3.card-title').forEach((element, index) => {
        const value = element.textContent.trim();
        const label = element.nextElementSibling?.textContent.trim();
        if (label) {
            metrics[label.toLowerCase().replace(/\s+/g, '_')] = value;
        }
    });
    
    return metrics;
}

/**
 * Extract compliance data from dashboard
 */
function extractComplianceData() {
    const compliance = {};
    
    // Extract compliance percentages
    document.querySelectorAll('.progress-bar').forEach(bar => {
        const percentage = bar.style.width;
        const framework = bar.closest('.text-center')?.querySelector('h6')?.textContent;
        if (framework && percentage) {
            compliance[framework.toLowerCase().replace(/\s+/g, '_')] = percentage;
        }
    });
    
    return compliance;
}

/**
 * Extract risk distribution data
 */
function extractRiskData() {
    // This would typically extract data from the risk distribution chart
    // For now, return placeholder structure
    return {
        low: 0,
        medium: 0,
        high: 0,
        critical: 0
    };
}

/**
 * Show alert message
 */
function showAlert(message, type = 'info') {
    const alertHtml = `
        <div class="alert alert-${type} alert-dismissible fade show" role="alert">
            <i class="fas fa-${getAlertIcon(type)} me-2"></i>
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    `;
    
    // Insert alert at the top of the main container
    const mainContainer = document.querySelector('main.container-fluid');
    if (mainContainer) {
        mainContainer.insertAdjacentHTML('afterbegin', alertHtml);
        
        // Auto-remove alert after 5 seconds
        setTimeout(() => {
            const alert = mainContainer.querySelector('.alert');
            if (alert) {
                alert.remove();
            }
        }, 5000);
    }
}

/**
 * Get icon for alert type
 */
function getAlertIcon(type) {
    const icons = {
        'success': 'check-circle',
        'danger': 'exclamation-triangle',
        'warning': 'exclamation-triangle',
        'info': 'info-circle'
    };
    return icons[type] || 'info-circle';
}

/**
 * Handle keyboard shortcuts
 */
document.addEventListener('keydown', function(event) {
    // Ctrl+R or Cmd+R: Refresh dashboard
    if ((event.ctrlKey || event.metaKey) && event.key === 'r') {
        event.preventDefault();
        refreshDashboardData();
        showAlert('Dashboard refreshed', 'info');
    }
    
    // Ctrl+S or Cmd+S: Start quick scan
    if ((event.ctrlKey || event.metaKey) && event.key === 's') {
        event.preventDefault();
        const scanModal = new bootstrap.Modal(document.getElementById('scanModal'));
        scanModal.show();
    }
    
    // Escape: Close any open modals
    if (event.key === 'Escape') {
        const openModals = document.querySelectorAll('.modal.show');
        openModals.forEach(modal => {
            const modalInstance = bootstrap.Modal.getInstance(modal);
            if (modalInstance) {
                modalInstance.hide();
            }
        });
    }
});

/**
 * Handle visibility change (tab switching)
 */
document.addEventListener('visibilitychange', function() {
    if (document.hidden) {
        stopAutoRefresh();
    } else {
        startAutoRefresh();
        refreshDashboardData(); // Refresh when tab becomes visible
    }
});

/**
 * Initialize tooltip and popover components
 */
function initializeTooltips() {
    // Initialize Bootstrap tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Initialize Bootstrap popovers
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
}

// Initialize tooltips when DOM is ready
document.addEventListener('DOMContentLoaded', initializeTooltips);

// Cleanup on page unload
window.addEventListener('beforeunload', function() {
    stopAutoRefresh();
});
