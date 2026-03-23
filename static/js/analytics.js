/**
 * Analytics JavaScript for CT ComplySphere Visibility & Governance Platform
 * Handles advanced analytics, predictive charts, and data visualization
 */

// Global chart instances
let riskTrendChart;
let riskGaugeChart;
let protocolRiskChart;
let cloudRiskChart;
let vulnerabilityPredictionChart;
let modelAccuracyChart;
let latencyChart;
let driftChart;

// Analytics data cache
let analyticsData = {};
let predictionData = {};

// Initialize analytics when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeAnalyticsDashboard();
    loadAnalyticsData();
    startRealTimeUpdates();
});

/**
 * Initialize the analytics dashboard
 */
function initializeAnalyticsDashboard() {
    initializeRiskTrendChart();
    initializeRiskGaugeChart();
    initializeProtocolRiskChart();
    initializeComplianceFrameworkChart();
    initializeCloudRiskChart();
    initializeVulnerabilityPredictionChart();
    initializeModelPerformanceCharts();
    initializePeriodSelector();
}

/**
 * Initialize risk trend chart with predictions
 */
function initializeRiskTrendChart() {
    const ctx = document.getElementById('riskTrendChart');
    if (!ctx) return;

    const chartCtx = ctx.getContext('2d');
    
    riskTrendChart = new Chart(chartCtx, {
        type: 'line',
        data: {
            labels: generateDateLabels(30),
            datasets: [
                {
                    label: 'Historical Risk Score',
                    data: generateHistoricalRiskData(30),
                    borderColor: 'var(--bs-primary)',
                    backgroundColor: 'rgba(var(--bs-primary-rgb), 0.1)',
                    fill: true,
                    tension: 0.4
                },
                {
                    label: 'Predicted Risk Score',
                    data: generatePredictedRiskData(30),
                    borderColor: 'var(--bs-warning)',
                    backgroundColor: 'rgba(var(--bs-warning-rgb), 0.1)',
                    borderDash: [5, 5],
                    fill: false,
                    tension: 0.4
                },
                {
                    label: 'PHI Exposure Events',
                    data: generatePHIExposureData(30),
                    borderColor: 'var(--bs-danger)',
                    backgroundColor: 'var(--bs-danger)',
                    type: 'scatter',
                    pointRadius: 6,
                    pointHoverRadius: 8
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                intersect: false,
                mode: 'index'
            },
            plugins: {
                legend: {
                    position: 'top'
                },
                tooltip: {
                    callbacks: {
                        title: function(context) {
                            return context[0].label;
                        },
                        label: function(context) {
                            if (context.dataset.label === 'PHI Exposure Events') {
                                return 'PHI Exposure Detected';
                            }
                            return context.dataset.label + ': ' + context.parsed.y.toFixed(1);
                        }
                    }
                }
            },
            scales: {
                x: {
                    display: true,
                    title: {
                        display: true,
                        text: 'Date'
                    }
                },
                y: {
                    display: true,
                    title: {
                        display: true,
                        text: 'Risk Score'
                    },
                    min: 0,
                    max: 100
                }
            }
        }
    });
}

/**
 * Initialize risk gauge chart
 */
function initializeRiskGaugeChart() {
    const ctx = document.getElementById('riskGaugeChart');
    if (!ctx) return;

    const chartCtx = ctx.getContext('2d');
    
    riskGaugeChart = new Chart(chartCtx, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [72, 28], // 72% risk, 28% remaining
                backgroundColor: [
                    'var(--bs-danger)',
                    'rgba(var(--bs-light-rgb), 0.2)'
                ],
                borderWidth: 0,
                cutout: '80%'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    enabled: false
                }
            }
        },
        plugins: [{
            beforeDraw: function(chart) {
                const width = chart.width;
                const height = chart.height;
                const ctx = chart.ctx;
                
                ctx.restore();
                const fontSize = (height / 120).toFixed(2);
                ctx.font = fontSize + "em sans-serif";
                ctx.textBaseline = "top";
                
                const text = "72%";
                const textX = Math.round((width - ctx.measureText(text).width) / 2);
                const textY = height / 2 - 20;
                
                ctx.fillStyle = 'var(--bs-body-color)';
                ctx.fillText(text, textX, textY);
                
                // Risk level text
                ctx.font = (fontSize * 0.6) + "em sans-serif";
                const riskText = "High Risk";
                const riskTextX = Math.round((width - ctx.measureText(riskText).width) / 2);
                const riskTextY = height / 2 + 10;
                
                ctx.fillStyle = 'var(--bs-danger)';
                ctx.fillText(riskText, riskTextX, riskTextY);
                
                ctx.save();
            }
        }]
    });
}

/**
 * Initialize protocol risk chart with vibrant colors
 */
function initializeProtocolRiskChart() {
    const ctx = document.getElementById('protocolRiskChart');
    if (!ctx) return;

    protocolRiskChart = new Chart(ctx.getContext('2d'), {
        type: 'radar',
        data: {
            labels: ['Kubernetes', 'Docker', 'REST API', 'gRPC', 'WebSocket', 'MQTT', 'GraphQL'],
            datasets: [{
                label: 'Risk Score',
                data: [65, 78, 45, 52, 68, 72, 38],
                backgroundColor: 'rgba(255, 99, 132, 0.2)',
                borderColor: 'rgb(255, 99, 132)',
                pointBackgroundColor: 'rgb(255, 99, 132)',
                pointBorderColor: '#fff',
                pointHoverBackgroundColor: '#fff',
                pointHoverBorderColor: 'rgb(255, 99, 132)'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                r: {
                    angleLines: {
                        display: true,
                        color: 'rgba(255, 99, 132, 0.1)'
                    },
                    grid: {
                        color: 'rgba(255, 99, 132, 0.1)'
                    },
                    pointLabels: {
                        color: '#495057',
                        font: {
                            size: 12,
                            weight: 'bold'
                        }
                    },
                    ticks: {
                        color: '#6c757d',
                        backdropColor: 'rgba(255, 255, 255, 0.75)'
                    },
                    suggestedMin: 0,
                    suggestedMax: 100
                }
            },
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    backgroundColor: 'rgba(0, 0, 0, 0.8)',
                    titleColor: '#fff',
                    bodyColor: '#fff',
                    cornerRadius: 8
                }
            }
        }
    });
}

/**
 * Initialize compliance framework radar chart with colorful design
 */
function initializeComplianceFrameworkChart() {
    const ctx = document.getElementById('complianceFrameworkChart');
    if (!ctx) return;

    const complianceFrameworkChart = new Chart(ctx.getContext('2d'), {
        type: 'radar',
        data: {
            labels: ['HIPAA', 'HITRUST CSF', 'FDA SaMD', 'GDPR', 'SOC 2 Type II'],
            datasets: [{
                label: 'Compliance Score',
                data: [85, 88, 75, 82, 90],
                backgroundColor: 'rgba(59, 130, 246, 0.2)',
                borderColor: '#3b82f6',
                borderWidth: 3,
                pointBackgroundColor: [
                    '#22c55e',    // Green for HIPAA
                    '#3b82f6',   // Blue for HITRUST
                    '#f97316',   // Orange for FDA
                    '#a855f7',   // Purple for GDPR
                    '#ec4899'    // Pink for SOC2
                ],
                pointBorderColor: '#fff',
                pointBorderWidth: 2,
                pointHoverBackgroundColor: '#fff',
                pointHoverBorderColor: [
                    '#22c55e',
                    '#3b82f6',
                    '#f97316',
                    '#a855f7',
                    '#ec4899'
                ],
                pointHoverBorderWidth: 3,
                pointRadius: 5,
                pointHoverRadius: 7,
                borderWidth: 2,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                r: {
                    angleLines: {
                        display: true,
                        color: 'rgba(156, 163, 175, 0.3)'
                    },
                    grid: {
                        color: 'rgba(156, 163, 175, 0.2)'
                    },
                    pointLabels: {
                        color: '#374151',
                        font: {
                            size: 13,
                            weight: '600'
                        }
                    },
                    ticks: {
                        color: '#6b7280',
                        backdropColor: 'rgba(255, 255, 255, 0.8)',
                        font: {
                            size: 11
                        }
                    },
                    suggestedMin: 0,
                    suggestedMax: 100
                }
            },
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    backgroundColor: 'rgba(17, 24, 39, 0.95)',
                    titleColor: '#f9fafb',
                    bodyColor: '#f9fafb',
                    borderColor: 'rgba(156, 163, 175, 0.2)',
                    borderWidth: 1,
                    cornerRadius: 12,
                    padding: 12,
                    callbacks: {
                        label: function(context) {
                            return context.label + ': ' + context.parsed.r + '%';
                        }
                    }
                }
            },
            elements: {
                line: {
                    tension: 0.1
                }
            }
        }
    });

    return complianceFrameworkChart;
}

/**
 * Initialize cloud risk chart
 */
function initializeCloudRiskChart() {
    const ctx = document.getElementById('cloudRiskChart');
    if (!ctx) return;

    cloudRiskChart = new Chart(ctx.getContext('2d'), {
        type: 'bar',
        data: {
            labels: ['AWS', 'Azure', 'GCP', 'Local'],
            datasets: [
                {
                    label: 'High Risk',
                    data: [8, 6, 4, 12],
                    backgroundColor: 'var(--bs-danger)'
                },
                {
                    label: 'Medium Risk',
                    data: [15, 18, 22, 8],
                    backgroundColor: 'var(--bs-warning)'
                },
                {
                    label: 'Low Risk',
                    data: [25, 28, 31, 18],
                    backgroundColor: 'var(--bs-success)'
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    stacked: true
                },
                y: {
                    stacked: true,
                    beginAtZero: true
                }
            },
            plugins: {
                legend: {
                    position: 'top'
                }
            }
        }
    });
}

/**
 * Initialize vulnerability prediction chart
 */
function initializeVulnerabilityPredictionChart() {
    const ctx = document.getElementById('vulnerabilityPredictionChart');
    if (!ctx) return;

    vulnerabilityPredictionChart = new Chart(ctx.getContext('2d'), {
        type: 'line',
        data: {
            labels: ['Week 1', 'Week 2', 'Week 3', 'Week 4'],
            datasets: [
                {
                    label: 'Predicted Vulnerabilities',
                    data: [12, 18, 25, 28],
                    borderColor: 'var(--bs-danger)',
                    backgroundColor: 'rgba(var(--bs-danger-rgb), 0.1)',
                    fill: true,
                    tension: 0.4
                },
                {
                    label: 'Critical Vulnerabilities',
                    data: [3, 5, 8, 9],
                    borderColor: 'var(--bs-warning)',
                    backgroundColor: 'rgba(var(--bs-warning-rgb), 0.1)',
                    fill: true,
                    tension: 0.4
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'top'
                }
            },
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

/**
 * Initialize model performance charts
 */
function initializeModelPerformanceCharts() {
    // Model Accuracy Chart
    const accuracyCtx = document.getElementById('modelAccuracyChart');
    if (accuracyCtx) {
        modelAccuracyChart = new Chart(accuracyCtx.getContext('2d'), {
            type: 'line',
            data: {
                labels: ['Day 1', 'Day 2', 'Day 3', 'Day 4', 'Day 5', 'Day 6', 'Day 7'],
                datasets: [{
                    label: 'Accuracy %',
                    data: [94.2, 94.1, 93.8, 94.3, 94.0, 94.2, 94.1],
                    borderColor: 'var(--bs-success)',
                    backgroundColor: 'rgba(var(--bs-success-rgb), 0.1)',
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: { y: { min: 90, max: 95 } }
            }
        });
    }

    // Latency Chart
    const latencyCtx = document.getElementById('latencyChart');
    if (latencyCtx) {
        latencyChart = new Chart(latencyCtx.getContext('2d'), {
            type: 'line',
            data: {
                labels: ['Day 1', 'Day 2', 'Day 3', 'Day 4', 'Day 5', 'Day 6', 'Day 7'],
                datasets: [{
                    label: 'Latency (ms)',
                    data: [156, 158, 162, 155, 159, 156, 157],
                    borderColor: 'var(--bs-info)',
                    backgroundColor: 'rgba(var(--bs-info-rgb), 0.1)',
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: { y: { min: 150, max: 170 } }
            }
        });
    }

    // Drift Chart
    const driftCtx = document.getElementById('driftChart');
    if (driftCtx) {
        driftChart = new Chart(driftCtx.getContext('2d'), {
            type: 'line',
            data: {
                labels: ['Day 1', 'Day 2', 'Day 3', 'Day 4', 'Day 5', 'Day 6', 'Day 7'],
                datasets: [{
                    label: 'Drift Score',
                    data: [0.12, 0.15, 0.18, 0.23, 0.26, 0.28, 0.25],
                    borderColor: 'var(--bs-warning)',
                    backgroundColor: 'rgba(var(--bs-warning-rgb), 0.1)',
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: { y: { min: 0, max: 0.5 } }
            }
        });
    }
}

/**
 * Initialize period selector for charts
 */
function initializePeriodSelector() {
    const periodButtons = document.querySelectorAll('[data-period]');
    periodButtons.forEach(button => {
        button.addEventListener('click', function() {
            // Remove active class from all buttons
            periodButtons.forEach(btn => btn.classList.remove('active'));
            
            // Add active class to clicked button
            this.classList.add('active');
            
            // Update charts with new period
            const period = parseInt(this.getAttribute('data-period'));
            updateChartsForPeriod(period);
        });
    });
}

/**
 * Update charts for selected time period
 */
function updateChartsForPeriod(days) {
    if (riskTrendChart) {
        riskTrendChart.data.labels = generateDateLabels(days);
        riskTrendChart.data.datasets[0].data = generateHistoricalRiskData(days);
        riskTrendChart.data.datasets[1].data = generatePredictedRiskData(days);
        riskTrendChart.data.datasets[2].data = generatePHIExposureData(days);
        riskTrendChart.update();
    }
}

/**
 * Load analytics data from API
 */
function loadAnalyticsData() {
    // Load risk trends
    fetch('/api/risk-trends?days=30')
        .then(response => response.json())
        .then(data => {
            analyticsData.riskTrends = data;
            updateRiskTrendChart(data);
        })
        .catch(error => console.error('Error loading risk trends:', error));

    // Load predictive data
    loadPredictiveAnalytics();
}

/**
 * Load predictive analytics data
 */
function loadPredictiveAnalytics() {
    fetch('/api/predictive-analytics')
        .then(response => response.json())
        .then(data => {
            predictionData = data;
            updatePredictiveCharts(data);
        })
        .catch(error => console.error('Error loading predictive analytics:', error));
}

/**
 * Update risk trend chart with real data
 */
function updateRiskTrendChart(data) {
    if (!riskTrendChart || !data) return;

    const labels = data.map(item => item.date);
    const riskScores = data.map(item => item.average_risk_score);
    const phiExposures = data.map(item => item.phi_exposure_rate > 0 ? item.average_risk_score : null);

    riskTrendChart.data.labels = labels;
    riskTrendChart.data.datasets[0].data = riskScores;
    riskTrendChart.data.datasets[2].data = phiExposures;
    riskTrendChart.update();
}

/**
 * Update predictive charts with real data
 */
function updatePredictiveCharts(data) {
    if (!data) return;

    // Update vulnerability prediction chart
    if (vulnerabilityPredictionChart && data.vulnerability_trends) {
        const vulnData = data.vulnerability_trends;
        // Update chart with real prediction data
        vulnerabilityPredictionChart.update();
    }

    // Update other predictive visualizations
    updateBreachRiskIndicators(data.breach_risk_prediction);
    updateComplianceTrends(data.compliance_trends);
}

/**
 * Update breach risk indicators
 */
function updateBreachRiskIndicators(breachRisk) {
    if (!breachRisk) return;

    // Update risk gauge
    if (riskGaugeChart) {
        const riskPercentage = Math.round(breachRisk.probability * 100);
        riskGaugeChart.data.datasets[0].data = [riskPercentage, 100 - riskPercentage];
        riskGaugeChart.update();
    }

    // Update risk factors
    const riskFactorsContainer = document.querySelector('.risk-factors');
    if (riskFactorsContainer && breachRisk.factors) {
        updateRiskFactorsDisplay(breachRisk.factors);
    }
}

/**
 * Update risk factors display
 */
function updateRiskFactorsDisplay(factors) {
    // This would update the risk factors section with real data
    // Implementation depends on the structure of the factors data
}

/**
 * Update compliance trends
 */
function updateComplianceTrends(complianceTrends) {
    if (!complianceTrends) return;

    // Update compliance prediction displays
    const trendElements = document.querySelectorAll('[data-compliance-framework]');
    trendElements.forEach(element => {
        const framework = element.getAttribute('data-compliance-framework');
        const frameworkData = complianceTrends.frameworks[framework];
        
        if (frameworkData) {
            updateComplianceFrameworkDisplay(element, frameworkData);
        }
    });
}

/**
 * Update compliance framework display
 */
function updateComplianceFrameworkDisplay(element, data) {
    const progressBar = element.querySelector('.progress-bar');
    const trendIcon = element.querySelector('.trend-icon');
    const scoreText = element.querySelector('.score-text');

    if (progressBar) {
        progressBar.style.width = data.predicted_score_30d + '%';
    }

    if (scoreText) {
        scoreText.textContent = data.predicted_score_30d + '%';
    }

    if (trendIcon) {
        trendIcon.className = `fas fa-arrow-${data.trend === 'increasing' ? 'up text-success' : 
                                           data.trend === 'decreasing' ? 'down text-danger' : 
                                           'right text-secondary'}`;
    }
}

/**
 * Start real-time updates
 */
function startRealTimeUpdates() {
    // Update every 30 seconds
    setInterval(() => {
        loadAnalyticsData();
        updateRealTimeMetrics();
    }, 30000);
}

/**
 * Update real-time metrics
 */
function updateRealTimeMetrics() {
    // Simulate real-time metric updates
    const metricCards = document.querySelectorAll('.card h4.card-title');
    metricCards.forEach(card => {
        // Add pulse animation to show update
        card.style.animation = 'pulse 0.5s ease-in-out';
        setTimeout(() => {
            card.style.animation = '';
        }, 500);
    });
}

/**
 * Generate date labels for charts
 */
function generateDateLabels(days) {
    const labels = [];
    const today = new Date();
    
    for (let i = days - 1; i >= 0; i--) {
        const date = new Date(today);
        date.setDate(date.getDate() - i);
        labels.push(date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
    }
    
    return labels;
}

/**
 * Generate historical risk data
 */
function generateHistoricalRiskData(days) {
    const data = [];
    let baseRisk = 45;
    
    for (let i = 0; i < days; i++) {
        baseRisk += (Math.random() - 0.5) * 10;
        baseRisk = Math.max(20, Math.min(80, baseRisk));
        data.push(baseRisk);
    }
    
    return data;
}

/**
 * Generate predicted risk data
 */
function generatePredictedRiskData(days) {
    const data = new Array(Math.floor(days * 0.7)).fill(null);
    const predictionDays = Math.ceil(days * 0.3);
    let lastHistorical = 65;
    
    for (let i = 0; i < predictionDays; i++) {
        lastHistorical += (Math.random() - 0.3) * 8; // Slight upward trend
        lastHistorical = Math.max(30, Math.min(90, lastHistorical));
        data.push(lastHistorical);
    }
    
    return data;
}

/**
 * Generate PHI exposure event data
 */
function generatePHIExposureData(days) {
    const data = [];
    
    for (let i = 0; i < days; i++) {
        // Random PHI exposure events (10% chance per day)
        if (Math.random() < 0.1) {
            data.push(Math.random() * 20 + 60); // High risk score when PHI exposed
        } else {
            data.push(null);
        }
    }
    
    return data;
}

/**
 * Export analytics data
 */
function exportAnalyticsData() {
    const exportData = {
        timestamp: new Date().toISOString(),
        analytics_data: analyticsData,
        prediction_data: predictionData,
        chart_data: extractChartData()
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { 
        type: 'application/json' 
    });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `healthcare_ai_analytics_${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

/**
 * Extract data from all charts
 */
function extractChartData() {
    const chartData = {};
    
    if (riskTrendChart) {
        chartData.riskTrend = riskTrendChart.data;
    }
    
    if (protocolRiskChart) {
        chartData.protocolRisk = protocolRiskChart.data;
    }
    
    if (cloudRiskChart) {
        chartData.cloudRisk = cloudRiskChart.data;
    }
    
    return chartData;
}

// Add CSS for pulse animation
const style = document.createElement('style');
style.textContent = `
    @keyframes pulse {
        0% { transform: scale(1); }
        50% { transform: scale(1.05); }
        100% { transform: scale(1); }
    }
    
    .progress-sm {
        height: 4px;
    }
    
    .emergency-scan {
        animation: emergency-pulse 1s infinite alternate;
    }
    
    @keyframes emergency-pulse {
        from { box-shadow: 0 0 10px rgba(220, 53, 69, 0.5); }
        to { box-shadow: 0 0 20px rgba(220, 53, 69, 0.8); }
    }
`;
document.head.appendChild(style);
