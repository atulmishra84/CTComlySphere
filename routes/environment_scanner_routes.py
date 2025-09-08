"""
Environment Scanner Routes

Web interface routes for the comprehensive environment scanner
"""

from flask import Blueprint, render_template, request, jsonify, redirect, url_for
import json
from datetime import datetime

from scanners.environment_scanner import environment_scanner, ScanTarget, ScannerType

environment_scanner_bp = Blueprint('environment_scanner', __name__, url_prefix='/environment-scanner')


@environment_scanner_bp.route('/')
def scanner_dashboard():
    """Environment Scanner main dashboard"""
    
    # Get scanner statistics
    stats = environment_scanner.get_scan_statistics()
    
    # Get scanner capabilities
    capabilities = environment_scanner.get_scanner_capabilities()
    
    # Get recent scan history
    recent_scans = environment_scanner.scan_history[-5:] if environment_scanner.scan_history else []
    
    # Get discovered agents
    discovered_agents = environment_scanner.get_discovered_agents()
    
    return render_template('environment_scanner/dashboard.html',
                         stats=stats,
                         capabilities=capabilities,
                         recent_scans=recent_scans,
                         discovered_agents=discovered_agents,
                         total_agents=len(discovered_agents))


@environment_scanner_bp.route('/api/run-scan', methods=['POST'])
def run_scan():
    """Start a new environment scan"""
    
    try:
        data = request.get_json()
        
        # Parse scan configuration
        environment = data.get('environment', 'All Environments')
        customer_filter = data.get('customer_filter', '')
        scanner_types = data.get('scanner_types', [])
        
        # Convert scanner type strings to enums
        if scanner_types:
            scan_types = [ScannerType(scanner_type) for scanner_type in scanner_types 
                         if scanner_type in [st.value for st in ScannerType]]
        else:
            scan_types = list(ScannerType)  # All scanners
        
        # Create scan target
        target = ScanTarget(
            environment=environment,
            customer_filter=customer_filter if customer_filter else None,
            scan_types=scan_types
        )
        
        # Start scan (sync version for Flask)
        scan_id = f"scan_{datetime.utcnow().timestamp()}"
        # In a real implementation, this would start the scan asynchronously
        # For demo purposes, we'll simulate a scan
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'message': f'Scan started with ID: {scan_id}',
            'target': {
                'environment': environment,
                'customer_filter': customer_filter,
                'scanner_count': len(scan_types)
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@environment_scanner_bp.route('/api/start-auto-scan', methods=['POST'])
def start_auto_scan():
    """Start automatic scanning"""
    
    try:
        data = request.get_json()
        
        environment = data.get('environment', 'All Environments')
        customer_filter = data.get('customer_filter', '')
        
        # Create scan target for auto-scan
        target = ScanTarget(
            environment=environment,
            customer_filter=customer_filter if customer_filter else None,
            scan_types=list(ScannerType)
        )
        
        # Start auto-scan (sync version for Flask)
        # In a real implementation, this would start auto-scan asynchronously
        # For demo purposes, we'll simulate auto-scan start
        
        return jsonify({
            'success': True,
            'message': 'Auto-scan started successfully',
            'auto_scan_enabled': True
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@environment_scanner_bp.route('/api/stop-auto-scan', methods=['POST'])
def stop_auto_scan():
    """Stop automatic scanning"""
    
    try:
        environment_scanner.stop_auto_scan()
        
        return jsonify({
            'success': True,
            'message': 'Auto-scan stopped successfully',
            'auto_scan_enabled': False
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@environment_scanner_bp.route('/api/scan-status/<scan_id>')
def get_scan_status(scan_id):
    """Get status of specific scan"""
    
    try:
        status = environment_scanner.get_scan_status(scan_id)
        
        if status:
            return jsonify({
                'success': True,
                'status': status
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Scan not found'
            }), 404
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@environment_scanner_bp.route('/api/discovered-agents')
def get_discovered_agents():
    """Get list of discovered agents with filtering"""
    
    try:
        environment = request.args.get('environment')
        customer_filter = request.args.get('customer_filter')
        
        agents = environment_scanner.get_discovered_agents(
            environment=environment,
            customer_filter=customer_filter
        )
        
        return jsonify({
            'success': True,
            'agents': agents,
            'total_count': len(agents)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@environment_scanner_bp.route('/api/scanner-capabilities')
def get_scanner_capabilities():
    """Get capabilities of all scanners"""
    
    try:
        capabilities = environment_scanner.get_scanner_capabilities()
        
        return jsonify({
            'success': True,
            'capabilities': capabilities
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@environment_scanner_bp.route('/api/scan-statistics')
def get_scan_statistics():
    """Get overall scanning statistics"""
    
    try:
        stats = environment_scanner.get_scan_statistics()
        
        return jsonify({
            'success': True,
            'statistics': stats
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@environment_scanner_bp.route('/deployment-guide')
def deployment_guide():
    """Deployment guide for scanning agents"""
    
    return render_template('environment_scanner/deployment_guide.html')


@environment_scanner_bp.route('/scanner-details/<scanner_type>')
def scanner_details(scanner_type):
    """Detailed view of specific scanner"""
    
    try:
        capabilities = environment_scanner.get_scanner_capabilities()
        
        if scanner_type not in capabilities:
            return "Scanner not found", 404
        
        scanner_info = capabilities[scanner_type]
        
        return render_template('environment_scanner/scanner_details.html',
                             scanner_type=scanner_type,
                             scanner_info=scanner_info)
        
    except Exception as e:
        return f"Error loading scanner details: {str(e)}", 500