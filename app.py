import os
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix

# Configure logging - reduce verbosity for better performance
logging.basicConfig(level=logging.WARNING)

# Set AWS environment variables to prevent credential lookup timeouts
os.environ.setdefault('AWS_DEFAULT_REGION', 'us-east-1')
os.environ.setdefault('AWS_ACCESS_KEY_ID', 'dummy')
os.environ.setdefault('AWS_SECRET_ACCESS_KEY', 'dummy')

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

# Create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure the database
database_url = os.environ.get("DATABASE_URL", "sqlite:///healthcare_ai_compliance.db")
app.config["SQLALCHEMY_DATABASE_URI"] = database_url

# Configure engine options for better performance and concurrency
engine_options = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Add SQLite-specific optimizations if using SQLite
if database_url.startswith('sqlite'):
    engine_options.update({
        "connect_args": {
            "check_same_thread": False,
            "timeout": 5.0
        },
        "pool_size": 5,
        "max_overflow": 10
    })

app.config["SQLALCHEMY_ENGINE_OPTIONS"] = engine_options

# Initialize the app with the extension
db.init_app(app)

# Initialize database schema synchronously BEFORE serving requests
with app.app_context():
    try:
        import models
        db.create_all()
        logging.warning("Database schema initialized synchronously")
    except Exception as e:
        logging.error(f"Failed to initialize database schema: {e}")

    # Auto-seed demo data — always called; each section checks its own table
    try:
        logging.warning("Running demo data seeder (per-section checks)...")
        from demo_seeder import seed_demo_data
        seed_demo_data(app, db)
    except Exception as e:
        logging.warning(f"Demo data auto-seed skipped: {e}")

# Health check endpoint for Azure Container Apps liveness/readiness probes
@app.route('/health')
def health_check():
    """Health check endpoint returning JSON status"""
    from flask import jsonify
    import datetime
    return jsonify({
        "status": "ok",
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "version": "1.0.0"
    }), 200

# Legacy health endpoint redirect
@app.route('/healthz')
def health_check_legacy():
    """Legacy health check endpoint"""
    from flask import jsonify
    import datetime
    return jsonify({
        "status": "ok",
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "version": "1.0.0"
    }), 200

# Fast startup mode - disable heavy integrations for now
FAST_START = os.getenv("FAST_START", "0") == "1"

# Import main routes
try:
    import app_routes
    logging.warning("Routes loaded successfully")
except Exception as e:
    logging.warning(f"Routes failed to load: {e}")
    # Create fallback route only if app_routes fails to load
    @app.route('/')
    def home():
        return "<h1>CT ComplySphere Visibility & Governance Platform</h1><p>Application is starting...</p>"

# Import and register blueprints with proper error handling
try:
    from routes.environment_scanner_routes import environment_scanner_bp
    app.register_blueprint(environment_scanner_bp)
    logging.warning("Blueprints registered successfully")
except Exception as e:
    logging.warning(f"Failed to register blueprints: {e}")

# Central asynchronous bootstrap system
import threading

def bootstrap_database():
    """Initialize database schema in background"""
    try:
        with app.app_context():
            import models
            db.create_all()
        logging.info("Database schema initialized")
    except Exception as e:
        logging.error(f"Failed to initialize database: {e}")

def bootstrap_integrations():
    """Initialize all integrations in background"""
    try:
        # Defer heavy integration imports to here
        logging.info("Initializing integrations...")
        
        # Other integrations initialized here if needed
            
        logging.info("Integrations initialized")
    except Exception as e:
        logging.error(f"Failed to initialize integrations: {e}")

def bootstrap_agents():
    """Initialize all agents in background"""  
    try:
        logging.info("Initializing agents...")
        # Import agents here when needed, don't trigger global initialization
        logging.info("Agents initialized")
    except Exception as e:
        logging.error(f"Failed to initialize agents: {e}")

def bootstrap_scheduler():
    """Initialize scheduler in background"""
    try:
        from services.scheduler_integration import init_scheduler_with_app
        init_scheduler_with_app(app)
        logging.info("Scheduler initialized")
    except ImportError as e:
        logging.warning(f"Scheduler not available: {e}")
    except Exception as e:
        logging.error(f"Failed to initialize scheduler: {e}")

def bootstrap_remediation():
    """Initialize automated remediation system in background with persistent event loop"""
    try:
        logging.info("Initializing automated remediation system...")
        
        from services.remediation_templates import remediation_template_manager
        from services.automated_remediation_service import automated_remediation_service
        import asyncio
        import threading
        
        with app.app_context():
            # Initialize remediation templates
            remediation_template_manager.initialize_templates()
            remediation_template_manager.install_default_workflows()
            
            logging.info("🔧 Starting persistent remediation service...")
            
            # Start persistent service in its own thread with event loop
            def run_persistent_service():
                """Run the remediation service with persistent event loop"""
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
                try:
                    # Initialize and run the service
                    loop.run_until_complete(automated_remediation_service.initialize())
                    loop.run_until_complete(automated_remediation_service.start_monitoring())
                    
                    # Keep the loop running
                    loop.run_forever()
                except Exception as e:
                    logging.error(f"Persistent remediation service error: {e}")
                finally:
                    loop.close()
            
            # Start in daemon thread
            service_thread = threading.Thread(target=run_persistent_service, daemon=True)
            service_thread.start()
            
            logging.info("🔧 Automated remediation system initialized successfully with persistent monitoring")
    except Exception as e:
        logging.error(f"Failed to initialize automated remediation system: {e}")

def start_async_bootstrap():
    """Start all bootstrap processes in separate daemon threads"""
    import time
    
    # Small delay to ensure Flask is ready
    time.sleep(2)
    
    # Always initialize database schema quickly
    threading.Thread(target=bootstrap_database, daemon=True).start()
    
    # Only run heavy background jobs if explicitly enabled AND not in fast start mode
    if os.getenv("BACKGROUND_JOBS") == "1" and not FAST_START:
        # Delay integrations and agents slightly to avoid overwhelming startup
        time.sleep(1)
        threading.Thread(target=bootstrap_integrations, daemon=True).start()
        
        time.sleep(1)  
        threading.Thread(target=bootstrap_agents, daemon=True).start()
        
        time.sleep(2)
        threading.Thread(target=bootstrap_scheduler, daemon=True).start()
        
        # Initialize remediation system after database is ready
        time.sleep(1)
        threading.Thread(target=bootstrap_remediation, daemon=True).start()
        
        logging.warning("Async bootstrap started with background jobs - Flask should be responsive now")
    else:
        logging.warning("Async bootstrap started in fast mode - Flask should be responsive now")

# Database is already initialized synchronously above, no need for background thread
logging.warning("Application ready to serve requests")
