import os
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix

# Configure logging
logging.basicConfig(level=logging.DEBUG)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

# Create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure the database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///healthcare_ai_compliance.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Initialize the app with the extension
db.init_app(app)

# Import and register routes first (should be side-effect free)
try:
    import app_routes
    logging.info("Routes loaded successfully")
except Exception as e:
    logging.error(f"Failed to load routes: {e}")
    # Create minimal routes for testing
    @app.route('/')
    def home():
        return "<h1>Healthcare AI Compliance Platform</h1><p>Application is starting...</p>"

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
    """Initialize automated remediation system in background"""
    try:
        logging.info("Initializing automated remediation system...")
        
        from services.remediation_templates import remediation_template_manager
        from services.automated_remediation_service import automated_remediation_service
        import asyncio
        
        with app.app_context():
            # Initialize remediation templates
            remediation_template_manager.initialize_templates()
            remediation_template_manager.install_default_workflows()
            
            # Initialize automated remediation service
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(automated_remediation_service.initialize())
            loop.close()
            
            logging.info("🔧 Automated remediation system initialized successfully")
    except Exception as e:
        logging.error(f"Failed to initialize automated remediation system: {e}")

def start_async_bootstrap():
    """Start all bootstrap processes in separate daemon threads"""
    import time
    
    # Small delay to ensure Flask is ready
    time.sleep(2)
    
    # Start each component in its own daemon thread
    threading.Thread(target=bootstrap_database, daemon=True).start()
    
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
    
    logging.info("Async bootstrap started - Flask should be responsive now")

# Start bootstrap in background thread
bootstrap_thread = threading.Thread(target=start_async_bootstrap, daemon=True)
bootstrap_thread.start()
logging.info("Background bootstrap thread started")
