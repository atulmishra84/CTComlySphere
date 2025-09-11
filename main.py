from app import app
# Import and register environment scanner blueprint
from routes.environment_scanner_routes import environment_scanner_bp
from routes.enhanced_dashboard_routes import enhanced_dashboard_bp
app.register_blueprint(environment_scanner_bp)
app.register_blueprint(enhanced_dashboard_bp)

# Import the main routes file properly
import routes

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
