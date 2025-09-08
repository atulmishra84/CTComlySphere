from app import app
# Import the main routes to register them with the app
import routes
# Import and register environment scanner blueprint
from routes.environment_scanner_routes import environment_scanner_bp
app.register_blueprint(environment_scanner_bp)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
