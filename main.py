from app import app
from routes.environment_scanner_routes import environment_scanner_bp

# Register environment scanner blueprint
app.register_blueprint(environment_scanner_bp)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
