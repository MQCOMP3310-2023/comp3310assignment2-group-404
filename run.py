from project import create_app
from project.auth import auth

if __name__ == '__main__':
    app = create_app()
    app.register_blueprint(auth)  # Register the auth Blueprint
    app.run(host='0.0.0.0', port=8000, debug=True)
