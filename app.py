from flask import Flask, request, jsonify
from flask_cors import CORS
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta
import jwt
import hashlib
import os

# Database setup
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./auth.db")

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Models
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    license_key = Column(String, unique=True, index=True)
    hwid = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    total_logins = Column(Integer, default=0)

# Create tables
Base.metadata.create_all(bind=engine)

# Flask app
app = Flask(__name__)
CORS(app)

# JWT configuration
SECRET_KEY = os.environ.get("SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Helper functions
def create_access_token(data):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None

def hash_hwid(hwid):
    return hashlib.sha256(hwid.encode()).hexdigest()

# Routes
@app.route('/api/auth', methods=['POST'])
def authenticate():
    """Authenticate user with license key, HWID, and IP"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
            
        license_key = data.get('license_key')
        hwid = data.get('hwid')
        ip_address = data.get('ip_address')
        
        if not all([license_key, hwid, ip_address]):
            return jsonify({"error": "Missing required fields"}), 400
        
        db = SessionLocal()
        
        # Find user by license key
        user = db.query(User).filter(User.license_key == license_key).first()
        
        if not user:
            db.close()
            return jsonify({"error": "Invalid license key"}), 401
        
        if not user.is_active:
            db.close()
            return jsonify({"error": "License is deactivated"}), 403
        
        hashed_hwid = hash_hwid(hwid)
        
        # If it's first login, register HWID and IP
        if not user.hwid:
            user.hwid = hashed_hwid
            user.ip_address = ip_address
            user.last_login = datetime.utcnow()
            user.total_logins = 1
            
            # Create token
            token_data = {
                "sub": license_key,
                "hwid": user.hwid,
                "ip": ip_address
            }
            token = create_access_token(token_data)
            
            db.commit()
            db.close()
            
            return jsonify({
                "status": True,
                "message": "HWID registered successfully",
                "token": token,
                "license_key": license_key
            })
        
        # Check if HWID matches
        if user.hwid != hashed_hwid:
            db.close()
            return jsonify({"error": "HWID mismatch"}), 403
        
        # Update login info
        user.last_login = datetime.utcnow()
        user.total_logins += 1
        
        # Create token
        token_data = {
            "sub": license_key,
            "hwid": user.hwid,
            "ip": ip_address
        }
        token = create_access_token(token_data)
        
        db.commit()
        db.close()
        
        return jsonify({
            "status": True,
            "message": "Authentication successful",
            "token": token,
            "license_key": license_key
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/validate', methods=['POST'])
def validate_token():
    """Validate JWT token"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
            
        token = data.get('token')
        if not token:
            return jsonify({"error": "Token is required"}), 400
        
        payload = verify_token(token)
        
        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 401
        
        return jsonify({
            "status": True,
            "message": "Token is valid",
            "license_key": payload.get("sub"),
            "hwid": payload.get("hwid")
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/register', methods=['POST'])
def register_license():
    """Register a new license key"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
            
        license_key = data.get('license_key')
        if not license_key:
            return jsonify({"error": "License key is required"}), 400
        
        db = SessionLocal()
        
        # Check if key already exists
        existing = db.query(User).filter(User.license_key == license_key).first()
        if existing:
            db.close()
            return jsonify({"error": "License key already exists"}), 400
        
        # Create new user
        new_user = User(
            license_key=license_key,
            is_active=True,
            created_at=datetime.utcnow()
        )
        
        db.add(new_user)
        db.commit()
        db.close()
        
        return jsonify({
            "status": True,
            "message": "License key registered successfully",
            "license_key": license_key
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/check/<license_key>', methods=['GET'])
def check_license(license_key):
    """Check license status"""
    try:
        if not license_key:
            return jsonify({"error": "License key is required"}), 400
        
        db = SessionLocal()
        user = db.query(User).filter(User.license_key == license_key).first()
        db.close()
        
        if not user:
            return jsonify({"error": "License key not found"}), 404
        
        return jsonify({
            "status": True,
            "license_key": user.license_key,
            "is_active": user.is_active,
            "has_hwid": user.hwid is not None,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "last_login": user.last_login.isoformat() if user.last_login else None,
            "total_logins": user.total_logins
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/', methods=['GET'])
def root():
    """Root endpoint"""
    return jsonify({
        "status": "online",
        "service": "Auth API",
        "version": "1.0.0",
        "endpoints": [
            "/api/auth - POST - Authenticate",
            "/api/validate - POST - Validate token",
            "/api/register - POST - Register license",
            "/api/check/{key} - GET - Check license"
        ]
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
