"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
import os
from flask import Flask, request, jsonify, url_for
from flask_migrate import Migrate
from flask_cors import CORS
from utils import APIException, generate_sitemap
from admin import setup_admin
from models import db, User, Animal,Adoption, Sponsorship 
#Added imports
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv #for enviroment variables
#Import for errors
from sqlalchemy.exc import SQLAlchemyError
#Imports for cloudinary
""" import cloudinary """
""" import cloudinary.uploader """

""" from cloudinary.utils import cloudinary_url """
#import for jwt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager




app = Flask(__name__)
app.url_map.strict_slashes = False

# Load environment variables from .env file
load_dotenv()
#jwt authentication
# Setup the Flask-JWT-Extended extension
jwt_super_secret = os.getenv('JWT_SUPER_SECRET')
app.config["JWT_SECRET_KEY"] = jwt_super_secret
jwt = JWTManager(app)

#DB
db_url = os.getenv("DATABASE_URL")
print(db_url)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

MIGRATE = Migrate(app, db)
db.init_app(app)
CORS(app)
setup_admin(app)
#######################confing cloudinary#########
# Configuration
cloudinary_cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME")
cloudinary_api_key = os.getenv("CLOUDINARY_API_KEY")
cloudinary_api_secret = os.getenv("CLOUDINARY_API_SECRET") 
cloudinary_url = os.getenv("CLOUDINARY_URL")

cloudinary.config( 
    cloud_name = cloudinary_cloud_name, 
    api_key = cloudinary_api_key , 
    api_secret = cloudinary_api_secret , # Click 'View API Keys' above to copy your API secret
    secure=True
)
#

# Upload an image
""" upload_result = cloudinary.uploader.upload("https://res.cloudinary.com/demo/image/upload/getting-started/shoes.jpg",public_id="shoes")
print(upload_result["secure_url"])

# Optimize delivery by resizing and applying auto-format and auto-quality
optimize_url, _ = cloudinary_url("shoes", fetch_format="auto", quality="auto")
print(optimize_url)

# Transform the image: auto-crop to square aspect_ratio
auto_crop_url, _ = cloudinary_url("shoes", width=500, height=500, crop="auto", gravity="auto")
print(auto_crop_url) """
#######################################################
# Handle/serialize errors like a JSON object
@app.errorhandler(APIException)
def handle_invalid_usage(error):
    return jsonify(error.to_dict()), error.status_code

# generate sitemap with all your endpoints
@app.route('/')
def sitemap():
    return generate_sitemap(app)

@app.route('/user', methods=['GET'])
def handle_hello():

    response_body = {
        "msg": "Hello, this is your GET /user response "
    }

    return jsonify(response_body), 200


####################Tests################


#User Registration
""" @app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(username=data['username'], email=data['email'], full_name=data['full_name'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "Registered successfully!"}), 201 """

#Another resgistation test
@app.route('/create-user', methods=['POST'])
def create_user():
    data = request.get_json()

    # Extract data from the JSON payload
    username = data.get('username')
    full_name = data.get('full_name')
    email = data.get('email')
    password = data.get('password')
    phone_number = data.get('phone_number', None)
    is_admin = data.get('is_admin', False)
    
    if not username or not full_name or not email or not password:
        return jsonify({'error': 'Missing required fields'}), 400

    # Hash the password
    hashed_password = generate_password_hash(password)

    # Create a new user instance
    new_user = User(
        username=username,
        full_name=full_name,
        email=email,
        password=hashed_password,
        phone_number=phone_number,
        is_admin=is_admin
    )

    # Add the new user to the database and commit
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User created successfully!', 'user': new_user.serialize()}), 201
##########################--end of register route--#############

##########################--Login Route--#############

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')  # Changed from username to email
    password = data.get('password')

    # Fetch user from database by email
    user = User.query.filter_by(email=email).first()

    # Check if user exists and password is correct
    if user and check_password_hash(user.password, password):
        # Create a JWT token
        access_token = create_access_token(identity=user.id)
        return jsonify({
            'token': access_token,
            'user_id': user.id
        }), 200
    else:
        return jsonify({"msg": "Invalid email or password"}), 401

##########################--End of Login Route--#############


# User Profile Route

""" @token_required (change order to work)"""
""" @app.route('/profile')
def profile(current_user):
    sponsored_animals = [sponsorship.animal.serialize() for sponsorship in current_user.sponsorships]
    adopted_animals = [adoption.animal.serialize() for adoption in current_user.adoptions]
    return jsonify({
        "user": current_user.serialize(),
        "sponsored_animals": sponsored_animals,
        "adopted_animals": adopted_animals
    })
"""

#Test Get all animals
# Print 10 animals test
@app.route('/api/animals', methods=['GET'])
def get_animals():
    animals = Animal.query.limit(10).all()
    return jsonify([animal.serialize() for animal in animals])

# this only runs if `$ python src/app.py` is executed
if __name__ == '__main__':
    PORT = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=PORT, debug=False)
