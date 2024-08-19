"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
import os
from flask import Flask, request, jsonify, url_for
from flask_migrate import Migrate
from flask_cors import CORS
from utils import APIException, generate_sitemap
from admin import setup_admin
from models import db, User, Animal,Adoption, Sponsorship, AnimalImage, AdoptionForm
#Added imports
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv #for enviroment variables
from functools import wraps

#Import for errors
from sqlalchemy.exc import SQLAlchemyError
#Imports for cloudinary
import cloudinary 
import cloudinary.uploader 
from cloudinary.utils import cloudinary_url 

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


#User Registration Primary
@app.route('/register', methods=['POST'])
def register():
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

    # Check for existing email and username
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already exists'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already exists'}), 400

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

    try:
        # Add the new user to the database and commit
        db.session.add(new_user)
        db.session.commit()
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

    return jsonify({'message': 'User created successfully!', 'user': new_user.serialize()}), 201
##########################################################################

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
##########################-- Log Out--#######################

#############################################################

####################--Decorator for token required --#########################################
def token_required(f):
    @wraps(f)
    @jwt_required()
    def decorated_function(*args, **kwargs):
        current_user = get_jwt_identity()  # Extracts the current user's identity from the token
        return f(*args, **kwargs)
    return decorated_function
############

######################--Decorator to check if the user is an admin--###################
def admin_required(f):
    @wraps(f)
    @jwt_required()
    def wrapper(*args, **kwargs):
        user_id = get_jwt_identity()  # Get the user ID from the JWT token
        user = User.query.get(user_id)  # Fetch the user object from the database
        if not user or not user.is_admin:
            return jsonify({"message": "Access denied! You need to be an Admin!"}), 403
        return f(*args, **kwargs)
    return wrapper

#################################################################################################
##############################--Delete User--###############################
# Delete user account
@app.route('/delete_user', methods=['DELETE'])
@jwt_required() 
def delete_user():
    current_user_id = get_jwt_identity()  # Extract the current user’s ID from the token
    user_to_delete = User.query.get(current_user_id)  # Fetch the user from the database

    if not user_to_delete:
        return jsonify({"error": "User not found!"}), 404

    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        return jsonify({"message": "User account deleted successfully!"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500



############################ User Profile Route######################################################



###########################################Admin Features#########################

#######################--Add Animals Admin--###########working######
# Add animal (admin only)
""" @app.route('/admin_add_animal', methods=['POST'])
@jwt_required()
@admin_required
def add_animal():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user.is_admin:
        return jsonify({"message": "Access denied! You need to be an admin!"}), 403

    data = request.get_json()
    name = data.get('name')
    species = data.get('species')
    gender = data.get('gender')
    description = data.get('description')
    location = data.get('location', None)
    life_stage = data.get('life_stage', None)
    weight = data.get('weight', None)
    breed = data.get('breed', None)
    known_illness = data.get('known_illness', None)

    if not all([name, species, gender, description]):
        return jsonify({'error': 'Missing required fields'}), 400

    new_animal = Animal(
        name=name,
        species=species,
        gender=gender,
        description=description,
        location=location,
        life_stage=life_stage,
        weight=weight,
        breed=breed,
        known_illness=known_illness
    )

    try:
        db.session.add(new_animal)
        db.session.commit()
        return jsonify({'message': 'Animal created successfully!', 'animal': new_animal.serialize()}), 201
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
##############################################################

############################----Delete Animal----###################
@app.route('/admin_delete_animal/<int:animal_id>', methods=['DELETE'])
@jwt_required()  # Ensure the request has a valid JWT token
@admin_required  # Ensure the authenticated user is an admin
def delete_animal(animal_id):
    # Fetch the animal from the database by its ID
    animal = Animal.query.get(animal_id)

    if not animal:
        return jsonify({"error": "Animal not found!"}), 404

    try:
        # Delete the animal from the database
        db.session.delete(animal)
        db.session.commit()
        return jsonify({"message": "Animal deleted successfully!"}), 200
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500 """

######################################################################
##############################--Add Animal with Image Test--########################################
@app.route('/admin_add_animal', methods=['POST'])
@jwt_required()
@admin_required
def add_animal():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user.is_admin:
        return jsonify({"message": "Access denied! You need to be an admin!"}), 403

    data = request.form
    name = data.get('name')
    species = data.get('species')
    gender = data.get('gender')
    description = data.get('description')
    location = data.get('location', None)
    life_stage = data.get('life_stage', None)
    weight = data.get('weight', None)
    breed = data.get('breed', None)
    known_illness = data.get('known_illness', None)

    if not all([name, species, gender, description]):
        return jsonify({'error': 'Missing required fields'}), 400

    new_animal = Animal(
        name=name,
        species=species,
        gender=gender,
        description=description,
        location=location,
        life_stage=life_stage,
        weight=weight,
        breed=breed,
        known_illness=known_illness
    )

    try:
        db.session.add(new_animal)
        db.session.commit()

        # Handle file uploads
        image_urls = []
        if 'image' in request.files:
            image_files = request.files.getlist('image')
            if image_files:
                for image_file in image_files:
                    upload_result = cloudinary.uploader.upload(image_file)
                    image_url = upload_result['secure_url']
                    image_urls.append(image_url)
                    # Add each image record to the database
                    animal_image = AnimalImage(animal_id=new_animal.id, image_url=image_url)
                    db.session.add(animal_image)

        db.session.commit()
        
        return jsonify({'message': 'Animal created successfully!', 'animal': new_animal.serialize(), 'image_urls': image_urls}), 201
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


######################################################################

##############################################---Public Routes---########################################################
# Fetch all animals from the database
@app.route('/animals', methods=['GET'])
def list_all_animals():
    try:
        animals = Animal.query.all()
        return jsonify([animal.serialize() for animal in animals]), 200
    except SQLAlchemyError as e:
        return jsonify({'error': str(e)}), 500


########################################################################################################################


# Print 10 animals test
@app.route('/api/animals', methods=['GET'])
def get_animals():
    animals = Animal.query.limit(10).all()
    return jsonify([animal.serialize() for animal in animals])

# this only runs if `$ python src/app.py` is executed
if __name__ == '__main__':
    PORT = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=PORT, debug=False)
