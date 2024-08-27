import os
import logging
from flask import Flask, request, jsonify, url_for, redirect
from flask_migrate import Migrate
from flask_cors import CORS
from utils import APIException, generate_sitemap
from admin import setup_admin
from models import db, User, Animal,Adoption, Sponsorship, AnimalImage, AdoptionForm
#Added imports
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv #for enviroment variables
from functools import wraps
from datetime import datetime,timedelta
#Import for errors
from sqlalchemy.exc import SQLAlchemyError
#Imports for cloudinary
import cloudinary.uploader 
from cloudinary.utils import cloudinary_url 
#import for jwt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
import stripe

app = Flask(__name__)
app.url_map.strict_slashes = False

# Load environment variables from .env file
load_dotenv()

# Setup the Flask-JWT-Extended extension
jwt_super_secret = os.getenv('JWT_SUPER_SECRET')
app.config["JWT_SECRET_KEY"] = jwt_super_secret
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
jwt = JWTManager(app)

#DB
db_url = os.getenv("DATABASE_URL")
#print(db_url)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

MIGRATE = Migrate(app, db)
db.init_app(app)
CORS(app)
setup_admin(app)
#######################-Cloudinary Confing--#########
cloudinary_cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME")
cloudinary_api_key = os.getenv("CLOUDINARY_API_KEY")
cloudinary_api_secret = os.getenv("CLOUDINARY_API_SECRET") 
cloudinary_url = os.getenv("CLOUDINARY_URL")

cloudinary.config( 
    cloud_name = cloudinary_cloud_name, 
    api_key = cloudinary_api_key , 
    api_secret = cloudinary_api_secret ,
    secure=True
)

#Stripe config#
stripe_secret_key = os.getenv("SECRET_KEY")
stripe_publishable_key = os.getenv("PUBLISHABLE_KEY")

stripe.api_key=stripe_secret_key
STRIPE_TEST_PUBLISHABLE_KEY=stripe_publishable_key


################# Handle/serialize errors like a JSON object#######
@app.errorhandler(APIException)
def handle_invalid_usage(error):
    return jsonify(error.to_dict()), error.status_code

# generate sitemap with all your endpoints
@app.route('/')
def sitemap():
    return generate_sitemap(app)

####################Tests################

#User Registration Primary - db v2 working (check response 0)
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    # Extract data from the JSON payload
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    email = data.get('email')
    password = data.get('password')
    phone_number = data.get('phone_number', None)
    is_admin = data.get('is_admin', False)
    
    # Validate required fields
    if not first_name or not last_name or not email or not password:
        return jsonify({'error': 'Missing required fields'}), 400

    # Check for existing email
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already exists'}), 400

    # Hash the password
    hashed_password = generate_password_hash(password)

    # Create a new user instance
    new_user = User(
        first_name=first_name,
        last_name=last_name,
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

##########################--end of register route--#############

##########################--Login Route-- db v2 working
@app.route('/login', methods=['POST']) 
def login():
    data = request.get_json()
    email = data.get('email')
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
@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    # Could also black list in the db (too much trouble)
    
    #lets give the user a confirmation 
    return jsonify({"message": "Successfully logged out"}), 200

####################--Decorator for token required --db v2 working #########################################
def token_required(f):
    @wraps(f)
    @jwt_required()
    def decorated_function(*args, **kwargs):
        current_user = get_jwt_identity()  # Extracts the current user's identity from the token
        return f(*args, **kwargs)
    return decorated_function
############

######################--Decorator to check if the user is an admin---db v2 working -###################
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

##############################--Delete User--###############################
# Delete user account-- db v2 working
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
########v4 get user profile (with animal images)#####
@app.route('/get_user_profile', methods=['GET'])
@jwt_required()
def get_user_profile():
    # Get the current user's identity from the JWT token
    user_id = get_jwt_identity()

    # Query the user from the db
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found!"}), 404

    # Query sponsored pets with associated animal data including images
    sponsored_pets = Sponsorship.query.filter_by(user_id=user_id).all()
    sponsored_pets_data = [
        {
            **sponsorship.serialize(),
            "animal": sponsorship.animal.serialize()  # Include the serialized animal data with images
        }
        for sponsorship in sponsored_pets
    ]

    # Query adoptions with associated animal data including images
    adoptions = Adoption.query.filter_by(user_id=user_id).all()
    adoptions_data = [
        {
            **adoption.serialize(),
            "animal": adoption.animal.serialize()  # Include the serialized animal data with images
        }
        for adoption in adoptions
    ]

    # Prepare user profile response
    user_profile_data = user.serialize()
    user_profile_data['sponsored_pets'] = sponsored_pets_data
    user_profile_data['adoptions'] = adoptions_data

    return jsonify(user_profile_data), 200

##################################### Get Single User Info ######################
#Get User By JWT Token
@app.route('/profile', methods=['GET'])  
@jwt_required()
def get_user_info():
    # Get the current user's identity from the JWT token
    user_id = get_jwt_identity()

    # Fetch the user from the database
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found!"}), 404

    # Return the user profile information
    return jsonify(user.serialize()), 200

#Update user Info####################- Added v3
@app.route('/update_user', methods=['PUT'])
@jwt_required()
def update_user():
    # Get the current user's identity from the JWT token
    user_id = get_jwt_identity()

    # Fetch the user from the database
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found!"}), 404

    # Get the data from the request
    data = request.get_json()

    # Update user details with the provided data, only if they exist in the request
    user.first_name = data.get('first_name', user.first_name)
    user.last_name = data.get('last_name', user.last_name)
    user.email = data.get('email', user.email)
    user.phone_number = data.get('phone_number', user.phone_number)

    # If password is provided, hash it before updating
    if 'password' in data:
        user.password = generate_password_hash(data['password'])

    try:
        # Save the updated user data to the database
        db.session.commit()
        return jsonify({"message": "User information updated successfully!", "user": user.serialize()}), 200
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

#####---User/ Animal Related Features--########################
#Test Route to adtop also ataches form
@app.route('/adopt', methods=['POST'])
@jwt_required()
def create_adoption():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user:
        return jsonify({"error": "User not found!"}), 404

    data = request.get_json()

    # Extract data for the form
    animal_id = data.get('animal_id')
    animal_name = data.get('animal_name')
    animal_reference = data.get('animal_reference')
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    email = data.get('email')
    phone_number = data.get('phone_number')
    first_time_adopting = data.get('first_time_adopting')
    already_have_pets = data.get('already_have_pets')
    current_pets_description = data.get('current_pets_description')
    interest_reason = data.get('interest_reason')
    met_animal = data.get('met_animal')
    space_for_play = data.get('space_for_play')
    able_to_front_vet_bills = data.get('able_to_front_vet_bills')

    # Validate required fields
    if not all([animal_id, animal_name, first_name, last_name, email, first_time_adopting, interest_reason, met_animal, space_for_play, able_to_front_vet_bills]):
        return jsonify({'error': 'Missing required fields'}), 400

    # Check if the animal exists
    animal = Animal.query.get(animal_id)
    if not animal:
        return jsonify({'error': 'Animal not found'}), 404

    # Create the adoption form
    adoption_form = AdoptionForm(
        animal_name=animal_name,
        animal_reference=animal_reference,
        first_name=first_name,
        last_name=last_name,
        email=email,
        phone_number=phone_number,
        first_time_adopting=first_time_adopting,
        already_have_pets=already_have_pets,
        current_pets_description=current_pets_description,
        interest_reason=interest_reason,
        met_animal=met_animal,
        space_for_play=space_for_play,
        able_to_front_vet_bills=able_to_front_vet_bills
    )

    try:
        db.session.add(adoption_form)
        db.session.commit()

        # Create the adoption record
        adoption = Adoption(
            user_id=user.id,
            animal_id=animal.id,
            form_id=adoption_form.id,
            adoption_status='Pending'
        )

        db.session.add(adoption)
        db.session.commit()

        return jsonify({'message': 'Adoption request submitted successfully!', 'adoption': adoption.serialize()}), 201

    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


###########################################Admin Features#########################

#######################--Add Animals Admin--###########working######
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
""" @app.route('/admin_delete_animal/<int:animal_id>', methods=['DELETE'])
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
##############################--Add Animal with Image Test- db v2 working (small problem with known illness)-########################################
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

#Delete Animal Admin Only  and Images From cloudinary---v2 db working and deleting pictures
#Trying route to delete animal and animal images from cloudinary when deleting animal
@app.route('/admin_delete_animal/<int:animal_id>', methods=['DELETE'])
@jwt_required()
@admin_required
def delete_animal(animal_id):
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user.is_admin:
        return jsonify({"message": "Access denied! You need to be an admin!"}), 403

    animal = Animal.query.get(animal_id)
    if not animal:
        return jsonify({"message": "Animal not found"}), 404

    try:
        # Get associated images
        images = AnimalImage.query.filter_by(animal_id=animal_id).all()
        
        # Delete images from Cloudinary
        for image in images:
            try:
                # Extract the public ID from the image URL
                public_id = image.image_url.split('/')[-1].split('.')[0]  # Adjust if needed
                cloudinary.uploader.destroy(public_id)
            except CloudinaryError as e:
                # Log the error or handle it accordingly
                print(f"Failed to delete image from Cloudinary: {e}")

        # Delete images from the database
        AnimalImage.query.filter_by(animal_id=animal_id).delete()

        # Then delete the animal
        db.session.delete(animal)
        db.session.commit()

        return jsonify({"message": "Animal and associated images deleted successfully"}), 200
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500
############################################################################

#####################################--Admin Update Animal--#######################################
@app.route('/admin_update_animal/<int:animal_id>', methods=['PUT'])
@jwt_required()
@admin_required
def update_animal(animal_id):
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user.is_admin:
        return jsonify({"message": "Access denied! You need to be an admin!"}), 403

    animal = Animal.query.get(animal_id)
    if not animal:
        return jsonify({"error": "Animal not found!"}), 404

    data = request.form.to_dict()  # Extract form data
    images = request.files.getlist('image')  # Extract files

    # Ensure at least one field or image is provided for update
    if not data and not images:
        return jsonify({"error": "No data or images provided for update!"}), 400

    # Log received data and images for debugging
    print(f"Received data: {data}")
    print(f"Received images: {images}")

    # Update the animal attributes only if new values are provided
    animal.name = data.get('name', animal.name)
    animal.species = data.get('species', animal.species)
    animal.gender = data.get('gender', animal.gender)
    animal.description = data.get('description', animal.description)
    animal.location = data.get('location', animal.location)
    animal.life_stage = data.get('life_stage', animal.life_stage)
    animal.weight = data.get('weight', animal.weight)
    animal.breed = data.get('breed', animal.breed)
    animal.known_illness = data.get('known_illness', animal.known_illness)

    # Handle image uploads if any
    if images:
        try:
            for image in images:
                upload_result = cloudinary.uploader.upload(image)
                image_url = upload_result['secure_url']

                # Create a new AnimalImage record for each uploaded image
                new_image = AnimalImage(animal_id=animal.id, image_url=image_url)
                db.session.add(new_image)

        except Exception as e:
            return jsonify({"error": f"Failed to upload images: {str(e)}"}), 500

    try:
        db.session.commit()
        return jsonify({'message': 'Animal updated successfully!', 'animal': animal.serialize()}), 200
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


############################################################################
#Delete single image from cloudinary and db working 🏆
@app.route('/delete_image/<int:image_id>', methods=['DELETE'])
@jwt_required()
@admin_required
def delete_image(image_id):
    # Fetch the image record from the database by its ID
    image = AnimalImage.query.get(image_id)

    if not image:
        return jsonify({"error": "Image not found!"}), 404

    try:
        # Extract the public ID from the image URL
        public_id = image.image_url.split('/')[-1].split('.')[0]  # Extract the public ID

        # Delete the image from Cloudinary
        cloudinary.uploader.destroy(public_id)

        # Delete the image record from the database
        db.session.delete(image)
        db.session.commit()

        return jsonify({"message": "Image and associated data deleted successfully!"}), 200
    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({"error": f"Failed to delete image from the database: {str(e)}"}), 500
#################################################################
#Get All Adoptions
@app.route('/adoptions', methods=['GET'])
@jwt_required()
@admin_required
def get_all_adoptions():
    try:
        # Query all adoptions from the database
        adoptions = Adoption.query.all()

        # Serialize each adoption, including the associated animal and its images
        adoptions_data = [
            {
                **adoption.serialize(),
                "animal": {
                    **adoption.animal.serialize(),
                    "images": [image.serialize() for image in adoption.animal.images]
                }
            }
            for adoption in adoptions
        ]

        return jsonify(adoptions_data), 200

    except SQLAlchemyError as e:
        return jsonify({'error': str(e)}), 500

#Update Adoption Status
@app.route('/update_adoption_status/<int:adoption_id>', methods=['PUT'])
@jwt_required()
@admin_required
def update_adoption_status(adoption_id):
    # Fetch the adoption record by ID
    adoption = Adoption.query.get(adoption_id)
    if not adoption:
        return jsonify({"error": "Adoption not found!"}), 404

    # Get the new status from the request data
    data = request.get_json()
    new_status = data.get('adoption_status')

    # Validate that the new status is provided
    if not new_status:
        return jsonify({'error': 'Missing required fields: adoption_status'}), 400

    # Update the adoption status
    adoption.adoption_status = new_status

    try:
        # Commit the changes to the database
        db.session.commit()
        return jsonify({"message": "Adoption status updated successfully!", "adoption": adoption.serialize()}), 200
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

#####################################---Stripe Payment Route--#######################################

#Followinng Stripe's Instructions to payment
YOUR_DOMAIN = 'http://localhost:5173' # no extra dash bite server here!

@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    try:
        # Receive the amount from the request's body
        data = request.get_json()
        print(data)
        euro_amount = int(data['amount']) #euros


        user_id = data['user_id']  # ID of the user making the payment
        animal_id = data['animal_id']  # ID of the animal being sponsored

        if euro_amount <= 0:
            return jsonify({'error': 'Invalid amount'}), 400

        # Convert euros to cents
        cent_amount = euro_amount * 100

        # Create a checkout session with the specified amount in cents
        checkout_session = stripe.checkout.Session.create(
            line_items=[{
                'price_data': {
                    'currency': 'eur',
                    'product_data': {
                        'name': 'Custom Amount',
                    },
                    'unit_amount': cent_amount,
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url=YOUR_DOMAIN + '/success',
            cancel_url=YOUR_DOMAIN + '/cancel',
            #Added to try metadata via webhook
            metadata={
                'user_id': user_id,
                'animal_id': animal_id,
                'sponsorship_amount': str(euro_amount),  # Store amount as a string
            } 
        )
        # Session is created successfully
        print(checkout_session)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    return jsonify({'url': checkout_session.url})




#Webhook for stripe response
@app.route('/webhook', methods=['POST'])
def stripe_webhook():
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get('Stripe-Signature')

    print(payload)

    webhook_secret = os.getenv('STRIPE_WEBHOOK_SECRET')  # Add your Stripe webhook secret here
    event = None

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
    except ValueError as e:
        return jsonify({'error': 'Invalid payload'}), 400
    except stripe.error.SignatureVerificationError as e:
        return jsonify({'error': 'Invalid signature'}), 400

    # Handle the event
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']

        # Extract metadata
        user_id = session['metadata']['user_id']
        animal_id = session['metadata']['animal_id']
        sponsorship_amount = session['metadata']['sponsorship_amount']

        # Automatically generate the sponsorship date
        sponsorship_date = datetime.now()

        try:
            # Insert the sponsorship into the database
            new_sponsorship = Sponsorship(
                user_id=user_id,
                animal_id=animal_id,
                sponsorship_amount=sponsorship_amount,
                sponsorship_date=sponsorship_date
            )
            db.session.add(new_sponsorship)
            db.session.commit()
            return jsonify({'status': 'success'}), 200
        except SQLAlchemyError as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500

    return jsonify({'status': 'success'}), 200


############################## Second Test Stripe payment route
""" @app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    try:
        # Receive data from the request's body
        data = request.get_json()
        print(data)

        # Extract the amount in euros
        euro_amount = int(data.get('amount', 0))  # euros

        # Validate the amount
        if euro_amount <= 0:
            return jsonify({'error': 'Invalid amount'}), 400

        # Convert euros to cents
        cent_amount = euro_amount * 100

        # Extract additional fields for Sponsorship
        user_id = data.get('user_id')
        animal_id = data.get('animal_id')
        sponsorship_amount = data.get('sponsorship_amount', '0')  # Default to '0'
        sponsorship_date = data.get('sponsorship_date', datetime.now())  # Default to now

        # Optional: Validate additional fields
        if not user_id or not animal_id:
            return jsonify({'error': 'User ID and Animal ID are required'}), 400

        # Create a checkout session with the specified amount in cents
        checkout_session = stripe.checkout.Session.create(
            line_items=[{
                'price_data': {
                    'currency': 'eur',
                    'product_data': {
                        'name': 'Custom Amount',
                    },
                    'unit_amount': cent_amount,
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url=YOUR_DOMAIN + '/success',
            cancel_url=YOUR_DOMAIN + '/cancel',
        )

        # (Optional) Save the sponsorship details in the database
        new_sponsorship = Sponsorship(
            user_id=user_id,
            animal_id=animal_id,
            sponsorship_amount=sponsorship_amount,
            sponsorship_date = data.get('sponsorship_date', None)
        )
        db.session.add(new_sponsorship)
        db.session.commit()

    except Exception as e:
        return jsonify({'error': str(e)}), 500

    return jsonify({'url': checkout_session.url}) """

##############################################---Public Routes---########################################################
# Fetch all animals from the database
@app.route('/animals', methods=['GET'])
def list_all_animals():
    try:
        animals = Animal.query.all()
        return jsonify([animal.serialize() for animal in animals]), 200
    except SQLAlchemyError as e:
        return jsonify({'error': str(e)}), 500
#######################################################################
#Get Single Animal
@app.route('/animal/<int:animal_id>', methods=['GET'])
def get_animal(animal_id):
    # Fetch the animal from the database by its ID
    animal = Animal.query.get(animal_id)
    
    if not animal:
        return jsonify({"error": "Animal not found!"}), 404

    # Serialize the animal data
    return jsonify(animal.serialize()), 200

# Print 10 animals  first test
@app.route('/api/animals', methods=['GET'])
def get_animals():
    animals = Animal.query.limit(10).all()
    return jsonify([animal.serialize() for animal in animals])

# this only runs if `$ python src/app.py` is executed
if __name__ == '__main__':
    PORT = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=PORT, debug=False)
