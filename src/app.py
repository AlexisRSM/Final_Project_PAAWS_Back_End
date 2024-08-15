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




app = Flask(__name__)
app.url_map.strict_slashes = False

# Load environment variables from .env file
load_dotenv()

db_url = os.getenv("DATABASE_URL")
print(db_url)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

MIGRATE = Migrate(app, db)
db.init_app(app)
CORS(app)
setup_admin(app)

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

""" User Autentication """
####################Tests################
""" @app.before_first_request
def create_tables():
    db.create_all() """


#User Registration
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(username=data['username'], email=data['email'], full_name=data['full_name'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "Registered successfully!"}), 201

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
