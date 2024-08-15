import os
import datetime
from flask import Flask, request, jsonify, url_for, flash, redirect, render_template
from flask_migrate import Migrate
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import jwt
from utils import APIException, generate_sitemap
from models import db, User, Animal, Adoption, Sponsorship

app = Flask(__name__)
app.url_map.strict_slashes = False

# Database configuration
db_url = os.getenv("DATABASE_URL")
if db_url is not None:
    app.config['SQLALCHEMY_DATABASE_URI'] = db_url.replace("postgres://", "postgresql://")
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///test.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'

MIGRATE = Migrate(app, db)
db.init_app(app)
CORS(app)

# Decorator for routes requiring token authentication ----New----
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            return jsonify({"message": "Token is missing!"}), 403
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(id=data['id']).first()
        except:
            return jsonify({"message": "Token is invalid!"}), 403
        return f(current_user, *args, **kwargs)
    return decorated

# Error handling
@app.errorhandler(APIException)
def handle_invalid_usage(error):
    return jsonify(error.to_dict()), error.status_code

# Generate sitemap
@app.route('/')
def sitemap():
    return generate_sitemap(app)

# User registration
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(username=data['username'], email=data['email'], full_name=data['full_name'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "Registered successfully!"}), 201

# User login with jwt -- Missing explanation from lukasz
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if user and check_password_hash(user.password, data['password']):
        token = jwt.encode({'id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)}, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({'token': token})
    return jsonify({"message": "Invalid credentials!"}), 401

# User profile
@app.route('/profile')
@token_required
def profile(current_user):
    sponsored_animals = [sponsorship.animal.serialize() for sponsorship in current_user.sponsorships]
    adopted_animals = [adoption.animal.serialize() for adoption in current_user.adoptions]
    return jsonify({
        "user": current_user.serialize(),
        "sponsored_animals": sponsored_animals,
        "adopted_animals": adopted_animals
    })

# Animal adoption
@app.route('/adopt', methods=['POST'])
@token_required
def adopt(current_user):
    data = request.get_json()
    animal = Animal.query.get(data['animal_id'])
    if animal:
        new_adoption = Adoption(user_id=current_user.id, animal_id=animal.id)
        db.session.add(new_adoption)
        db.session.commit()
        return jsonify({"message": "Adoption application submitted!"}), 200
    return jsonify({"message": "Animal not found!"}), 404

# Animal sponsorship
@app.route('/sponsor', methods=['POST'])
@token_required
def sponsor(current_user):
    data = request.get_json()
    animal = Animal.query.get(data['animal_id'])
    if animal:
        new_sponsorship = Sponsorship(user_id=current_user.id, animal_id=animal.id, sponsorship_amount=data['amount'])
        current_user.current_spending = str(float(current_user.current_spending) + float(data['amount']))
        current_user.total_spent = str(float(current_user.total_spent) + float(data['amount']))
        db.session.add(new_sponsorship)
        db.session.commit()
        return jsonify({"message": "Sponsorship successful!"}), 200
    return jsonify({"message": "Animal not found!"}), 404

# List animals by category
@app.route('/categories', methods=['POST'])
def categories():
    data = request.get_json()
    animals = Animal.query.filter_by(species=data['species'], gender=data['gender']).all()
    return jsonify([animal.serialize() for animal in animals])

# Payment (Fictitious process)
@app.route('/payment', methods=['POST'])
@token_required
def payment(current_user):
    data = request.get_json()
    # Logic to process payment would go here
    return jsonify({"message": "Payment successful!"}), 200

# Administration (Add an animal)
@app.route('/admin', methods=['POST'])
@token_required
def admin(current_user):
    if not current_user.is_admin:
        return jsonify({"message": "Access denied!"}), 403
    data = request.get_json()
    new_animal = Animal(
        name=data['name'],
        species=data['species'],
        gender=data['gender'],
        description=data['description'],
        image_file=data.get('image_file', 'default.jpg')
    )
    db.session.add(new_animal)
    db.session.commit()
    return jsonify({"message": "Animal added successfully!"}), 201

# Animal details
@app.route('/animal/<int:animal_id>', methods=['GET'])
def animal_detail(animal_id):
    animal = Animal.query.get_or_404(animal_id)
    return jsonify(animal.serialize())

# List all animals
@app.route('/api/animals', methods=['GET'])
def get_animals():
    animals = Animal.query.all()
    return jsonify([animal.serialize() for animal in animals])

# Get a specific animal
@app.route('/api/animal/<int:animal_id>', methods=['GET'])
def get_animal(animal_id):
    animal = Animal.query.get_or_404(animal_id)
    return jsonify(animal.serialize())

# Add an animal
@app.route('/api/animal', methods=['POST'])
@token_required
def add_animal(current_user):
    if not current_user.is_admin:
        return jsonify({"message": "Access denied!"}), 403
    data = request.get_json()
    new_animal = Animal(
        name=data['name'],
        species=data['species'],
        gender=data['gender'],
        description=data['description'],
        image_file=data.get('image_file', 'default.jpg')
    )
    db.session.add(new_animal)
    db.session.commit()
    return jsonify({"message": "Animal added successfully!"}), 201

# Update a specific animal
@app.route('/api/animal/<int:animal_id>', methods=['PUT'])
@token_required
def update_animal(current_user, animal_id):
    if not current_user.is_admin:
        return jsonify({"message": "Access denied!"}), 403
    data = request.get_json()
    animal = Animal.query.get_or_404(animal_id)
    animal.name = data['name']
    animal.species = data['species']
    animal.gender = data['gender']
    animal.description = data['description']
    animal.image_file = data.get('image_file', 'default.jpg')
    db.session.commit()
    return jsonify({"message": "Animal updated successfully!"})

# Delete a specific animal
@app.route('/api/animal/<int:animal_id>', methods=['DELETE'])
@token_required
def delete_animal(current_user, animal_id):
    if not current_user.is_admin:
        return jsonify({"message": "Access denied!"}), 403
    animal = Animal.query.get_or_404(animal_id)
    db.session.delete(animal)
    db.session.commit()
    return jsonify({"message": "Animal deleted successfully!"})

if __name__ == '__main__':
    PORT = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=PORT, debug=False)
