from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

# Adoption model with form data and unique constraint
class Adoption(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    animal_id = db.Column(db.Integer, db.ForeignKey('animal.id'), nullable=False)
    adoption_date = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    adoption_status = db.Column(db.String(50), nullable=False, default='Pending')
    form_data = db.Column(db.Text, nullable=True)

    user = db.relationship('User', back_populates='adoptions')
    animal = db.relationship('Animal', back_populates='adoptions')

    __table_args__ = (db.UniqueConstraint('user_id', 'animal_id', name='uq_user_animal_adoption'),)

    def __repr__(self):
        return f'<Adoption User {self.user_id} adopts Animal {self.animal_id}>'

# Sponsorship model with sponsorship amount
class Sponsorship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    animal_id = db.Column(db.Integer, db.ForeignKey('animal.id'), nullable=False)
    sponsorship_amount = db.Column(db.Float, nullable=False, default=0.0)
    sponsorship_date = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())

    user = db.relationship('User', back_populates='sponsorships')
    animal = db.relationship('Animal', back_populates='sponsorships')

    __table_args__ = (db.UniqueConstraint('user_id', 'animal_id', name='uq_user_animal_sponsorship'),)

    def __repr__(self):
        return f'<Sponsorship User {self.user_id} sponsors Animal {self.animal_id} with {self.sponsorship_amount}>'

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.String(255), nullable=True)
    is_admin = db.Column(db.Boolean(), default=False, nullable=False)
    current_spending = db.Column(db.Float, default=0.0, nullable=False)
    total_spent = db.Column(db.Float, default=0.0, nullable=False)
    adopted_animals = db.relationship('Adoption', back_populates='user')  # Refers to Adoption model
    sponsorships = db.relationship('Sponsorship', back_populates='user')  # Refers to Sponsorship model

    def __repr__(self):
        return f'<User {self.username}>'

    def set_password(self, password):
        self.password = generate_password(password)

    def check_password(self, password):
        return check_password(self.password, password)

    def serialize(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "phone_number": self.phone_number,
            "current_spending": self.current_spending,
            "total_spent": self.total_spent,
            # do not serialize the password, it's a security breach
        }

class Animal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    species = db.Column(db.String(255), nullable=False)
    gender = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image_file = db.Column(db.String(255), nullable=False, default='default.jpg')
    sponsor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    adoptions = db.relationship('Adoption', back_populates='animal')  # Refers to Adoption model
    sponsorships = db.relationship('Sponsorship', back_populates='animal')  # Refers to Sponsorship model

    def __repr__(self):
        return f'<Animal {self.name}>'

    def serialize(self):
        return {
            "id": self.id,
            "name": self.name,
            "species": self.species,
            "gender": self.gender,
            "description": self.description,
            "image_file": self.image_file,
            "sponsor_id": self.sponsor_id,
            "applicants": [adoption.user_id for adoption in self.adoptions],
            "sponsors": [sponsorship.user_id for sponsorship in self.sponsorships]
        }
