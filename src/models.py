from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

# Model for Adoptions
class Adoption(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    animal_id = db.Column(db.Integer, db.ForeignKey('animal.id'), nullable=False)
    adoption_date = db.Column(db.DateTime, default=datetime.utcnow)
    adoption_status = db.Column(db.String(50), default='Pending')
    form_data = db.Column(db.Text)

    user = db.relationship('User', back_populates='adoptions')
    animal = db.relationship('Animal', back_populates='adoptions')

    __table_args__ = (db.UniqueConstraint('user_id', 'animal_id', name='uq_user_animal_adoption'),)

    def __repr__(self):
        return f'<Adoption User {self.user_id} adopts Animal {self.animal_id}>'

# Model for Sponsorships
class Sponsorship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    animal_id = db.Column(db.Integer, db.ForeignKey('animal.id'), nullable=False)
    sponsorship_amount = db.Column(db.Float, default=0.0)
    sponsorship_date = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', back_populates='sponsorships')
    animal = db.relationship('Animal', back_populates='sponsorships')

    __table_args__ = (db.UniqueConstraint('user_id', 'animal_id', name='uq_user_animal_sponsorship'),)

    def __repr__(self):
        return f'<Sponsorship User {self.user_id} sponsors Animal {self.animal_id} with {self.sponsorship_amount}>'

# Model for Users
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.String(255))
    is_admin = db.Column(db.Boolean, default=False)
    current_spending = db.Column(db.Float, default=0.0)
    total_spent = db.Column(db.Float, default=0.0)

    adoptions = db.relationship('Adoption', back_populates='user')
    sponsorships = db.relationship('Sponsorship', back_populates='user')

    def __repr__(self):
        return f'<User {self.username}>'

# Model for Animals
class Animal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    species = db.Column(db.String(255), nullable=False)
    gender = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image_file = db.Column(db.String(255), default='default.jpg')
    sponsor_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    adoptions = db.relationship('Adoption', back_populates='animal')
    sponsorships = db.relationship('Sponsorship', back_populates='animal')

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
