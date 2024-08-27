from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

# Model for Adoptions
class Adoption(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    animal_id = db.Column(db.Integer, db.ForeignKey('animal.id'), nullable=False)
    adoption_date = db.Column(db.DateTime, default=datetime.now)
    adoption_status = db.Column(db.String(255), default='Pending')
    form_id = db.Column(db.Integer, db.ForeignKey('adoption_form.id'))  # Foreign Key to AdoptionForm

    # Relationship with User and Animal
    user = db.relationship('User', back_populates='adoptions')
    animal = db.relationship('Animal', back_populates='adoptions')
    form = db.relationship('AdoptionForm', back_populates='adoption')

    __table_args__ = (db.UniqueConstraint('user_id', 'animal_id', name='uq_user_animal_adoption'),)

    def __repr__(self):
        return f'<Adoption User {self.user_id} adopts Animal {self.animal_id}>'

    def serialize(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "animal_id": self.animal_id,
            "adoption_date": self.adoption_date.isoformat() if self.adoption_date else None,
            "adoption_status": self.adoption_status,
            "form": self.form.serialize() if self.form else None
        }

# Model for Adoption Forms
class AdoptionForm(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    animal_name = db.Column(db.String(255), nullable=False)
    animal_reference = db.Column(db.String(255), nullable=False)  #For animal chip or other later
    first_name = db.Column(db.String(255), nullable=False)
    last_name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.String(255), nullable=False)
    first_time_adopting = db.Column(db.String(255), nullable=False)
    already_have_pets = db.Column(db.String(255), nullable=True)  # Made nullable 
    current_pets_description = db.Column(db.Text, nullable=True)  # Made nullable 
    interest_reason = db.Column(db.Text, nullable=False)
    met_animal = db.Column(db.String(255), nullable=False)
    space_for_play = db.Column(db.String(255), nullable=False)
    able_to_front_vet_bills = db.Column(db.String(255), nullable=False)

    # Relationship with Adoption
    adoption = db.relationship('Adoption', back_populates='form', uselist=False)

    def __repr__(self):
        return f'<AdoptionForm {self.first_name} {self.last_name}>'

    def serialize(self):
        return {
            "id": self.id,
            "animal_name": self.animal_name,
            "animal_reference": self.animal_reference,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "email": self.email,
            "phone_number": self.phone_number,
            "first_time_adopting": self.first_time_adopting,
            "already_have_pets": self.already_have_pets,
            "current_pets_description": self.current_pets_description,
            "interest_reason": self.interest_reason,
            "met_animal": self.met_animal,
            "space_for_play": self.space_for_play,
            "able_to_front_vet_bills": self.able_to_front_vet_bills
        }

# Model for Sponsorships
#Could add type of contribution to organise later (Montly or one time)
class Sponsorship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    animal_id = db.Column(db.Integer, db.ForeignKey('animal.id'), nullable=False)
    sponsorship_amount = db.Column(db.String(255), default='0')
    sponsorship_date = db.Column(db.DateTime, default=datetime.now)

    # Relationship with User and Animal
    user = db.relationship('User', back_populates='sponsorships')
    animal = db.relationship('Animal', back_populates='sponsorships')

    # __table_args__ = (db.UniqueConstraint('user_id', 'animal_id', name='uq_user_animal_sponsorship'),) #i think this should be in adoption....

    def __repr__(self):
        return f'<Sponsorship User {self.user_id} sponsors Animal {self.animal_id} with {self.sponsorship_amount}>'

    def serialize(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "animal_id": self.animal_id,
            "sponsorship_amount": self.sponsorship_amount,
            "sponsorship_date": self.sponsorship_date.isoformat() if self.sponsorship_date else None
        }

# Model for Users
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=True) # Changed to True
    first_name = db.Column(db.String(255),nullable=False) #Added
    last_name = db.Column(db.String(255),nullable=False) #Added
    #full_name = db.Column(db.String(255), nullable=False) voided
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.String(255),unique=True,nullable=True) #Added unique and nullable
    is_admin = db.Column(db.Boolean, default=False)
    current_spending = db.Column(db.String(255), default='0')
    #total_spent = db.Column(db.String(255), default='0') voided calculated dynamically

    # Relationships with Adoption and Sponsorship
    adoptions = db.relationship('Adoption', back_populates='user')
    sponsorships = db.relationship('Sponsorship', back_populates='user')

    #This serves to calculate total amount for each user
    @property
    def total_spent(self):
        return sum(float(sponsorship.sponsorship_amount) for sponsorship in self.sponsorships)

    def __repr__(self):
        return f'<User {self.username}>'

    def serialize(self):
        return {
            #might want to add usarname later
            'id': self.id,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'email': self.email,
            'phone_number': self.phone_number,
            "is_admin": self.is_admin,
            "current_spending": self.current_spending,
            "total_spent": self.total_spent  #Calulated Dynamically
        }

#Model For Password Reset Token
class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(255), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)

    user = db.relationship('User')

    def __init__(self, user_id, token, expires_at):
        self.user_id = user_id
        self.token = token
        self.expires_at = expires_at

    def __repr__(self):
        return f'<PasswordResetToken {self.token} for user {self.user_id}>'


# Model for Animals
class Animal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    species = db.Column(db.String(255), nullable=False)
    gender = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    #sponsor_id = db.Column(db.Integer, db.ForeignKey('user.id')) #Remover evitar cirar novo registo para animal se ouver sponsor novo

    # New fields
    location = db.Column(db.String(255), nullable=True)
    life_stage = db.Column(db.String(255), nullable=True)
    weight = db.Column(db.String(255), nullable=True)
    breed = db.Column(db.String(255), nullable=True)
    known_illness = db.Column(db.String(255), nullable=True)  

    # Relationships with Adoption and Sponsorship and Images
    adoptions = db.relationship('Adoption', back_populates='animal')
    sponsorships = db.relationship('Sponsorship', back_populates='animal')
    images = db.relationship('AnimalImage', back_populates='animal')

    # Relationship with AnimalImage
    #(might want to implement to solve problem deleting pets and images cascade automatically) images = db.relationship('AnimalImage', backref='animal', cascade='all, delete-orphan')

    def __repr__(self):
        return f'<Animal {self.name}>'

    def serialize(self):
        return {
            "id": self.id,
            "name": self.name,
            "species": self.species,
            "gender": self.gender,
            "description": self.description,
            "location": self.location,
            "life_stage": self.life_stage,
            "weight": self.weight,
            "breed": self.breed,
            "known_illness": self.known_illness,
            "images": [image.serialize() for image in self.images]
        }

# Model for Animal Images
class AnimalImage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    animal_id = db.Column(db.Integer, db.ForeignKey('animal.id'), nullable=False)
    image_url = db.Column(db.String(255), nullable=False)

    # Relationship with Animal
    animal = db.relationship('Animal', back_populates='images')

    def __repr__(self):
        return f'<AnimalImage {self.image_url}>'

    def serialize(self):
        return {
            "id": self.id,
            "animal_id": self.animal_id,
            "image_url": self.image_url
        }
