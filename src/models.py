from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

""""Ask if i do have the need to use pdf as primary key"""
# Association table for adoption 
adoptions = db.Table('adoptions',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('animal_id', db.Integer, db.ForeignKey('animal.id'), primary_key=True)
)

# Association table for sponsorship
sponsorships = db.Table('sponsorships',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('animal_id', db.Integer, db.ForeignKey('animal.id'), primary_key=True)
)

class User(db.Model):  """Might Add something later""" 
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password= db.Column(db.String(128), nullable=False)
    is_active = db.Column(db.Boolean(), default=True, nullable=False)
    is_admin = db.Column(db.Boolean(), default=False, nullable=False)
    sponsored_animals = db.relationship('Animal', secondary=sponsorships, lazy='subquery', backref=db.backref('sponsors', lazy=True))
    phone_number = db.Column(db.String(20), nullable=True)
    current_spending = db.Column(db.Float, default=0.0, nullable=False)
    total_spent = db.Column(db.Float, default=0.0, nullable=False)
    adopted_animals = db.relationship('Animal', secondary=adoptions, lazy='subquery', backref=db.backref('applicants', lazy=True))

    def __repr__(self):
        return f'<User {self.username}>'

    def set_password(self, password):
        self.password = generate_password(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

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
    name = db.Column(db.String(100), nullable=False)
    species = db.Column(db.String(100), nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    sponsor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

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
            "applicants": [user.id for user in self.applicants],
            "sponsors": [user.id for user in self.sponsors]
        }

