#Maybe Delete this init_db
from app import app, db

with app.app_context():
    db.create_all()
    print("Database created successfully!")
