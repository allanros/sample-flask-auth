from flask import Flask, jsonify, request
from models.user import User
from database import db
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
import bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mysecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:admin123@127.0.0.1:3306/flask-crud'

login_manager = LoginManager()
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, user_id)

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if username and password:
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.checkpw(str.encode(password), str.encode(user.password)):
            login_user(user)
            print(current_user.is_authenticated)
            return jsonify({'message': 'Logged in successfully'})
    
    return jsonify({'message': 'Invalid credentials'}), 400 

@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully'})

@app.route('/user', methods=['POST'])
def create_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if username and password:
        if User.query.filter_by(username=username).first() is None:
            hashed_password = bcrypt.hashpw(str.encode(password), bcrypt.gensalt())
            user = User(username=username, password=hashed_password, role='user')
            db.session.add(user)
            db.session.commit()
            return jsonify({'message': 'User created successfully'}), 201
        else:
            return jsonify({'message': 'User already exists'}), 400
    
    return jsonify({'message': 'Invalid data'}), 400

@app.route('/user/<int:id_user>', methods=['GET'])
@login_required
def read_user(id_user):
    user = db.session.get(User, id_user)
    if user:
        return jsonify({'username': user.username, 'role': user.role})
    return jsonify({'message': 'User not found'}), 404

@app.route('/user/<int:id_user>', methods=['PUT'])
@login_required
def update_user(id_user):
    user = User.query.get(id_user)
    data = request.get_json()
    password = data.get('password')

    if user and password:
        if id_user != current_user.id and current_user.role != 'admin':
            return jsonify({'message': 'Update not allowed'}), 403
        user.password = password
        db.session.commit()

        return jsonify({'message': f'User {user.username} updated successfully'})
    
    return jsonify({'message': 'User not found'}), 404

@app.route('/user/<int:id_user>', methods=['DELETE'])
@login_required
def delete_user(id_user):
    user = User.query.get(id_user)

    if user == current_user or current_user.role != 'admin':
        return jsonify({'message': 'Deletion not allowed'}), 403

    if user:
        db.session.delete(user)
        db.session.commit()

        return jsonify({'message': f'User {user.username} deleted successfully'})
    return jsonify({'message': 'User not found'}), 404


if __name__ == '__main__':
    app.run(debug=True)