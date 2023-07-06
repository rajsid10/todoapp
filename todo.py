from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your-secret-key'  # Change this to a secure secret key
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

    def __init__(self, username, password):
        self.username = username
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)


class TodoItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('todo_items', lazy=True))

    def __init__(self, title, user_id):
        self.title = title
        self.user_id = user_id


@app.route('/api/register', methods=['POST'])
def register():
    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        return jsonify({'message': 'Missing username or password'}), 400

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'message': 'Username already exists'}), 400

    new_user = User(username=username, password=password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201


@app.route('/api/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        return jsonify({'message': 'Missing username or password'}), 400

    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({'message': 'Invalid username or password'}), 401

    access_token = create_access_token(identity=user.id)
    return jsonify({'access_token': access_token}), 200


@app.route('/api/todo', methods=['GET'])
@jwt_required()
def get_todo_items():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    todo_items = [item.title for item in user.todo_items]
    return jsonify({'todo_items': todo_items}), 200


@app.route('/api/todo', methods=['POST'])
@jwt_required()
def create_todo_item():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    title = request.json.get('title')

    if not title:
        return jsonify({'message': 'Missing title'}), 400

    new_todo_item = TodoItem(title=title, user_id=user.id)
    db.session.add(new_todo_item)
    db.session.commit()

    return jsonify({'message': 'Todo item created successfully'}), 201


@app.route('/api/todo/<int:item_id>', methods=['PUT'])
@jwt_required()
def update_todo_item(item_id):
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    todo_item = TodoItem.query.filter_by(id=item_id, user_id=user.id).first()

    if not todo_item:
        return jsonify({'message': 'Todo item not found'}), 404

    new_title = request.json.get('title')

    if not new_title:
        return jsonify({'message': 'Missing title'}), 400

    todo_item.title = new_title
    db.session.commit()

    return jsonify({'message': 'Todo item updated successfully'}), 200


@app.route('/api/todo/<int:item_id>', methods=['DELETE'])
@jwt_required()
def delete_todo_item(item_id):
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    todo_item = TodoItem.query.filter_by(id=item_id, user_id=user.id).first()

    if not todo_item:
        return jsonify({'message': 'Todo item not found'}), 404

    db.session.delete(todo_item)
    db.session.commit()

    return jsonify({'message': 'Todo item deleted successfully'}), 200


if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
