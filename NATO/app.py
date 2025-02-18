from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime
import os


# Initialize app
app = Flask(__name__)
CORS(app)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://knut_y9i6_user:0IujIHlJIkOznIHpmb1r5sxWcbvycYt0@dpg-cuq3ua3tq21c73a1tg8g-a.oregon-postgres.render.com/knut_y9i6'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-secret-key')

# Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    tsc_number = db.Column(db.Integer, unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(10), default='user', nullable=False)  # 'user' or 'admin'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    records = db.relationship('FinancialRecord', backref='user', lazy=True)
class FinancialRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    month = db.Column(db.String(20), nullable=False)
    year = db.Column(db.Integer, nullable=False)
    paid_in = db.Column(db.Float, default=0.0)
    balance = db.Column(db.Float, default=0.0)
    loaned = db.Column(db.Float, default=0.0)
    repaid = db.Column(db.Float, default=0.0)
    shares = db.Column(db.Float, default=0.0)
    interest = db.Column(db.Float, default=0.0)
    category = db.Column(db.String(50), nullable=False) #added a column for category which i will use to select the category of the financial record
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    


# Routes

# User registration
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    if not all(key in data for key in ['name', 'email', 'tsc_number', 'password']):
        return jsonify({'message': 'Missing required fields'}), 400
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Email already exists'}), 400
    if User.query.filter_by(tsc_number=data['tsc_number']).first():
        return jsonify({'message': 'TSC Number already exists'}), 400
    
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    
    new_user = User(
        name=data['name'],
        email=data['email'],
        tsc_number=data['tsc_number'],
        password=hashed_password,
        role=data.get('role', 'user')
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully!'}), 201

# User login
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email'], tsc_number=data['tsc_number']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        token = create_access_token(identity={'id': user.id, 'role': user.role})
        return jsonify({'token': token, 'role': user.role, 'tsc_number': user.tsc_number}), 200
    return jsonify({'message': 'Invalid credentials'}), 401

# Get financial records (user)
# Get all financial records (Admin) or user-specific records
@app.route('/api/records', methods=['GET'])
@jwt_required()
def get_records():
    current_user = get_jwt_identity()
    user_id = current_user['id']
    role = current_user['role']
    
    category = request.args.get('category')
    
    if role == 'admin':  # Admin fetches all records
        query = FinancialRecord.query.join(User).add_columns(
            FinancialRecord.id, FinancialRecord.user_id, FinancialRecord.month,
            FinancialRecord.year, FinancialRecord.paid_in, FinancialRecord.balance,
            FinancialRecord.loaned, FinancialRecord.repaid, FinancialRecord.shares,
            FinancialRecord.interest, FinancialRecord.category, User.tsc_number
        )
    else:  # Normal user fetches only their records
        query = FinancialRecord.query.join(User).add_columns(
            FinancialRecord.id, FinancialRecord.user_id, FinancialRecord.month,
            FinancialRecord.year, FinancialRecord.paid_in, FinancialRecord.balance,
            FinancialRecord.loaned, FinancialRecord.repaid, FinancialRecord.shares,
            FinancialRecord.interest, FinancialRecord.category, User.tsc_number
        ).filter(FinancialRecord.user_id == user_id)

    if category:
        query = query.filter(FinancialRecord.category == category)

    records = query.all()

    return jsonify([{
        'id': record.id,
        'user_id': record.user_id,
        'tsc_number': record.tsc_number,  # Include TSC number
        'month': record.month,
        'year': record.year,
        'paid_in': record.paid_in,
        'balance': record.balance,
        'loaned': record.loaned,
        'repaid': record.repaid,
        'shares': record.shares,
        'interest': record.interest,
        'category': record.category,
    } for record in records])



# Add financial record
@app.route('/api/records', methods=['POST'])
@jwt_required()
def add_record():
    current_user = get_jwt_identity()
    user_id = current_user['id']
    data = request.get_json()
    # Validate category
    valid_category = ['Burial and Development Fund', 'Education Fund']
    if 'category' not in data or data['category'] not in valid_category:
        return jsonify({'message':'Invalid category. Choose either "Burial and Development Fund" or "Education Fund"' })
    
    new_record = FinancialRecord(
        user_id=user_id,
        month=data['month'],
        year=data['year'],
        paid_in=data['paid_in'],
        balance=data['balance'],
        loaned=data['loaned'],
        repaid=data['repaid'],
        shares=data['shares'],
        interest=data['interest'],
        category=data['category']  #ive added the function to assign category
    )
    db.session.add(new_record)
    db.session.commit()
    return jsonify({'message': 'Record added successfully!'}), 201

# fetch user details
@app.route('/api/user/details', methods=['GET'])
@jwt_required()
def get_user_details():
    try:
        current_user = get_jwt_identity()
        user_id = current_user['id']
        
        # fetch user details from the database
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'message': 'user not found'}), 404
        
        # Return user details if found
        return jsonify({
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'role': user.role,
            'created_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }), 200
    except Exception as e:
        return jsonify({'message': 'An error occurred', 'error': str(e)}), 500
        
# Admin or User: Get graph data (Monthly summary or financial overview)
@app.route('/api/graph-data', methods=['GET'])
@jwt_required()
def get_graph_data():
    try:
        current_user = get_jwt_identity()
        user_id = current_user['id']
        
        # Retrieve the financial records (monthly data)
        records = FinancialRecord.query.filter_by(user_id=user_id).all()
        
        # Prepare the data for graph (e.g., month-wise financial summary)
        labels = []
        values = []
        
        for record in records:
            month_year = f"{record.month} {record.year}"
            if month_year not in labels:
                labels.append(month_year)
                values.append(record.paid_in)  # You can also choose another attribute for visualization
        
        # Return data in the format expected by your frontend (e.g., chart.js)
        return jsonify({
            'labels': labels,
            'values': values,
        }), 200

    except Exception as e:
        return jsonify({'message': 'An error occurred while fetching graph data', 'error': str(e)}), 500

# Delete financial record
@app.route('/api/records/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_record(id):
    current_user = get_jwt_identity()
    record = FinancialRecord.query.filter_by(id=id, user_id=current_user['id']).first()
    if record:
        db.session.delete(record)
        db.session.commit()
        return jsonify({'message': 'Record deleted successfully!'}), 200
    return jsonify({'message': 'Record not found'}), 404

# Admin: Get all users
@app.route('/api/admin/users', methods=['GET'])
@jwt_required()
def get_all_users():
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        return jsonify({'message': 'Access denied'}), 403
    users = User.query.all()
    return jsonify([{
        'id': user.id,
        'name': user.name,
        'email': user.email,
        'tsc_number': user.tsc_number, 
        'role': user.role
    } for user in users])


# Admin: Add financial record for any user
@app.route('/api/admin/records', methods=['POST'])
@jwt_required()
def admin_add_record():
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        return jsonify({'message': 'Access denied'}), 403
    data = request.get_json()
    # validate category 
    valid_category = ['Burial and Development Fund', 'Education Fund']
    if 'category' not in data or data['category'] not in valid_category:
        return jsonify({'message':'Invalid category. Choose either "Burial and Development Fund" or "Education Fund"' })
    
    new_record = FinancialRecord(
        user_id=data['user_id'],
        month=data['month'],
        year=data['year'],
        paid_in=data['paid_in'],
        balance=data['balance'],
        loaned=data['loaned'],
        repaid=data['repaid'],
        shares=data['shares'],
        interest=data['interest'],
        category = data['category']
    )
    db.session.add(new_record)
    db.session.commit()
    return jsonify({'message': 'Record added successfully!'}), 201

# Admin: Get all financial records
@app.route('/api/admin/records', methods=['GET'])
@jwt_required()
def admin_get_records():
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        return jsonify({'message': 'Access denied'}), 403
    
    category = request.args.get('category')  # Optional filter
    query = FinancialRecord.query

    if category:
        query = query.filter_by(category=category)  # Filter by category if provided

    records = query.all()
    records = FinancialRecord.query.all()
    return jsonify([{
        'id': record.id,
        'user_id': record.user_id,
        'month': record.month,
        'year': record.year,
        'paid_in': record.paid_in,
        'balance': record.balance,
        'loaned': record.loaned,
        'repaid': record.repaid,
        'shares': record.shares,
        'interest': record.interest,
        'category': record.category
    } for record in records]), 200

# Admin: Update a financial record
@app.route('/api/admin/records/<int:id>', methods=['PUT'])
@jwt_required()
def admin_update_record(id):
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        return jsonify({'message': 'Access denied'}), 403

    record = FinancialRecord.query.get(id)
    if not record:
        return jsonify({'message': 'Record not found'}), 404

    data = request.get_json()
    record.month = data.get('month', record.month)
    record.year = data.get('year', record.year)
    record.paid_in = data.get('paid_in', record.paid_in)
    record.balance = data.get('balance', record.balance)
    record.loaned = data.get('loaned', record.loaned)
    record.repaid = data.get('repaid', record.repaid)
    record.shares = data.get('shares', record.shares)
    record.interest = data.get('interest', record.interest)

    db.session.commit()
    return jsonify({'message': 'Record updated successfully!'}), 200

# Admin: Delete a financial record
@app.route('/api/admin/records/<int:id>', methods=['DELETE'])
@jwt_required()
def admin_delete_record(id):
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        return jsonify({'message': 'Access denied'}), 403

    record = FinancialRecord.query.get(id)
    if not record:
        return jsonify({'message': 'Record not found'}), 404

    db.session.delete(record)
    db.session.commit()
    return jsonify({'message': 'Record deleted successfully!'}), 200

# Run the app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)