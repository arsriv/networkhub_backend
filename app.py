import os
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, verify_jwt_in_request, get_jwt_identity
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random
import string
import os
from datetime import datetime, timedelta
import base64
from bson import ObjectId
import json

load_dotenv()

app = Flask(__name__)

# Configuration from environment variables
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-secret-key-change-in-production')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

jwt = JWTManager(app)
CORS(app,
     supports_credentials=True,
     origins=["https://networkhub-frontend.vercel.app"],
     methods=["GET", "POST", "OPTIONS"],
     allow_headers=["Content-Type", "Authorization"])

# MongoDB connection
MONGODB_URI = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/')
client = MongoClient(MONGODB_URI)
db = client['networkhub']
users = db.users
posts = db.posts
follows = db.follows
otps = db.otps


# Email configuration
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_ADDRESS = os.getenv('EMAIL_ADDRESS')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')
def send_otp_email(email, otp):
    """Send OTP via email"""
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = email
        msg['Subject'] = "NetworkHub - Email Verification"
        
        body = f"""
        Welcome to NetworkHub!
        
        Your verification code is: {otp}
        
        This code will expire in 10 minutes.
        
        Best regards,
        NetworkHub Team
        """
        
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        text = msg.as_string()
        server.sendmail(EMAIL_ADDRESS, email, text)
        server.quit()
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

def generate_otp():
    """Generate 6-digit OTP"""
    return ''.join(random.choices(string.digits, k=6))

def allowed_file(filename):
    """Check if file extension is allowed"""
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

class JSONEncoder(json.JSONEncoder):
    """Custom JSON encoder for MongoDB ObjectId"""
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return json.JSONEncoder.default(self, o)

app.json_encoder = JSONEncoder

@app.route('/api/signup', methods=['POST'])
def signup():
    """User signup with email OTP verification"""
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['email', 'password', 'firstName', 'lastName']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'{field} is required'}), 400
    
    email = data['email'].lower()
    
    # Check if user already exists
    if users.find_one({'email': email}):
        return jsonify({'error': 'User already exists'}), 400
    
    # Generate and store OTP
    otp = generate_otp()
    otp_data = {
        'email': email,
        'otp': otp,
        'user_data': {
            'email': email,
            'password': generate_password_hash(data['password']),
            'firstName': data['firstName'],
            'lastName': data['lastName'],
            'bio': data.get('bio', ''),
            'location': data.get('location', ''),
            'profileImage': '',
            'followers': [],
            'following': [],
            'createdAt': datetime.utcnow()
        },
        'createdAt': datetime.utcnow(),
        'expiresAt': datetime.utcnow() + timedelta(minutes=10)
    }
    
    otps.insert_one(otp_data)
    
    # Send OTP email
    if send_otp_email(email, otp):
        return jsonify({'message': 'OTP sent to email', 'email': email}), 200
    else:
        return jsonify({'error': 'Failed to send OTP email'}), 500

@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    """Verify OTP and create user account"""
    data = request.get_json()
    
    if 'email' not in data or 'otp' not in data:
        return jsonify({'error': 'Email and OTP are required'}), 400
    
    email = data['email'].lower()
    otp = data['otp']
    
    # Find OTP record
    otp_record = otps.find_one({
        'email': email,
        'otp': otp,
        'expiresAt': {'$gt': datetime.utcnow()}
    })
    
    if not otp_record:
        return jsonify({'error': 'Invalid or expired OTP'}), 400
    
    # Create user account
    user_id = users.insert_one(otp_record['user_data']).inserted_id
    
    # Clean up OTP
    otps.delete_many({'email': email})
    
    # Generate access token
    access_token = create_access_token(identity=str(user_id))
    
    return jsonify({
        'message': 'Account created successfully',
        'access_token': access_token,
        'user': {
            'id': str(user_id),
            'email': email,
            'firstName': otp_record['user_data']['firstName'],
            'lastName': otp_record['user_data']['lastName']
        }
    }), 201

@app.route('/api/login', methods=['POST','OPTIONS'])
def login():
    if request.method == "OPTIONS":
        return '', 200
                      
    data = request.get_json()
                       
    if 'email' not in data or 'password' not in data:
        return jsonify({'error': 'Email and password are required'}), 400
    
    email = data['email'].lower()
    user = users.find_one({'email': email})
    
    if not user or not check_password_hash(user['password'], data['password']):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    access_token = create_access_token(identity=str(user['_id']))
    
    return jsonify({
        'access_token': access_token,
        'user': {
            'id': str(user['_id']),
            'email': user['email'],
            'firstName': user['firstName'],
            'lastName': user['lastName'],
            'bio': user.get('bio', ''),
            'location': user.get('location', ''),
            'profileImage': user.get('profileImage', '')
        }
    }), 200

@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    """Send OTP for password reset"""
    data = request.get_json()
    
    if 'email' not in data:
        return jsonify({'error': 'Email is required'}), 400
    
    email = data['email'].lower()
    user = users.find_one({'email': email})
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Generate and store OTP
    otp = generate_otp()
    otp_data = {
        'email': email,
        'otp': otp,
        'type': 'password_reset',
        'createdAt': datetime.utcnow(),
        'expiresAt': datetime.utcnow() + timedelta(minutes=10)
    }
    
    otps.insert_one(otp_data)
    
    # Send OTP email
    if send_otp_email(email, otp):
        return jsonify({'message': 'OTP sent to email', 'email': email}), 200
    else:
        return jsonify({'error': 'Failed to send OTP email'}), 500

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    """Reset password with OTP verification"""
    data = request.get_json()
    
    required_fields = ['email', 'otp', 'newPassword']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'{field} is required'}), 400
    
    email = data['email'].lower()
    otp = data['otp']
    new_password = data['newPassword']
    
    # Verify OTP
    otp_record = otps.find_one({
        'email': email,
        'otp': otp,
        'type': 'password_reset',
        'expiresAt': {'$gt': datetime.utcnow()}
    })
    
    if not otp_record:
        return jsonify({'error': 'Invalid or expired OTP'}), 400
    
    # Update password
    users.update_one(
        {'email': email},
        {'$set': {'password': generate_password_hash(new_password)}}
    )
    
    # Clean up OTP
    otps.delete_many({'email': email, 'type': 'password_reset'})
    
    return jsonify({'message': 'Password reset successfully'}), 200

@app.route('/api/profile', methods=['GET'])
def get_profile():
    """Get user profile"""
    try:
        verify_jwt_in_request()
        user_id = get_jwt_identity()
        
        user = users.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Get follower and following counts
        follower_count = len(user.get('followers', []))
        following_count = len(user.get('following', []))
        
        return jsonify({
            'id': str(user['_id']),
            'email': user['email'],
            'firstName': user['firstName'],
            'lastName': user['lastName'],
            'bio': user.get('bio', ''),
            'location': user.get('location', ''),
            'profileImage': user.get('profileImage', ''),
            'followerCount': follower_count,
            'followingCount': following_count
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Invalid token'}), 401

@app.route('/api/profile', methods=['PUT'])
def update_profile():
    """Update user profile"""
    try:
        verify_jwt_in_request()
        user_id = get_jwt_identity()
        
        data = request.get_json()
        update_data = {}
        
        # Allow updating specific fields
        allowed_fields = ['firstName', 'lastName', 'bio', 'location']
        for field in allowed_fields:
            if field in data:
                update_data[field] = data[field]
        
        if update_data:
            users.update_one(
                {'_id': ObjectId(user_id)},
                {'$set': update_data}
            )
        
        return jsonify({'message': 'Profile updated successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': 'Invalid token'}), 401

@app.route('/api/upload-profile-image', methods=['POST'])
def upload_profile_image():
    """Upload profile image"""
    try:
        verify_jwt_in_request()
        user_id = get_jwt_identity()
        
        if 'image' not in request.files:
            return jsonify({'error': 'No image file'}), 400
        
        file = request.files['image']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if file and allowed_file(file.filename):
            # Convert image to base64
            image_data = base64.b64encode(file.read()).decode('utf-8')
            image_url = f"data:image/{file.filename.rsplit('.', 1)[1].lower()};base64,{image_data}"
            
            # Update user profile
            users.update_one(
                {'_id': ObjectId(user_id)},
                {'$set': {'profileImage': image_url}}
            )
            
            return jsonify({'profileImage': image_url}), 200
        
        return jsonify({'error': 'Invalid file type'}), 400
        
    except Exception as e:
        return jsonify({'error': 'Invalid token'}), 401

@app.route('/api/posts', methods=['POST'])
def create_post():
    """Create a new post"""
    try:
        verify_jwt_in_request()
        user_id = get_jwt_identity()
        
        data = request.get_json()
        
        if 'content' not in data:
            return jsonify({'error': 'Content is required'}), 400
        
        # Get user info
        user = users.find_one({'_id': ObjectId(user_id)})
        
        post_data = {
            'userId': ObjectId(user_id),
            'content': data['content'],
            'image': data.get('image', ''),
            'author': {
                'firstName': user['firstName'],
                'lastName': user['lastName'],
                'profileImage': user.get('profileImage', '')
            },
            'likes': [],
            'comments': [],
            'createdAt': datetime.utcnow()
        }
        
        post_id = posts.insert_one(post_data).inserted_id
        
        return jsonify({
            'message': 'Post created successfully',
            'postId': str(post_id)
        }), 201
        
    except Exception as e:
        return jsonify({'error': 'Invalid token'}), 401

@app.route('/api/posts', methods=['GET'])
def get_posts():
    """Get all posts (feed)"""
    try:
        verify_jwt_in_request()
        user_id = get_jwt_identity()
        
        # Get posts from users that current user follows + own posts
        user = users.find_one({'_id': ObjectId(user_id)})
        following = user.get('following', [])
        following.append(ObjectId(user_id))  # Include own posts
        
        posts_data = list(posts.find(
            {'userId': {'$in': following}}
        ).sort('createdAt', -1))
        
        # Format posts for frontend
        formatted_posts = []
        for post in posts_data:
            formatted_posts.append({
                'id': str(post['_id']),
                'userId': str(post['userId']),
                'content': post['content'],
                'image': post.get('image', ''),
                'author': post['author'],
                'likes': len(post.get('likes', [])),
                'comments': len(post.get('comments', [])),
                'createdAt': post['createdAt'].isoformat(),
                'isLiked': ObjectId(user_id) in post.get('likes', [])
            })
        
        return jsonify(formatted_posts), 200
        
    except Exception as e:
        return jsonify({'error': 'Invalid token'}), 401

@app.route('/api/follow/<user_id>', methods=['POST'])
def follow_user(user_id):
    """Follow a user"""
    try:
        verify_jwt_in_request()
        current_user_id = get_jwt_identity()
        
        if current_user_id == user_id:
            return jsonify({'error': 'Cannot follow yourself'}), 400
        
        # Add to current user's following list
        users.update_one(
            {'_id': ObjectId(current_user_id)},
            {'$addToSet': {'following': ObjectId(user_id)}}
        )
        
        # Add to target user's followers list
        users.update_one(
            {'_id': ObjectId(user_id)},
            {'$addToSet': {'followers': ObjectId(current_user_id)}}
        )
        
        return jsonify({'message': 'User followed successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': 'Invalid token'}), 401

@app.route('/api/unfollow/<user_id>', methods=['POST'])
def unfollow_user(user_id):
    """Unfollow a user"""
    try:
        verify_jwt_in_request()
        current_user_id = get_jwt_identity()
        
        # Remove from current user's following list
        users.update_one(
            {'_id': ObjectId(current_user_id)},
            {'$pull': {'following': ObjectId(user_id)}}
        )
        
        # Remove from target user's followers list
        users.update_one(
            {'_id': ObjectId(user_id)},
            {'$pull': {'followers': ObjectId(current_user_id)}}
        )
        
        return jsonify({'message': 'User unfollowed successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': 'Invalid token'}), 401

@app.route('/api/users/search', methods=['GET'])
def search_users():
    """Search users by name"""
    try:
        verify_jwt_in_request()
        current_user_id = get_jwt_identity()
        
        query = request.args.get('q', '')
        if not query:
            return jsonify([]), 200
        
        # Search users by first name or last name
        search_results = list(users.find({
            '$and': [
                {'_id': {'$ne': ObjectId(current_user_id)}},
                {'$or': [
                    {'firstName': {'$regex': query, '$options': 'i'}},
                    {'lastName': {'$regex': query, '$options': 'i'}}
                ]}
            ]
        }).limit(10))
        
        # Get current user's following list
        current_user = users.find_one({'_id': ObjectId(current_user_id)})
        following = current_user.get('following', [])
        
        # Format results
        formatted_results = []
        for user in search_results:
            formatted_results.append({
                'id': str(user['_id']),
                'firstName': user['firstName'],
                'lastName': user['lastName'],
                'bio': user.get('bio', ''),
                'profileImage': user.get('profileImage', ''),
                'isFollowing': user['_id'] in following
            })
        
        return jsonify(formatted_results), 200
        
    except Exception as e:
        return jsonify({'error': 'Invalid token'}), 401

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
