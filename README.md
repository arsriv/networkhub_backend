# 🌐 NetworkHub

NetworkHub is a social media platform where users can sign up, log in, post images, send follow requests, and manage their profiles. It features email authentication, profile pictures, and a password reset system via OTP.

---


---

## 🔗 Live Demo

👉 [website](https://networkhub-frontend.vercel.app)  

## 👥 Demo User
 Email : demo@mail.com            Password : demopass123
Or you can create an account
---


---


## 🚀 Tech Stack

- **Frontend:** React (hosted on Vercel)
- **Backend:** Flask (hosted on Railway)
- **Database:** MongoDB Atlas
- **Email Service:** SMTP (for sending OTPs)

---

## 🛠️ Features

- User Signup & Login with email verification  
- Forgot Password (OTP-based reset)  
- Profile picture upload  
- Post image content  
- Send/accept follow requests  
- Responsive UI

---

## 📦 Setup Instructions

### 1. Clone the repositories:

```bash
# Frontend
git clone https://github.com/arsriv/networkhub-frontend.git

# Backend
git clone https://github.com/arsriv/networkhub-backend.git
```

### 2. Backend (Flask API)

- Install Python dependencies:

```bash
pip install -r requirements.txt
```

- Set environment variables:
  - `MONGO_URI`
  - `SECRET_KEY`
  - `MAIL_USERNAME`
  - `MAIL_PASSWORD`

- Run the Flask server:

```bash
python app.py
```

### 3. Frontend (React)

- Install packages:

```bash
npm install
```

- Set the API base URL in your environment (e.g. `.env`):

```env
REACT_APP_API_BASE=https://your-backend-url.railway.app
```

- Start development server:

```bash
npm start
```


## ✨ Extra Notes

- OTPs expire after 10 minutes
- Users can’t see private posts unless they follow the user
- Profile images and posts are handled with local uploads or external URLs
