from fastapi import FastAPI, APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import bcrypt
import jwt
from emergentintegrations.llm.chat import LlmChat, UserMessage
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from twilio.rest import Client

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

security = HTTPBearer()

# JWT Configuration
JWT_SECRET = os.getenv('JWT_SECRET')
JWT_ALGORITHM = 'HS256'

# Twilio Client (optional)
try:
    if os.getenv('TWILIO_ACCOUNT_SID') and os.getenv('TWILIO_AUTH_TOKEN'):
        twilio_client = Client(
            os.getenv('TWILIO_ACCOUNT_SID'),
            os.getenv('TWILIO_AUTH_TOKEN')
        )
    else:
        twilio_client = None
except Exception:
    twilio_client = None

# Models
class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    email: EmailStr
    role: str  # 'parent' or 'child'
    parent_id: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: str
    parent_email: Optional[str] = None

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class ChatScanRequest(BaseModel):
    message: str
    child_id: str

class ChatScanResult(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    child_id: str
    message: str
    risk_level: str
    analysis: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class ProfileDetectionRequest(BaseModel):
    profile_data: str
    child_id: str

class ProfileDetectionResult(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    child_id: str
    profile_data: str
    is_fake: bool
    confidence: str
    analysis: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class SOSAlert(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    child_id: str
    child_username: str
    location: Optional[str] = None
    message: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    notified: bool = False

class SOSRequest(BaseModel):
    child_id: str
    location: Optional[str] = None
    message: Optional[str] = None

class QuizRequest(BaseModel):
    topic: str
    child_id: str

class ScenarioRequest(BaseModel):
    scenario_type: str
    child_id: str

class ComplaintRequest(BaseModel):
    user_id: str
    complaint_type: str
    description: str
    evidence: Optional[str] = None

class Complaint(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    complaint_type: str
    description: str
    evidence: Optional[str] = None
    status: str = "submitted"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class BlockUserRequest(BaseModel):
    parent_id: str
    blocked_username: str
    reason: str

class BlockedUser(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    parent_id: str
    child_id: str
    blocked_username: str
    reason: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

# Helper Functions
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_token(user_id: str, role: str) -> str:
    payload = {
        'user_id': user_id,
        'role': role,
        'exp': datetime.now(timezone.utc) + timedelta(days=7)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_gemini_response(prompt: str, system_message: str) -> str:
    try:
        chat = LlmChat(
            api_key=os.getenv('EMERGENT_LLM_KEY'),
            session_id=str(uuid.uuid4()),
            system_message=system_message
        ).with_model("gemini", "gemini-2.5-pro")
        
        response = await chat.send_message(UserMessage(text=prompt))
        return response
    except Exception as e:
        logging.error(f"Gemini API error: {e}")
        raise HTTPException(status_code=500, detail="AI service error")

def send_email(to_email: str, subject: str, content: str):
    """Send email - mocked if API key not available"""
    try:
        if os.getenv('SENDGRID_API_KEY') and os.getenv('SENDGRID_API_KEY') != 'your_sendgrid_api_key':
            message = Mail(
                from_email=os.getenv('SENDER_EMAIL'),
                to_emails=to_email,
                subject=subject,
                html_content=content
            )
            sg = SendGridAPIClient(os.getenv('SENDGRID_API_KEY'))
            sg.send(message)
            logging.info(f"Email sent to {to_email}")
        else:
            # Mock email sending
            logging.info(f"[MOCKED] Email would be sent to {to_email} - Subject: {subject}")
    except Exception as e:
        logging.error(f"Email error: {e}")

def send_sms(to_phone: str, message: str):
    """Send SMS - mocked if credentials not available"""
    try:
        if twilio_client and os.getenv('TWILIO_PHONE_NUMBER') and os.getenv('TWILIO_PHONE_NUMBER') != '+1234567890':
            twilio_client.messages.create(
                body=message,
                from_=os.getenv('TWILIO_PHONE_NUMBER'),
                to=to_phone
            )
            logging.info(f"SMS sent to {to_phone}")
        else:
            # Mock SMS sending
            logging.info(f"[MOCKED] SMS would be sent to {to_phone} - Message: {message}")
    except Exception as e:
        logging.error(f"SMS error: {e}")

# Auth Routes
@api_router.post("/auth/register")
async def register(user_data: UserRegister):
    # Check if user exists
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # If child, find parent
    parent_id = None
    if user_data.role == "child" and user_data.parent_email:
        parent = await db.users.find_one({"email": user_data.parent_email, "role": "parent"})
        if not parent:
            raise HTTPException(status_code=400, detail="Parent not found")
        parent_id = parent['id']
    
    # Create user
    user = User(
        username=user_data.username,
        email=user_data.email,
        role=user_data.role,
        parent_id=parent_id
    )
    
    user_dict = user.model_dump()
    user_dict['password'] = hash_password(user_data.password)
    user_dict['created_at'] = user_dict['created_at'].isoformat()
    
    await db.users.insert_one(user_dict)
    
    token = create_token(user.id, user.role)
    return {"token": token, "user": user, "message": "Registration successful"}

@api_router.post("/auth/login")
async def login(credentials: UserLogin):
    user = await db.users.find_one({"email": credentials.email})
    if not user or not verify_password(credentials.password, user['password']):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_token(user['id'], user['role'])
    
    user_data = User(**{k: v for k, v in user.items() if k != 'password'})
    return {"token": token, "user": user_data}

# Child Dashboard Routes
@api_router.post("/chat/scan", response_model=ChatScanResult)
async def scan_chat(request: ChatScanRequest, current_user = Depends(get_current_user)):
    system_message = "You are a cyber safety expert analyzing messages for potential risks to children. Identify threats like cyberbullying, grooming, inappropriate content, or scams. Respond with risk level (low/medium/high) and brief analysis."
    
    prompt = f"Analyze this message for potential risks: '{request.message}'"
    
    response = await get_gemini_response(prompt, system_message)
    
    # Parse risk level from response
    risk_level = "low"
    if "high" in response.lower():
        risk_level = "high"
    elif "medium" in response.lower():
        risk_level = "medium"
    
    result = ChatScanResult(
        child_id=request.child_id,
        message=request.message,
        risk_level=risk_level,
        analysis=response
    )
    
    result_dict = result.model_dump()
    result_dict['timestamp'] = result_dict['timestamp'].isoformat()
    await db.chat_scans.insert_one(result_dict)
    
    return result

@api_router.post("/profile/detect", response_model=ProfileDetectionResult)
async def detect_fake_profile(request: ProfileDetectionRequest, current_user = Depends(get_current_user)):
    system_message = "You are an expert at detecting fake social media profiles. Analyze profile information for red flags like stolen photos, inconsistent information, suspicious behavior patterns, or bot-like activity. Provide confidence level (low/medium/high) and detailed analysis."
    
    prompt = f"Analyze this profile for authenticity: {request.profile_data}"
    
    response = await get_gemini_response(prompt, system_message)
    
    is_fake = "fake" in response.lower() or "suspicious" in response.lower()
    confidence = "low"
    if "high confidence" in response.lower():
        confidence = "high"
    elif "medium confidence" in response.lower():
        confidence = "medium"
    
    result = ProfileDetectionResult(
        child_id=request.child_id,
        profile_data=request.profile_data,
        is_fake=is_fake,
        confidence=confidence,
        analysis=response
    )
    
    result_dict = result.model_dump()
    result_dict['timestamp'] = result_dict['timestamp'].isoformat()
    await db.fake_profiles.insert_one(result_dict)
    
    return result

@api_router.post("/sos/trigger", response_model=SOSAlert)
async def trigger_sos(request: SOSRequest, current_user = Depends(get_current_user)):
    # Get child info
    child = await db.users.find_one({"id": request.child_id})
    if not child:
        raise HTTPException(status_code=404, detail="Child not found")
    
    alert = SOSAlert(
        child_id=request.child_id,
        child_username=child['username'],
        location=request.location,
        message=request.message
    )
    
    alert_dict = alert.model_dump()
    alert_dict['timestamp'] = alert_dict['timestamp'].isoformat()
    await db.sos_alerts.insert_one(alert_dict)
    
    # Notify parent
    if child.get('parent_id'):
        parent = await db.users.find_one({"id": child['parent_id']})
        if parent:
            email_content = f"""
            <h2>🚨 SOS Alert from {child['username']}</h2>
            <p><strong>Time:</strong> {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Location:</strong> {request.location or 'Not provided'}</p>
            <p><strong>Message:</strong> {request.message or 'Emergency alert triggered'}</p>
            <p>Please check on your child immediately.</p>
            """
            send_email(parent['email'], "🚨 SOS Alert from Your Child", email_content)
            alert_dict['notified'] = True
            await db.sos_alerts.update_one({"id": alert.id}, {"$set": {"notified": True}})
    
    return alert

@api_router.post("/awareness/quiz")
async def generate_quiz(request: QuizRequest, current_user = Depends(get_current_user)):
    system_message = "You are an educational AI creating engaging cyber safety quizzes for children. Create age-appropriate questions with multiple choice answers."
    
    prompt = f"Create a 5-question quiz about: {request.topic}. Format: Question, 4 options (A-D), correct answer."
    
    response = await get_gemini_response(prompt, system_message)
    
    # Save quiz session
    quiz_session = {
        "id": str(uuid.uuid4()),
        "child_id": request.child_id,
        "topic": request.topic,
        "quiz_content": response,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    await db.awareness_sessions.insert_one(quiz_session)
    
    return {"quiz": response, "session_id": quiz_session['id']}

@api_router.post("/awareness/scenario")
async def generate_scenario(request: ScenarioRequest, current_user = Depends(get_current_user)):
    system_message = "You are an educational AI creating interactive cyber safety scenarios for children. Create realistic but age-appropriate situations where they must make safe choices."
    
    prompt = f"Create an interactive scenario about: {request.scenario_type}. Include situation, choices, and outcomes."
    
    response = await get_gemini_response(prompt, system_message)
    
    # Save scenario session
    scenario_session = {
        "id": str(uuid.uuid4()),
        "child_id": request.child_id,
        "scenario_type": request.scenario_type,
        "scenario_content": response,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    await db.awareness_sessions.insert_one(scenario_session)
    
    return {"scenario": response, "session_id": scenario_session['id']}

# Parent Dashboard Routes
@api_router.get("/parent/children")
async def get_children(current_user = Depends(get_current_user)):
    if current_user['role'] != 'parent':
        raise HTTPException(status_code=403, detail="Only parents can access this")
    
    children = await db.users.find({"parent_id": current_user['user_id']}, {"_id": 0, "password": 0}).to_list(100)
    return {"children": children}

@api_router.get("/parent/activities/{child_id}")
async def get_child_activities(child_id: str, current_user = Depends(get_current_user)):
    if current_user['role'] != 'parent':
        raise HTTPException(status_code=403, detail="Only parents can access this")
    
    # Verify child belongs to parent
    child = await db.users.find_one({"id": child_id, "parent_id": current_user['user_id']})
    if not child:
        raise HTTPException(status_code=404, detail="Child not found")
    
    chat_scans = await db.chat_scans.find({"child_id": child_id}, {"_id": 0}).sort("timestamp", -1).limit(50).to_list(50)
    fake_profiles = await db.fake_profiles.find({"child_id": child_id}, {"_id": 0}).sort("timestamp", -1).limit(50).to_list(50)
    sos_alerts = await db.sos_alerts.find({"child_id": child_id}, {"_id": 0}).sort("timestamp", -1).limit(50).to_list(50)
    awareness = await db.awareness_sessions.find({"child_id": child_id}, {"_id": 0}).sort("timestamp", -1).limit(20).to_list(20)
    
    return {
        "child": {k: v for k, v in child.items() if k not in ['_id', 'password']},
        "chat_scans": chat_scans,
        "fake_profiles": fake_profiles,
        "sos_alerts": sos_alerts,
        "awareness_sessions": awareness
    }

@api_router.get("/parent/notifications")
async def get_notifications(current_user = Depends(get_current_user)):
    if current_user['role'] != 'parent':
        raise HTTPException(status_code=403, detail="Only parents can access this")
    
    # Get all children
    children = await db.users.find({"parent_id": current_user['user_id']}).to_list(100)
    child_ids = [c['id'] for c in children]
    
    # Get recent high-risk activities
    high_risk_chats = await db.chat_scans.find(
        {"child_id": {"$in": child_ids}, "risk_level": "high"},
        {"_id": 0}
    ).sort("timestamp", -1).limit(10).to_list(10)
    
    fake_profiles = await db.fake_profiles.find(
        {"child_id": {"$in": child_ids}, "is_fake": True},
        {"_id": 0}
    ).sort("timestamp", -1).limit(10).to_list(10)
    
    sos_alerts = await db.sos_alerts.find(
        {"child_id": {"$in": child_ids}},
        {"_id": 0}
    ).sort("timestamp", -1).limit(10).to_list(10)
    
    return {
        "high_risk_chats": high_risk_chats,
        "fake_profiles": fake_profiles,
        "sos_alerts": sos_alerts
    }

@api_router.post("/parent/block-user", response_model=BlockedUser)
async def block_user(request: BlockUserRequest, current_user = Depends(get_current_user)):
    if current_user['role'] != 'parent':
        raise HTTPException(status_code=403, detail="Only parents can block users")
    
    # For this demo, we'll assume child_id is passed or we block for all children
    children = await db.users.find({"parent_id": request.parent_id}).to_list(100)
    
    blocked_users = []
    for child in children:
        blocked = BlockedUser(
            parent_id=request.parent_id,
            child_id=child['id'],
            blocked_username=request.blocked_username,
            reason=request.reason
        )
        
        blocked_dict = blocked.model_dump()
        blocked_dict['timestamp'] = blocked_dict['timestamp'].isoformat()
        await db.blocked_users.insert_one(blocked_dict)
        blocked_users.append(blocked)
    
    return blocked_users[0] if blocked_users else None

# Complaint Routes
@api_router.post("/complaint/submit", response_model=Complaint)
async def submit_complaint(request: ComplaintRequest, current_user = Depends(get_current_user)):
    complaint = Complaint(
        user_id=request.user_id,
        complaint_type=request.complaint_type,
        description=request.description,
        evidence=request.evidence
    )
    
    complaint_dict = complaint.model_dump()
    complaint_dict['timestamp'] = complaint_dict['timestamp'].isoformat()
    await db.complaints.insert_one(complaint_dict)
    
    # Send to police via email and SMS
    user = await db.users.find_one({"id": request.user_id})
    
    email_content = f"""
    <h2>Cybercrime Complaint Report</h2>
    <p><strong>Complaint ID:</strong> {complaint.id}</p>
    <p><strong>From:</strong> {user['username'] if user else 'Unknown'} ({user['email'] if user else 'Unknown'})</p>
    <p><strong>Type:</strong> {request.complaint_type}</p>
    <p><strong>Time:</strong> {complaint.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
    <p><strong>Description:</strong></p>
    <p>{request.description}</p>
    {f'<p><strong>Evidence:</strong> {request.evidence}</p>' if request.evidence else ''}
    <p>Please investigate this matter urgently.</p>
    """
    
    send_email(os.getenv('POLICE_EMAIL'), f"Cybercrime Complaint - {complaint.id}", email_content)
    
    sms_message = f"New cybercrime complaint #{complaint.id[:8]} from {user['username'] if user else 'User'}. Type: {request.complaint_type}. Check email for details."
    send_sms(os.getenv('POLICE_PHONE'), sms_message)
    
    return complaint

@api_router.get("/complaints")
async def get_complaints(current_user = Depends(get_current_user)):
    complaints = await db.complaints.find(
        {"user_id": current_user['user_id']},
        {"_id": 0}
    ).sort("timestamp", -1).to_list(100)
    return {"complaints": complaints}

# Health check
@api_router.get("/")
async def root():
    return {"message": "CyberSafe API is running"}

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()