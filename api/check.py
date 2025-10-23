from flask import Flask, request, jsonify
import uuid
import requests
import re
from datetime import datetime, timezone
from user_agent import generate_user_agent
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

def safe_request(url, headers=None, data=None, method='GET', timeout=10):
    try:
        if method.upper() == 'POST':
            response = requests.post(url, headers=headers, data=data, timeout=timeout)
        else:
            response = requests.get(url, headers=headers, timeout=timeout)
        return response
    except requests.exceptions.Timeout:
        logger.error(f"Request timeout for {url}")
        return None
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error for {url}: {e}")
        return None

def GetRDay(expiry_date):
    try:
        expiry = datetime.strptime(expiry_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        current = datetime.now(timezone.utc)
        delta = expiry - current
        return max(0, delta.days)
    except:
        return 0

def check_crunchyroll_account(user, pasw):
    result = {
        "active_subscription": "false",
        "country": "N/A", 
        "days_remaining": 0,
        "email": user,
        "expiry_date": "N/A",
        "plan": "N/A",
        "status": "FREE",
        "verified": "false",
        "powered_by": "@DEMONXRAIHAN"
    }
    
    try:
        id = str(uuid.uuid4())
        userA = generate_user_agent()

        login = "https://beta-api.crunchyroll.com/auth/v1/token"
        header = {
            "Host": "beta-api.crunchyroll.com",
            "User-Agent": userA,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "Origin": "https://sso.crunchyroll.com",
            "Referer": "https://sso.crunchyroll.com/login",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
        }

        data = {
            "grant_type": "password",
            "username": user,
            "password": pasw,
            "scope": "offline_access",
            "client_id": "ajcylfwdtjjtq7qpgks3",
            "client_secret": "oKoU8DMZW7SAaQiGzUEdTQG4IimkL8I_",
            "device_type": "@BesicCode",
            "device_id": id,
            "device_name": "Luis"
        }

        r1 = safe_request(login, headers=header, data=data, method='POST', timeout=15)
        if not r1:
            return result
            
        login_r = r1.json()

        if "error" in login_r:
            return result
        elif "access_token" not in login_r:
            return result

        act = login_r.get("access_token")

        get_id = "https://beta-api.crunchyroll.com/accounts/v1/me"
        header = {
            "Authorization": f"Bearer {act}",
            "User-Agent": userA,
        }

        r2 = safe_request(get_id, headers=header, timeout=10)
        if not r2:
            return result
            
        account_data = r2.json()

        aci = account_data.get("account_id")
        exi = account_data.get("external_id")

        emailV = re.search(r'"email_verified":([^,}]*)', r2.text)
        if emailV:
            result["verified"] = emailV.group(1).strip().lower()

        if exi:
            sts = f"https://beta-api.crunchyroll.com/subs/v1/subscriptions/{exi}/benefits"
            header = {"Authorization": f"Bearer {act}"}
            r3 = safe_request(sts, headers=header, timeout=10)
            if r3:
                benefits_data = r3.text

                if '"total":0,' not in benefits_data:
                    result["status"] = "PREMIUM"
                    result["active_subscription"] = "true"

                country = re.search(r'"subscription_country":"([^"]*)"', benefits_data)
                if country:
                    result["country"] = country.group(1).strip()

        if aci:
            sub_url = f"https://beta-api.crunchyroll.com/subs/v3/subscriptions/{aci}"
            header = {"Authorization": f"Bearer {act}"}
            r4 = safe_request(sub_url, headers=header, timeout=10)
            if r4:
                subscription_data = r4.text

                plan_match = re.search(r'"sku":"([^"]*)"', subscription_data)
                if plan_match:
                    result["plan"] = plan_match.group(1).strip()

                expiry_match = re.search(r'"expiration_date":"([^"]*)"', subscription_data)
                renewal_match = re.search(r'"next_renewal_date":"([^"]*)"', subscription_data)
                
                expiry_date = "N/A"
                if expiry_match:
                    expiry_date = expiry_match.group(1).strip().split('T')[0]
                elif renewal_match:
                    expiry_date = renewal_match.group(1).strip().split('T')[0]
                
                result["expiry_date"] = expiry_date
                
                if expiry_date != "N/A":
                    days_remaining = GetRDay(expiry_date)
                    result["days_remaining"] = days_remaining
        
    except Exception as e:
        logger.error(f"Error in check_crunchyroll_account: {e}")
    
    return result

@app.route('/', methods=['GET', 'POST'])
def check_account():
    if request.method == 'POST':
        data = request.get_json()
        if not data:
            return jsonify({
                "error": "No JSON data provided",
                "powered_by": "@DEMONXRAIHAN"
            }), 400
        
        email = data.get('email', '').strip()
        password = data.get('password', '').strip()
    else:
        email = request.args.get('email', '').strip()
        password = request.args.get('password', '').strip()
    
    if not email or not password:
        return jsonify({
            "error": "Email and password are required",
            "powered_by": "@DEMONXRAIHAN"
        }), 400
    
    result = check_crunchyroll_account(email, password)
    
    return jsonify(result)

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy",
        "powered_by": "@DEMONXRAIHAN"
    })

# Vercel serverless function handler
def handler(request, context=None):
    with app.app_context():
        return app.full_dispatch_request()
