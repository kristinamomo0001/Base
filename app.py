from flask import Flask, request, jsonify, make_response
import gspread
import os
import json
from datetime import datetime, timedelta, timezone
from oauth2client.service_account import ServiceAccountCredentials
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import jwt
import re
import logging
import uuid

app = Flask(__name__)

# 配置日志记录
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 配置速率限制
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per day", "10 per minute"],
)

# Google Sheets API 配置
scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]

# Ulive 配置
ulive_gsa_env_var = "RLa_p_pct"
ulive_service_account_info = os.getenv(ulive_gsa_env_var)
if not ulive_service_account_info:
    raise ValueError(f"Environment variable {ulive_gsa_env_var} not found!")
ulive_service_account_data = json.loads(ulive_service_account_info)
ulive_creds = ServiceAccountCredentials.from_json_keyfile_dict(ulive_service_account_data, scope)
ulive_client = gspread.authorize(ulive_creds)

# Zillow 配置
zillow_gsa_env_var = "Zsa_p_pct"
zillow_service_account_info = os.getenv(zillow_gsa_env_var)
if not zillow_service_account_info:
    raise ValueError(f"Environment variable {zillow_gsa_env_var} not found!")
zillow_service_account_data = json.loads(zillow_service_account_info)
zillow_creds = ServiceAccountCredentials.from_json_keyfile_dict(zillow_service_account_data, scope)
zillow_client = gspread.authorize(zillow_creds)

# JWT 密钥加载
ulive_secret_key_env_var = "RL_p_pct"
zillow_secret_key_env_var = "Zs_p_pct"
ULIVE_SECRET_KEY = os.getenv(ulive_secret_key_env_var)
ZILLOW_SECRET_KEY = os.getenv(zillow_secret_key_env_var)
if not ULIVE_SECRET_KEY or not ZILLOW_SECRET_KEY:
    raise ValueError("One or both JWT secret keys not found!")

# Google Sheets 工具类
class GoogleSheetManager:
    def __init__(self, client, spreadsheet_name, worksheet_name):
        spreadsheet = client.open(spreadsheet_name)
        try:
            self.sheet = spreadsheet.worksheet(worksheet_name)
        except gspread.exceptions.WorksheetNotFound:
            self.sheet = spreadsheet.add_worksheet(title=worksheet_name, rows="100", cols="20")

    def get_all_users(self):
        return self.sheet.get_all_records()

    def update_user_ip(self, row_index, ip_address):
        self.sheet.update_cell(row_index, 4, ip_address)

    def append_user(self, fingerprint, registration_date, expiry_date, ip_address):
        self.sheet.append_row([
            fingerprint,
            registration_date.strftime("%Y-%m-%d"),
            expiry_date.strftime("%Y-%m-%d"),
            ip_address,
            "active"
        ])

# 验证指纹格式
def validate_fingerprint(fingerprint):
    if not re.match(r"^[a-f0-9]{64}$", fingerprint):
        raise ValueError("Invalid fingerprint format: Must be a 64-character SHA256 hash")

# 生成 JWT Token
def generate_token(fingerprint, secret_key):
    token_id = str(uuid.uuid4())
    payload = {
        "fingerprint": fingerprint,
        "jti": token_id,
        "exp": datetime.utcnow() + timedelta(hours=1),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, secret_key, algorithm="HS256")

# 验证 JWT Token
def verify_token(token, secret_key):
    try:
        decoded = jwt.decode(token, secret_key, algorithms=["HS256"])
        return decoded
    except jwt.ExpiredSignatureError:
        logging.warning("Token verification failed: Token has expired")
        raise ValueError("Token has expired")
    except jwt.InvalidTokenError:
        logging.warning("Token verification failed: Invalid token")
        raise ValueError("Invalid token")

# Ulive 注册接口
@app.route('/ulive/register', methods=['POST'])
@limiter.limit("5 per minute")
def ulive_register_user():
    try:
        data = request.json
        fingerprint = data.get("fingerprint")
        ip_address = request.remote_addr

        if not fingerprint:
            return jsonify({"error": "Missing fingerprint"}), 400

        validate_fingerprint(fingerprint)
        sheet_manager = GoogleSheetManager(ulive_client, "R_Hunter", "U_Live")
        users = sheet_manager.get_all_users()

        for index, user in enumerate(users):
            if user["Fingerprint"] == fingerprint:
                row_index = index + 2
                sheet_manager.update_user_ip(row_index, ip_address)
                token = generate_token(fingerprint, ULIVE_SECRET_KEY)
                return jsonify({
                    "message": "IP updated successfully",
                    "fingerprint": fingerprint,
                    "ip_address": ip_address,
                    "registration_date": user["Registration Date"],
                    "expiry_date": user["Expiry Date"],
                    "status": user["Status"],
                    "token": token
                }), 200

        registration_date = datetime.now(timezone.utc)
        expiry_date = registration_date + timedelta(days=2)
        sheet_manager.append_user(fingerprint, registration_date, expiry_date, ip_address)
        token = generate_token(fingerprint, ULIVE_SECRET_KEY)
        return jsonify({
            "message": "User registered successfully",
            "fingerprint": fingerprint,
            "ip_address": ip_address,
            "registration_date": registration_date.strftime("%Y-%m-%d"),
            "expiry_date": expiry_date.strftime("%Y-%m-%d"),
            "status": "active",
            "token": token
        }), 201
    except ValueError as ve:
        logging.error(f"Ulive Validation error: {ve}")
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        logging.error(f"Ulive Unexpected error: {e}")
        return jsonify({"error": "Internal server error"}), 500

# Zillow 注册接口
@app.route('/zillow/register', methods=['POST'])
@limiter.limit("5 per minute")
def zillow_register_user():
    try:
        data = request.json
        fingerprint = data.get("fingerprint")
        ip_address = request.remote_addr

        if not fingerprint:
            return jsonify({"error": "Missing fingerprint"}), 400

        validate_fingerprint(fingerprint)
        sheet_manager = GoogleSheetManager(zillow_client, "R_Hunter", "Zillow")
        users = sheet_manager.get_all_users()

        for index, user in enumerate(users):
            if user["Fingerprint"] == fingerprint:
                row_index = index + 2
                sheet_manager.update_user_ip(row_index, ip_address)
                token = generate_token(fingerprint, ZILLOW_SECRET_KEY)
                return jsonify({
                    "message": "IP updated successfully",
                    "fingerprint": fingerprint,
                    "ip_address": ip_address,
                    "registration_date": user["Registration Date"],
                    "expiry_date": user["Expiry Date"],
                    "status": user["Status"],
                    "token": token
                }), 200

        registration_date = datetime.now(timezone.utc)
        expiry_date = registration_date + timedelta(days=2)
        sheet_manager.append_user(fingerprint, registration_date, expiry_date, ip_address)
        token = generate_token(fingerprint, ZILLOW_SECRET_KEY)
        return jsonify({
            "message": "User registered successfully",
            "fingerprint": fingerprint,
            "ip_address": ip_address,
            "registration_date": registration_date.strftime("%Y-%m-%d"),
            "expiry_date": expiry_date.strftime("%Y-%m-%d"),
            "status": "active",
            "token": token
        }), 201
    except ValueError as ve:
        logging.error(f"Zillow Validation error: {ve}")
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        logging.error(f"Zillow Unexpected error: {e}")
        return jsonify({"error": "Internal server error"}), 500

# Ulive 验证接口
@app.route('/ulive/validate', methods=['POST'])
@limiter.limit("10 per minute")
def ulive_validate_user():
    try:
        token = request.headers.get("Authorization")
        if not token:
            return jsonify({"error": "Missing token"}), 400
        if token.startswith("Bearer "):
            token = token.split("Bearer ")[1]

        decoded = verify_token(token, ULIVE_SECRET_KEY)
        fingerprint = decoded.get("fingerprint")

        sheet_manager = GoogleSheetManager(ulive_client, "R_Hunter", "U_Live")
        users = sheet_manager.get_all_users()

        for user in users:
            if user["Fingerprint"] == fingerprint:
                expiry_date = user.get("Expiry Date", "")
                if not expiry_date:
                    return jsonify({"error": "Expiry date is missing"}), 400

                expiry_date_dt = datetime.strptime(expiry_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                expiry_end_of_day = expiry_date_dt + timedelta(days=1) - timedelta(seconds=1)
                current_time = datetime.now(timezone.utc)

                if current_time >= expiry_end_of_day:
                    return jsonify({
                        "error": "服务已过期，请联系客户@Root_Hunter777支持续期。"
                    }), 403

                remaining_days = (expiry_end_of_day - current_time).days
                if remaining_days <= 3:
                    return jsonify({
                        "status": "warning",
                        "remaining_days": remaining_days,
                        "message": f"剩余 {remaining_days} 天，请尽快联系客户@Root_Hunter777续期。"
                    }), 200

                return jsonify({
                    "status": "active",
                    "expiry_date": expiry_date,
                    "remaining_days": remaining_days,
                    "message": "User is active."
                }), 200

        return jsonify({"error": "User not found"}), 404
    except ValueError as ve:
        logging.error(f"Ulive Validation error: {ve}")
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        logging.error(f"Ulive Unexpected error: {e}")
        return jsonify({"error": "Internal server error"}), 500

# Zillow 验证接口
@app.route('/zillow/validate', methods=['POST'])
@limiter.limit("10 per minute")
def zillow_validate_user():
    try:
        token = request.headers.get("Authorization")
        if not token:
            return jsonify({"error": "Missing token"}), 400
        if token.startswith("Bearer "):
            token = token.split("Bearer ")[1]

        decoded = verify_token(token, ZILLOW_SECRET_KEY)
        fingerprint = decoded.get("fingerprint")

        sheet_manager = GoogleSheetManager(zillow_client, "R_Hunter", "Zillow")
        users = sheet_manager.get_all_users()

        for user in users:
            if user["Fingerprint"] == fingerprint:
                expiry_date = user.get("Expiry Date", "")
                if not expiry_date:
                    return jsonify({"error": "Expiry date is missing"}), 400

                expiry_date_dt = datetime.strptime(expiry_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                expiry_end_of_day = expiry_date_dt + timedelta(days=1) - timedelta(seconds=1)
                current_time = datetime.now(timezone.utc)

                if current_time >= expiry_end_of_day:
                    return jsonify({
                        "status": "expired",
                        "message": "请联系客户@Root_Hunter777支持续期。"
                    }), 200

                remaining_days = (expiry_end_of_day - current_time).days
                if remaining_days <= 3:
                    return jsonify({
                        "status": "warning",
                        "remaining_days": remaining_days,
                        "message": f"剩余 {remaining_days} 天，请尽快联系客户@Root_Hunter777续期。"
                    }), 200

                return jsonify({
                    "status": "active",
                    "expiry_date": expiry_date,
                    "remaining_days": remaining_days,
                    "message": "User is active."
                }), 200

        return jsonify({"error": "User not found"}), 404
    except ValueError as ve:
        logging.error(f"Zillow Validation error: {ve}")
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        logging.error(f"Zillow Unexpected error: {e}")
        return jsonify({"error": "Internal server error"}), 500

# 根路由
@app.route('/')
def home():
    response_data = {"message": "Combined Ulive and Zillow Service @Root_Hunter777"}
    response = make_response(json.dumps(response_data, ensure_ascii=False))
    response.headers["Content-Type"] = "application/json; charset=utf-8"
    return response

if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
