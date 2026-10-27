from flask import Blueprint, jsonify
from app.services import process_pontifex_logic

api_bp = Blueprint('api', __name__)

@api_bp.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "service": "pontifex-backend"}), 200

@api_bp.route('/process', methods=['POST'])
def process_data():
    result = process_pontifex_logic()
    return jsonify({"success": True, "data": result}), 200
