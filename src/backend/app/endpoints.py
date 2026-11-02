from flask import Blueprint, jsonify, request
from app.services import process_pontifex_logic, wake_on_lan as wol_service

api_bp = Blueprint('api', __name__)

@api_bp.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "service": "pontifex-backend"}), 200

@api_bp.route('/process', methods=['POST'])
def process_data():
    result = process_pontifex_logic()
    return jsonify({"success": True, "data": result}), 200

@api_bp.route('/devices/wol', methods=['PUT'])
def wake_on_lan():
    data = request.get_json()
    result = wol_service(mac_address=data['mac'], ip_address=data.get('ip', '255.255.255.255'), port=data.get('port', 9))
    if result.get('success'):
        return jsonify(result), 200
    else:
        return jsonify(result), 400
