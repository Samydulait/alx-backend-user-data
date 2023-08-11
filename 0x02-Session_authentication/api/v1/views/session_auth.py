#!/usr/bin/env python3

"""
Handles all routes for the Session authentication
"""

from flask import request, jsonify, abort
from api.v1.views import app_views
from os import getenv


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def login():
    """
    Creates a new session after retrieving the user
    from email and password
    """
    from api.v1.app import auth
    from models.user import User

    email = request.form.get('email')
    pswd = request.form.get('password')

    if not email:
        return jsonify({"error": "email missing"}), 400
    if not pswd:
        return jsonify({"error": "password missing"}), 400
    usr = User.search({"email": email})
    if not usr:
        return jsonify({"error": "no user found for this email"}), 404

    usr = usr[0]
    if not usr.is_valid_password(pswd):
        return jsonify({"error": "wrong password"}), 401
    session_id = auth.create_session(usr.id)
    session_name = getenv("SESSION_NAME")
    resp = jsonify(usr.to_json())
    resp.set_cookie(session_name, session_id)
    return resp


@app_views.route('/auth_session/logout',
                 methods=['DELETE'], strict_slashes=False)
def logout():
    """
    Deletes the current session
    """
    from api.v1.app import auth

    if not auth.destroy_session(request):
        abort(404)

    return jsonify({}), 200