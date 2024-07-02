#!/usr/bin/env python3

from flask import request, session, jsonify
from flask_restful import Resource
from werkzeug.security import generate_password_hash, check_password_hash

from config import app, db, api
from models import User

class ClearSession(Resource):
    def delete(self):
        session.clear()
        return {}, 204

class Signup(Resource):
    def post(self):
        json = request.get_json()
        username = json['username']
        password = json['password']
        
        user = User(username=username)
        user.password_hash = generate_password_hash(password)
        
        db.session.add(user)
        db.session.commit()
        
        session['user_id'] = user.id
        
        return user.to_dict(), 201

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            user = User.query.get(user_id)
            return user.to_dict(), 200
        return {}, 204

class Login(Resource):
    def post(self):
        json = request.get_json()
        username = json['username']
        password = json['password']
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            return user.to_dict(), 200
        
        return {'error': 'Invalid credentials'}, 401

class Logout(Resource):
    def delete(self):
        session.clear()
        return {}, 204

api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
