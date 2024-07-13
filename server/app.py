#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):

    def post(self):
        json_data = request.get_json()
        if not json_data.get('username'):
            return {"message": "Username cannot be empty"}, 422
        duplicate_name_user = User.query.filter(User.username==json_data['username']).first()
        if duplicate_name_user:
            return {"message": "This username is already used. Try with a new username"}, 422
        new_record = User(
            username = json_data.get('username'),
            image_url = json_data.get('image_url'),
            bio = json_data.get('bio')
        )

        new_record.password_hash = json_data.get('password')

        db.session.add(new_record)
        db.session.commit()
        print(new_record)

        session['user_id'] = new_record.id
        response = new_record.to_dict()
        print(response)

        return new_record.to_dict(), 201

class CheckSession(Resource):
    def get(self):
        user = User.query.filter(User.id==session.get('user_id')).first()
        if user:
            return user.to_dict()
        else:
            return {'mesage': '401: Not Authorized'}, 401 

class Login(Resource):
    def post(self):
        json_data = request.get_json()
        user = User.query.filter(User.username==json_data.get('username')).first()
        if user and user.authenticate(json_data.get('password')):
            session['user_id'] = user.id
            return user.to_dict()

        return {'error': 'Invalid username or password'}, 401

class Logout(Resource):
    def delete(self):
        if not session['user_id']:
            return {'error': 'You are not logged in'}, 401

        session['user_id']= None
        return {}, 204

class RecipeIndex(Resource):
    def get(self):
        if not session['user_id']:
            return {'message': 'Please signup/login to see Recipe'}, 401
        recipes = Recipe.query.all()
        recipes_dict = []
        for recipe in recipes:
            recipes_dict.append(recipe.to_dict())
        return recipes_dict, 200  

    def post(self):
        if not session['user_id']:
            return {'message': 'Please signup/login to add recipes'}, 401
        json_data = request.get_json()
        if len(json_data.get('instructions'))<=50:
            return {'error': 'Instruction must be at least 50 characters long'}, 422
        new_record = Recipe(
            title =json_data.get('title'),
            instructions=json_data.get('instructions'),
            minutes_to_complete=json_data.get('minutes_to_complete'),
            user_id=session.get('user_id')
        )
        db.session.add(new_record)
        db.session.commit()
        if new_record.id:        
            return new_record.to_dict(), 201
        return {'error': 'The input information is not valid'}, 422
           


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)