from flask import Flask, render_template, redirect, url_for, flash, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_restful import Api, Resource
from flask_httpauth import HTTPTokenAuth
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
import os
import binascii
import random
from sqlalchemy import func

app = Flask(__name__)
api = Api(app)
auth = HTTPTokenAuth(scheme='Bearer')

# Configurações básicas
app.config['SECRET_KEY'] = 'facu123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

db = SQLAlchemy(app)

def generate_short_token():
    return binascii.hexlify(os.urandom(5)).decode()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    token = db.Column(db.String(250), unique=True, nullable=False)

class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if user.password == form.password.data:
                flash('Voce ja tem um usuario! Aqui está o seu token: ' + user.token, 'info')
                return redirect(url_for('register'))
            else:
                flash('Voce ja tem um usuario! Senha errada!', 'danger')
                return redirect(url_for('register'))
        token = generate_short_token()
        new_user = User(email=form.email.data, password=form.password.data, token=token)
        db.session.add(new_user)
        db.session.commit()
        flash('Registrado com Sucesso! Aqui está o seu token: ' + token, 'success')
        return redirect(url_for('register'))
    return render_template('register.html', form=form)

@auth.verify_token
def verify_token(token):
    user = User.query.filter_by(token=token).first()
    if user:
        return True
    return False

class JokeModel(db.Model):
    __tablename__ = 'joke'
    id = db.Column(db.Integer, primary_key=True)
    theme = db.Column(db.String(150), nullable=False)
    content = db.Column(db.String(500), nullable=False)

class Joke(Resource):
    def get(self, theme=None):
        # Tente pegar o token do cabeçalho primeiro
        token = request.headers.get('Authorization')

        # Se o token no cabeçalho começa com "Bearer", remova essa parte
        if token and token.startswith("Bearer "):
            token = token[7:]
        # Se não encontrarmos no cabeçalho, tente pegar da URL
        if not token:
            token = request.args.get('token')

        # Verifica se o token está no banco de dados
        user = User.query.filter_by(token=token).first()
        if not user:
            return {"message": "Acesso negado: Token inválido ou não fornecido"}, 401

        if theme:
            theme = theme.lower()
            jokes_in_theme = JokeModel.query.filter(func.lower(JokeModel.theme) == theme).all()
            if jokes_in_theme:
                selected_joke = random.choice(jokes_in_theme)
                return jsonify({'theme': theme, 'joke': selected_joke.content})
            else:
                return {"message": "Nenhuma piada encontrada para o tema especificado."}, 404
        else:
            all_jokes = JokeModel.query.all()
            selected_joke = random.choice(all_jokes)
            return jsonify({'theme': selected_joke.theme, 'joke': selected_joke.content})

    @auth.login_required
    def post(self):
        data = request.get_json()
        theme = data.get('theme', 'general').lower()  # Convertendo para minúsculas aqui
        joke_content = data.get('joke')

        if joke_content:
            new_joke = JokeModel(theme=theme, content=joke_content)
            db.session.add(new_joke)
            db.session.commit()
            return {'message': 'Piada adicionada com sucesso!'}
        return {'message': 'Piada não fornecida'}, 400

    @auth.login_required
    def put(self, theme=None):
        if not theme:
            return {'message': 'Tema não fornecido'}, 400

        theme = theme.lower()  # Convertendo para minúsculas
        data = request.get_json()
        old_joke_content = data.get('old_joke')
        new_joke_content = data.get('new_joke')
        new_theme = data.get('new_theme', theme).lower()  # Se um novo tema não for fornecido, mantenha o atual

        theme_exists = JokeModel.query.filter_by(theme=theme).first()
        if not theme_exists:
            return {'message': 'Não tem dado nesse tema'}, 404

        if old_joke_content and new_joke_content:
            old_joke = JokeModel.query.filter_by(theme=theme, content=old_joke_content).first()

            if old_joke:
                old_joke.content = new_joke_content
                old_joke.theme = new_theme  # Atualizando o tema
                db.session.commit()
                return {'message': 'Piada e/ou tema atualizado com sucesso!'}
            else:
                return {'message': 'Piada não encontrada'}, 404
        return {'message': 'Dados incompletos fornecidos'}, 400

    @auth.login_required
    def delete(self, theme=None):
        if not theme:
            return {'message': 'Tema não fornecido'}, 400

        theme = theme.lower()  # Convertendo para minúsculas aqui
        data = request.get_json()
        joke_content = data.get('joke')

        theme_exists = JokeModel.query.filter_by(theme=theme).first()
        if not theme_exists:
            return {'message': 'Não tem dado nesse tema'}, 404

        if joke_content:
            joke_to_delete = JokeModel.query.filter_by(theme=theme, content=joke_content).first()

            if joke_to_delete:
                db.session.delete(joke_to_delete)
                db.session.commit()
                return {'message': 'Piada excluída com sucesso!'}
            else:
                return {'message': 'Piada não encontrada'}, 404
        return {'message': 'Dados incompletos fornecidos'}, 400

api.add_resource(Joke, '/joke', '/joke/<string:theme>')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000)
