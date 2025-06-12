from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
from config import Config
import os
from extensions import db, bcrypt, login_manager

# --- APPLICATION ---
app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
bcrypt.init_app(app)
login_manager.init_app(app)

from models import User, PasswordEntry
from forms import RegistrationForm, LoginForm, AddPasswordForm, EditPasswordForm
from utils import generate_encryption_key, encrypt_data, decrypt_data

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- ROUTES ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, password_hash=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Il tuo account è stato creato! Ora puoi effettuare il login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            flash('Login avvenuto con successo!', 'success')
            # Reindirizza l'utente alla pagina che voleva visitare prima del login
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Login fallito. Controlla username e password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    flash('Hai effettuato il logout.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    decrypted_passwords = []
    master_password_provided = False

    if request.method == 'POST':
        master_password = request.form.get('master_password')
        if master_password:
            master_password_provided = True

            encrypted_entries = PasswordEntry.query.filter_by(user_id=current_user.id).all()

            for entry in encrypted_entries:
                try:
                    key = generate_encryption_key(master_password, entry.salt)

                    decrypted_pw = decrypt_data(key, entry.iv, entry.encrypted_password, entry.tag)

                    if decrypted_pw:
                        entry.decrypted_password = decrypted_pw
                        decrypted_passwords.append(entry)
                    else:
                        flash(f'Errore durante la decrittografia di {entry.name}. Master password errata?', 'danger')
                        decrypted_passwords = []
                        break
                except Exception as e:
                    flash(f'Errore critico nella decrittografia: {e}', 'danger')
                    decrypted_passwords = []
                    break
        else:
            flash('Per favore, inserisci la Master Password per sbloccare le password.', 'info')

    return render_template('dashboard.html', decrypted_passwords=decrypted_passwords)

@app.route('/add_password', methods=['GET', 'POST'])
@login_required
def add_password():
    form = AddPasswordForm()
    if form.validate_on_submit():
        master_password = form.master_password.data
        password_to_encrypt = form.password_entry.data

        # Genera un nuovo salt per questa entry
        entry_salt = os.urandom(16) # 16 bytes per un buon salt

        try:
            # Deriva la chiave di crittografia dalla master password e dal salt
            key = generate_encryption_key(master_password, entry_salt)

            # Crittografa la password
            iv, encrypted_pw_bytes, tag = encrypt_data(key, password_to_encrypt)

            # Crea la nuova entry nel database
            new_entry = PasswordEntry(
                user_id=current_user.id,
                name=form.name.data,
                username_entry=form.username_entry.data,
                encrypted_password=encrypted_pw_bytes,
                salt=entry_salt,
                iv=iv,
                tag=tag
            )
            db.session.add(new_entry)
            db.session.commit()
            flash('Password aggiunta con successo!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash(f'Errore durante l\'aggiunta della password. Controlla la Master Password. Errore: {e}', 'danger')
    return render_template('add_password.html', form=form)

@app.route('/edit_password/<int:entry_id>', methods=['GET', 'POST'])
@login_required
def edit_password(entry_id):
    entry = PasswordEntry.query.get_or_404(entry_id)
    if entry.user_id != current_user.id:
        flash('Non hai i permessi per modificare questa password.', 'danger')
        return redirect(url_for('dashboard'))

    form = EditPasswordForm()
    if form.validate_on_submit():
        master_password = form.master_password.data

        if form.password_entry.data:
            password_to_encrypt = form.password_entry.data
            entry_salt = os.urandom(16)
            try:
                key = generate_encryption_key(master_password, entry_salt)
                iv, encrypted_pw_bytes, tag = encrypt_data(key, password_to_encrypt)

                entry.encrypted_password = encrypted_pw_bytes
                entry.salt = entry_salt
                entry.iv = iv
                entry.tag = tag
                flash('Password aggiornata e ricrittografata con successo!', 'success')
            except Exception as e:
                flash(f'Errore durante la ricrittografia della password. Controlla la Master Password. Errore: {e}', 'danger')
                return render_template('edit_password.html', form=form, entry=entry)

        entry.name = form.name.data
        entry.username_entry = form.username_entry.data

        db.session.commit()
        flash('Dettagli password aggiornati con successo!', 'success')
        return redirect(url_for('dashboard'))
    elif request.method == 'GET':
        form.name.data = entry.name
        form.username_entry.data = entry.username_entry
    return render_template('edit_password.html', form=form, entry=entry)

@app.route('/delete_password/<int:entry_id>', methods=['POST'])
@login_required
def delete_password(entry_id):
    entry = PasswordEntry.query.get_or_404(entry_id)
    if entry.user_id != current_user.id:
        flash('Non hai i permessi per eliminare questa password.', 'danger')
        return redirect(url_for('dashboard'))

    db.session.delete(entry)
    db.session.commit()
    flash('Password eliminata con successo.', 'success')
    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
