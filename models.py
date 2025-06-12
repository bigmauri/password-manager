from extensions import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    passwords = db.relationship('PasswordEntry', backref='owner', lazy=True)

    @property
    def is_authenticated(self):
        """
        True se l'utente è autenticato, False altrimenti.
        """
        return True # Per i nostri scopi, un utente loggato è autenticato

    @property
    def is_active(self):
        """
        True se l'utente è attivo (non disabilitato), False altrimenti.
        """
        return True # Per i nostri scopi, gli utenti sono sempre attivi

    @property
    def is_anonymous(self):
        """
        True se l'utente è anonimo, False altrimenti.
        """
        return False # I nostri utenti non sono anonimi una volta loggati

    def get_id(self):
        """
        Restituisce l'ID univoco dell'utente come stringa.
        """
        return str(self.id)

    def __repr__(self):
        return f"User('{self.username}')"

class PasswordEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False) # Es. "Google", "Facebook"
    username_entry = db.Column(db.String(100), nullable=False)
    encrypted_password = db.Column(db.LargeBinary, nullable=False)
    salt = db.Column(db.LargeBinary, nullable=False)
    iv = db.Column(db.LargeBinary, nullable=False)
    tag = db.Column(db.LargeBinary, nullable=False)

    def __repr__(self):
        return f"PasswordEntry('{self.name}', '{self.username_entry}')"
