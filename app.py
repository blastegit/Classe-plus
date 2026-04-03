import logging
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_bcrypt import Bcrypt
from functools import wraps
from datetime import datetime, timedelta

# config de base
app = Flask(__name__)
app.secret_key = "Super_Secret_Key_ENT"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///campus.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
bcrypt = Bcrypt(app)

# config du logging
logging.basicConfig(filename='security.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')


# ==========================================
# MODELES
# ==========================================

class Classe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nom = db.Column(db.String(50), unique=True, nullable=False)
    etudiants = db.relationship('User', backref='classe_associee', lazy=True)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    nom = db.Column(db.String(50), nullable=True)
    prenom = db.Column(db.String(50), nullable=True)
    classe_id = db.Column(db.Integer, db.ForeignKey('classe.id'), nullable=True)

class Cours(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    classe_id = db.Column(db.Integer, db.ForeignKey('classe.id'), nullable=False)
    professeur_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    matiere = db.Column(db.String(100), nullable=False)
    jour = db.Column(db.String(20), nullable=False)
    start_time = db.Column(db.String(10), nullable=False)
    end_time = db.Column(db.String(10), nullable=False)
    classe = db.relationship('Classe', backref='cours_liste')
    professeur = db.relationship('User', backref='cours_prof')

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    etudiant_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    professeur_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    projet = db.Column(db.String(100), nullable=False)
    valeur = db.Column(db.Float, nullable=False)
    etudiant = db.relationship('User', foreign_keys=[etudiant_id], backref='notes_recues')
    professeur_rel = db.relationship('User', foreign_keys=[professeur_id], backref='notes_donnees')

class Absence(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    etudiant_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    professeur_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.String(20), nullable=False)
    statut = db.Column(db.String(20), nullable=False)
    etudiant = db.relationship('User', foreign_keys=[etudiant_id], backref='absences')
    professeur_rel = db.relationship('User', foreign_keys=[professeur_id])

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    expediteur_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    destinataire_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    classe_id = db.Column(db.Integer, db.ForeignKey('classe.id'), nullable=True)
    contenu = db.Column(db.Text, nullable=False)
    date_envoi = db.Column(db.DateTime, default=datetime.utcnow)
    expediteur = db.relationship('User', foreign_keys=[expediteur_id], backref='messages_envoyes')
    destinataire = db.relationship('User', foreign_keys=[destinataire_id], backref='messages_recus')


# decorateur pour les roles
def role_required(*roles):
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            if session.get('role') not in roles:
                logging.warning(f"Acces refuse - {session.get('username')} sur {request.path}")
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return wrapper


# headers de securite
@app.after_request
def ajouter_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:;"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response


# ==========================================
# AUTHENTIFICATION
# ==========================================

@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if session['role'] == 'admin':
        return redirect(url_for('admin_home'))
    if session['role'] == 'professeur':
        return redirect(url_for('prof_home'))
    if session['role'] == 'etudiant':
        return redirect(url_for('etu_home'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash("Veuillez remplir tous les champs.", "error")
            return render_template('login.html')

        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session.permanent = True
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            logging.info(f"Connexion reussie : {username}")
            return redirect(url_for('home'))

        logging.warning(f"Echec connexion : {username}")
        flash("Identifiants incorrects.", "error")
    return render_template('login.html')

@app.route('/logout')
def logout():
    nom = session.get('username', 'inconnu')
    session.clear()
    logging.info(f"Deconnexion : {nom}")
    return redirect(url_for('login'))

@app.errorhandler(403)
def page_interdite(e):
    return render_template('403.html'), 403


# ==========================================
# MESSAGERIE
# ==========================================

@app.route('/messages', methods=['GET', 'POST'])
def messages():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        dest_id = request.form.get('destinataire_id')
        cls_id = request.form.get('classe_id')
        contenu = request.form.get('contenu', '').strip()

        if not contenu:
            flash("Le message ne peut pas etre vide.", "error")
            return redirect(url_for('messages'))

        msg = Message(
            expediteur_id=session['user_id'],
            destinataire_id=int(dest_id) if dest_id else None,
            classe_id=int(cls_id) if cls_id else None,
            contenu=contenu
        )
        db.session.add(msg)
        db.session.commit()
        flash("Message envoye !", "success")
        return redirect(url_for('messages'))

    me = User.query.get(session['user_id'])
    mes_messages = Message.query.filter(
        (Message.destinataire_id == me.id) | (Message.classe_id == me.classe_id)
    ).order_by(Message.date_envoi.desc()).all()
    users = User.query.all()
    classes = Classe.query.all()
    return render_template('shared/messages.html', messages=mes_messages, users=users, classes=classes, me=me)


# ==========================================
# ETUDIANT
# ==========================================

@app.route('/etudiant/home')
@role_required('etudiant')
def etu_home():
    me = User.query.get(session['user_id'])
    nb_notes = Note.query.filter_by(etudiant_id=me.id).count()
    nb_absences = Absence.query.filter_by(etudiant_id=me.id, statut='Absent').count()
    nb_retards = Absence.query.filter_by(etudiant_id=me.id, statut='Retard').count()
    return render_template('etudiant/home.html', user=me, nb_notes=nb_notes, nb_absences=nb_absences, nb_retards=nb_retards)

@app.route('/etudiant/notes')
@role_required('etudiant')
def etu_notes():
    notes = Note.query.filter_by(etudiant_id=session['user_id']).all()
    moyenne = round(sum(n.valeur for n in notes) / len(notes), 2) if notes else None
    return render_template('etudiant/notes.html', notes=notes, moyenne=moyenne)

@app.route('/etudiant/edt')
@role_required('etudiant')
def etu_edt():
    me = User.query.get(session['user_id'])
    cours = Cours.query.filter_by(classe_id=me.classe_id).all() if me.classe_id else []
    jour_map = {'Lundi': 1, 'Mardi': 2, 'Mercredi': 3, 'Jeudi': 4, 'Vendredi': 5}
    events = []
    for c in cours:
        prof = User.query.get(c.professeur_id)
        nom_prof = f"{prof.prenom} {prof.nom}" if prof else "?"
        events.append({
            'title': f"{c.matiere} - {nom_prof}",
            'daysOfWeek': [jour_map.get(c.jour, 1)],
            'startTime': c.start_time,
            'endTime': c.end_time
        })
    return render_template('etudiant/edt.html', events=events)

@app.route('/etudiant/absences')
@role_required('etudiant')
def etu_absences():
    absences = Absence.query.filter_by(etudiant_id=session['user_id']).order_by(Absence.date.desc()).all()
    return render_template('etudiant/absences.html', absences=absences)


# ==========================================
# PROFESSEUR
# ==========================================

@app.route('/professeur/home')
@role_required('professeur')
def prof_home():
    me = User.query.get(session['user_id'])
    mes_cours = Cours.query.filter_by(professeur_id=me.id).all()
    nb_cours = len(mes_cours)
    classes_ids = list(set([c.classe_id for c in mes_cours]))
    nb_eleves = User.query.filter(User.classe_id.in_(classes_ids), User.role == 'etudiant').count() if classes_ids else 0
    return render_template('prof/home.html', user=me, nb_cours=nb_cours, nb_eleves=nb_eleves)

@app.route('/professeur/edt')
@role_required('professeur')
def prof_edt():
    cours = Cours.query.filter_by(professeur_id=session['user_id']).all()
    jour_map = {'Lundi': 1, 'Mardi': 2, 'Mercredi': 3, 'Jeudi': 4, 'Vendredi': 5}
    events = []
    for c in cours:
        classe = Classe.query.get(c.classe_id)
        events.append({
            'title': f"{c.matiere} ({classe.nom if classe else '?'})",
            'daysOfWeek': [jour_map.get(c.jour, 1)],
            'startTime': c.start_time,
            'endTime': c.end_time
        })
    return render_template('prof/edt.html', events=events)

@app.route('/professeur/appel', methods=['GET', 'POST'])
@role_required('professeur')
def prof_appel():
    mes_cours = Cours.query.filter_by(professeur_id=session['user_id']).all()
    classes_ids = list(set([c.classe_id for c in mes_cours]))
    eleves = User.query.filter(User.classe_id.in_(classes_ids), User.role == 'etudiant').all() if classes_ids else []
    classes = Classe.query.filter(Classe.id.in_(classes_ids)).all() if classes_ids else []

    if request.method == 'POST':
        etudiant_id = request.form.get('etudiant_id')
        statut = request.form.get('statut')
        date_jour = request.form.get('date', datetime.now().strftime("%Y-%m-%d"))

        if etudiant_id and statut:
            etu = User.query.get(int(etudiant_id))
            if etu and etu.classe_id in classes_ids:
                absence = Absence(
                    etudiant_id=int(etudiant_id),
                    professeur_id=session['user_id'],
                    date=date_jour,
                    statut=statut
                )
                db.session.add(absence)
                db.session.commit()
                flash("Appel enregistre.", "success")
            else:
                flash("Etudiant non autorise.", "error")
        return redirect(url_for('prof_appel'))

    absences_recentes = Absence.query.filter_by(professeur_id=session['user_id']).order_by(Absence.date.desc()).limit(20).all()
    return render_template('prof/appel.html', eleves=eleves, classes=classes, absences_recentes=absences_recentes)

@app.route('/professeur/notes', methods=['GET', 'POST'])
@role_required('professeur')
def prof_notes():
    mes_cours = Cours.query.filter_by(professeur_id=session['user_id']).all()
    classes_ids = list(set([c.classe_id for c in mes_cours]))
    eleves = User.query.filter(User.classe_id.in_(classes_ids), User.role == 'etudiant').all() if classes_ids else []

    if request.method == 'POST':
        etudiant_id = request.form.get('etudiant_id')
        projet = request.form.get('projet', '').strip()
        valeur = request.form.get('valeur')

        if etudiant_id and projet and valeur:
            try:
                val = float(valeur)
                if val < 0 or val > 20:
                    flash("La note doit etre entre 0 et 20.", "error")
                    return redirect(url_for('prof_notes'))

                etu = User.query.get(int(etudiant_id))
                if etu and etu.classe_id in classes_ids:
                    note = Note(
                        etudiant_id=int(etudiant_id),
                        professeur_id=session['user_id'],
                        projet=projet,
                        valeur=val
                    )
                    db.session.add(note)
                    db.session.commit()
                    flash("Note ajoutee.", "success")
                else:
                    flash("Etudiant non autorise.", "error")
            except ValueError:
                flash("Note invalide.", "error")
        else:
            flash("Remplir tous les champs.", "error")
        return redirect(url_for('prof_notes'))

    notes_mises = Note.query.filter_by(professeur_id=session['user_id']).order_by(Note.id.desc()).all()
    return render_template('prof/notes.html', eleves=eleves, notes_mises=notes_mises)


# ==========================================
# ADMIN
# ==========================================

@app.route('/admin/home')
@role_required('admin')
def admin_home():
    nb_users = User.query.count()
    nb_classes = Classe.query.count()
    nb_cours = Cours.query.count()
    nb_etudiants = User.query.filter_by(role='etudiant').count()
    nb_profs = User.query.filter_by(role='professeur').count()
    return render_template('admin/home.html', nb_users=nb_users, nb_classes=nb_classes, nb_cours=nb_cours, nb_etudiants=nb_etudiants, nb_profs=nb_profs)

@app.route('/admin/users', methods=['GET', 'POST'])
@role_required('admin')
def admin_users():
    if request.method == 'POST':
        action = request.form.get('action')

        # creer un utilisateur
        if action == 'creer_user':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            role = request.form.get('role', '')
            nom = request.form.get('nom', '').strip()
            prenom = request.form.get('prenom', '').strip()

            if not username or not password or not role:
                flash("Champs obligatoires manquants.", "error")
            elif User.query.filter_by(username=username).first():
                flash("Ce nom d'utilisateur existe deja.", "error")
            elif role not in ['admin', 'professeur', 'etudiant']:
                flash("Role invalide.", "error")
            else:
                hashed = bcrypt.generate_password_hash(password).decode('utf-8')
                u = User(username=username, password=hashed, role=role, nom=nom, prenom=prenom)
                db.session.add(u)
                db.session.commit()
                flash(f"Utilisateur {prenom} {nom} cree.", "success")
                logging.info(f"Nouvel utilisateur : {username} ({role})")

        # creer une classe
        elif action == 'creer_classe':
            nom_classe = request.form.get('nom_classe', '').strip()
            if not nom_classe:
                flash("Nom de classe requis.", "error")
            elif Classe.query.filter_by(nom=nom_classe).first():
                flash("Classe deja existante.", "error")
            else:
                c = Classe(nom=nom_classe)
                db.session.add(c)
                db.session.commit()
                flash(f"Classe {nom_classe} creee.", "success")

        # assigner etudiant a une classe
        elif action == 'assigner_classe':
            user_id = request.form.get('user_id')
            classe_id = request.form.get('classe_id')
            if user_id and classe_id:
                u = User.query.get(int(user_id))
                if u:
                    u.classe_id = int(classe_id)
                    db.session.commit()
                    flash(f"{u.prenom} {u.nom} assigne.", "success")

        # ajouter un cours
        elif action == 'ajouter_cours':
            classe_id = request.form.get('classe_id')
            prof_id = request.form.get('professeur_id')
            matiere = request.form.get('matiere', '').strip()
            jour = request.form.get('jour', '')
            debut = request.form.get('start_time', '')
            fin = request.form.get('end_time', '')

            if classe_id and prof_id and matiere and jour and debut and fin:
                cours = Cours(
                    classe_id=int(classe_id),
                    professeur_id=int(prof_id),
                    matiere=matiere,
                    jour=jour,
                    start_time=debut,
                    end_time=fin
                )
                db.session.add(cours)
                db.session.commit()
                flash("Cours ajoute.", "success")
            else:
                flash("Tous les champs du cours sont requis.", "error")

        # supprimer un utilisateur
        elif action == 'supprimer_user':
            user_id = request.form.get('user_id')
            if user_id:
                u = User.query.get(int(user_id))
                if u and u.username != 'admin':
                    db.session.delete(u)
                    db.session.commit()
                    flash("Utilisateur supprime.", "success")
                else:
                    flash("Impossible de supprimer cet utilisateur.", "error")

        return redirect(url_for('admin_users'))

    users = User.query.all()
    classes = Classe.query.all()
    professeurs = User.query.filter_by(role='professeur').all()
    etudiants = User.query.filter_by(role='etudiant').all()
    cours_liste = Cours.query.all()
    return render_template('admin/users.html', users=users, classes=classes, professeurs=professeurs, etudiants=etudiants, cours_liste=cours_liste)


# ==========================================
# LANCEMENT LOCAL
# ==========================================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # compte admin par defaut
        if not User.query.filter_by(username='admin').first():
            hashed = bcrypt.generate_password_hash('admin').decode('utf-8')
            admin = User(username='admin', password=hashed, role='admin', nom='Systeme', prenom='Admin')
            db.session.add(admin)
            db.session.commit()
            print(">>> Compte admin cree (admin/admin)")
    print(">>> App lancee sur http://127.0.0.1:5000")
    app.run(debug=True, use_reloader=False)
