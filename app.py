from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import mysql.connector
from mysql.connector import Error
import bcrypt
from functools import wraps
from datetime import timedelta
from flask_mail import Mail, Message
import os
import re
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime, timedelta
import secrets
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


def generate_secure_token():
    return secrets.token_urlsafe(32)


dotenv_path = os.path.join(os.path.dirname(__file__), '.idea/.env')
load_dotenv(dotenv_path)


app = Flask(__name__)

app.secret_key = 'dein_geheimer_schlüssel'  # Ersetze dies durch einen sicheren Schlüssel

# Flask-Mail konfigurieren
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEBUG'] = True
app.config['MAIL_DEFAULT_SENDER'] = 'lenasappointmentcalendar@gmail.com'  # Ersetzen Sie mit Ihrer Gmail-Adresse

mail = Mail(app)

app.secret_key = 'dein_geheimer_schlüssel'  # Ersetze durch einen sicheren Schlüssel
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Sitzungslaufzeit

def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

@app.route('/routes')
def list_routes():
    from flask import jsonify
    routes = {rule.endpoint: rule.rule for rule in app.url_map.iter_rules()}
    return jsonify(routes)


# Middleware: Prüft, ob ein Benutzer angemeldet ist
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:  # Prüfen, ob die Sitzung aktiv ist
            return redirect(url_for('login'))  # Weiterleitung zur Login-Seite
        return f(*args, **kwargs)
    return decorated_function

# Verbindung zur MySQL-Datenbank herstellen
def create_connection():
    try:
        connection = mysql.connector.connect(
            host="sql7.freesqldatabase.com",           # Hostname (z.B. localhost)
            user="sql7751854",   # MySQL-Benutzername
            password="3E6mHi2PwD",   # MySQL-Passwort
            database="sql7751854",  # Name der Datenbank
            ssl_disabled = True    #Übergangslösung
        )
        if connection.is_connected():
            print("Verbindung erfolgreich!")
            return connection
    except Error as e:
        print(f"Fehler: {e}")
        return None

# Verbindung beenden
def close_connection(connection):
    if connection.is_connected():
        connection.close()
        print("Verbindung geschlossen.")

@app.route("/")
def show_calendar():
    if 'user_id' in session:  # Prüfe, ob der Benutzer angemeldet ist
        username = session['username']
        return render_template("calendar.html", username=username, logged_in=True)
    else:
        return render_template("calendar.html", logged_in=False)


@app.route("/get_events")
def get_events():
    connection = create_connection()
    events = []
    if connection:
        try:
            cursor = connection.cursor()

            # Allgemeine Ereignisse
            query = "SELECT calendar_id, date, time_slot, is_available FROM calendar ORDER BY date, time_slot"
            cursor.execute(query)
            rows = cursor.fetchall()
            for row in rows:
                calendar_id, date, time_slot, is_available = row
                if is_available:
                    print(f"Allgemeiner Eintrag: ID=calendar-{calendar_id}")  # Debug
                    events.append({
                        "id": f"calendar-{calendar_id}",
                        "title": "Termin verfügbar",
                        "start": f"{date}T{time_slot}",
                        "color": "green"
                    })

            # Benutzertermine
            query = "SELECT appointment_id, date, time_slot, title FROM appointments WHERE status = 'confirmed'"
            cursor.execute(query)
            rows = cursor.fetchall()
            for row in rows:
                appointment_id, date, time_slot, title = row
                print(f"Benutzertermin: ID={appointment_id}, Datum={date}, Zeit={time_slot}")  # Debug
                events.append({
                    "id": str(appointment_id),  # ID muss rein numerisch bleiben
                    "title": title,
                    "start": f"{date}T{time_slot}",
                    "color": "blue"
                })
        except Error as e:
            print(f"Fehler beim Abrufen der Daten: {e}")
        finally:
            close_connection(connection)
    return jsonify(events)


# Route für die Anmeldeseite
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        connection = create_connection()
        if connection:
            try:
                cursor = connection.cursor()
                query = "SELECT user_id, username, password_hash FROM users WHERE email = %s"
                cursor.execute(query, (email,))
                user = cursor.fetchone()

                if user:
                    user_id, username, hashed_password = user
                    # Passwort überprüfen
                    if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
                        # Sitzung starten
                        session['user_id'] = user_id
                        session['username'] = username
                        print(f"Willkommen, {username}!")
                        return redirect(url_for("show_calendar"))
                    else:
                        return "Ungültige Anmeldedaten", 401
                else:
                    return "Ungültige Anmeldedaten", 401
            except Error as e:
                print(f"Fehler beim Login: {e}")
                return "Fehler beim Login", 500
            finally:
                close_connection(connection)
    return render_template("login.html")

# Route für die Registrierungsseite
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        connection = create_connection()
        if connection:
            try:
                cursor = connection.cursor()
                query = "INSERT INTO users (username, email, password_hash, role) VALUES (%s, %s, %s, %s)"
                cursor.execute(query, (username, email, hashed_password.decode('utf-8'), 'user'))
                connection.commit()

                print(f"Benutzer {username} erfolgreich registriert!")

                # HTML-Bestätigungs-E-Mail senden
                subject = "Erfolgreiche Registrierung"
                context = {"username": username}
                send_email(subject, email, template='email_template.html', context=context)

                return redirect(url_for("show_calendar"))
            except Error as e:
                print(f"Fehler bei der Registrierung: {e}")
                return "Fehler bei der Registrierung", 500
            finally:
                close_connection(connection)
    return render_template("register.html")


def send_email(subject, recipient, body_text=None, template=None, context=None):
    """
    Versendet eine E-Mail mit Text- oder HTML-Inhalt.
    """
    try:
        print(f"Versuche, eine E-Mail zu senden an: {recipient}")  # Debug-Ausgabe
        print(f"Betreff: {subject}")

        msg = Message(subject, recipients=[recipient])

        if body_text:
            msg.body = body_text

        if template:
            # HTML-Vorlage rendern und als HTML-E-Mail anhängen
            if not context:
                context = {}

            # Kontext erweitern, um die URL für statische Dateien zu unterstützen
            context['static_url'] = url_for('static', filename='', _external=True)
            print(f"Verwende Template: {template}")  # Debug-Ausgabe
            msg.html = render_template(template, **context)

        mail.send(msg)
        print(f"E-Mail an {recipient} gesendet.")
    except Exception as e:
        print(f"Fehler beim Versenden der E-Mail: {e}")


@app.route("/logout")
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    print("Sitzung beendet.")
    return redirect(url_for("show_calendar"))


@app.route("/add_appointment", methods=["POST"])
@login_required
def add_appointment():
    try:
        # JSON-Daten aus der Anfrage auslesen
        data = request.json
        print(f"Empfangene Daten: {data}")  # Debug

        user_id = session['user_id']
        date = data.get("date")
        time_slot = data.get("time_slot")
        title = data.get("title")

        # Prüfen, ob alle benötigten Felder vorhanden sind
        if not date or not time_slot or not title:
            print("Fehlende Daten: Datum, Zeitfenster oder Titel fehlen.")
            return jsonify({"success": False, "message": "Fehlende Daten."}), 400

        connection = create_connection()
        if connection:
            try:
                cursor = connection.cursor()

                # Überprüfen, ob der Termin für den Benutzer bereits existiert
                cursor.execute("""
                    SELECT appointment_id FROM appointments 
                    WHERE user_id = %s AND date = %s AND time_slot = %s
                """, (user_id, date, time_slot))
                existing_appointment = cursor.fetchone()

                if existing_appointment:
                    return jsonify({"success": False, "message": "Termin existiert bereits."}), 400

                # Termin in die Datenbank einfügen
                query = """
                    INSERT INTO appointments (user_id, date, time_slot, title) 
                    VALUES (%s, %s, %s, %s)
                """
                cursor.execute(query, (user_id, date, time_slot, title))
                connection.commit()
                print(f"Termin gebucht: {date} {time_slot} für Benutzer {user_id}")
                return jsonify({"success": True, "message": "Termin erfolgreich gebucht!"}), 200
            except Error as e:
                print(f"SQL-Fehler: {e}")
                return jsonify({"success": False, "message": "Fehler beim Speichern des Termins."}), 500
            finally:
                close_connection(connection)
        else:
            print("Keine Verbindung zur Datenbank.")
            return jsonify({"success": False, "message": "Datenbankverbindung fehlgeschlagen."}), 500
    except Exception as e:
        print(f"Allgemeiner Fehler: {e}")
        return jsonify({"success": False, "message": "Fehler beim Verarbeiten der Anfrage."}), 500


@app.route("/cancel_appointment", methods=["POST"])
@login_required
def cancel_appointment():
    try:
        data = request.json
        appointment_id = data.get("appointment_id")

        print(f"Empfangene Termin-ID: {appointment_id}")  # Debug

        # Nur numerische IDs zulassen (für Benutzertermine)
        if not appointment_id or not str(appointment_id).isdigit():
            print(f"Ungültige Termin-ID: {appointment_id}")  # Debug
            return jsonify({"success": False, "message": "Ungültige Termin-ID."}), 400

        connection = create_connection()
        if connection:
            try:
                cursor = connection.cursor()

                # Termin aus der Datenbank löschen
                query = "DELETE FROM appointments WHERE appointment_id = %s AND user_id = %s"
                print(f"SQL-Abfrage: {query} mit Werten: {appointment_id}, {session['user_id']}")  # Debug
                cursor.execute(query, (appointment_id, session['user_id']))
                connection.commit()

                if cursor.rowcount > 0:
                    print(f"Termin mit ID {appointment_id} erfolgreich gelöscht.")  # Debug
                    return jsonify({"success": True, "message": "Termin erfolgreich gelöscht."}), 200
                else:
                    print(f"Termin mit ID {appointment_id} konnte nicht gefunden werden.")  # Debug
                    return jsonify({"success": False, "message": "Termin konnte nicht gelöscht werden."}), 404
            except Error as e:
                print(f"SQL-Fehler beim Löschen: {e}")  # Debug
                return jsonify({"success": False, "message": "Fehler beim Löschen des Termins."}), 500
            finally:
                close_connection(connection)
        else:
            print("Keine Verbindung zur Datenbank.")  # Debug
            return jsonify({"success": False, "message": "Datenbankverbindung fehlgeschlagen."}), 500
    except Exception as e:
        print(f"Allgemeiner Fehler: {e}")  # Debug
        return jsonify({"success": False, "message": "Fehler beim Verarbeiten der Anfrage."}), 500


@app.route('/send_test_email')
def send_test_email():
    try:
        msg = Message("Test-E-Mail", recipients=["test@example.com"])
        msg.body = "Dies ist eine Test-E-Mail von Ihrer Flask-Anwendung."
        mail.send(msg)
        return "E-Mail erfolgreich gesendet!"
    except Exception as e:
        print(f"Fehler beim Senden der E-Mail: {e}")
        return "E-Mail konnte nicht gesendet werden.", 500

@app.route('/test_email_template')
def test_email_template():
    try:
        return render_template('email_template.html', username="TestUser")
    except Exception as e:
        print(f"Fehler beim Rendern des Templates: {e}")
        return f"Fehler: {e}", 500

@app.route("/versionen")
def versionen():
    return render_template("versionen.html")


limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://"  # Für Entwicklung: Nutze "redis://localhost:6379" in Produktion
)

@app.route("/forgot_password", methods=["GET", "POST"])
@limiter.limit("5 per hour")  # Limit für Passwort-Zurücksetzen
def forgot_password():
    message = None  # Standard-Nachricht ist leer
    if request.method == "POST":
        email = request.form.get("email")
        connection = create_connection()
        if connection:
            try:
                cursor = connection.cursor()
                query = "SELECT user_id FROM users WHERE email = %s"
                cursor.execute(query, (email,))
                user = cursor.fetchone()

                if user:
                    token = generate_reset_token(email)
                    expiry_time = datetime.now() + timedelta(hours=1)

                    # Token in die Datenbank speichern
                    cursor.execute(
                        "UPDATE users SET reset_token = %s, token_expiry = %s WHERE email = %s",
                        (token, expiry_time, email)
                    )
                    connection.commit()

                    # Sende E-Mail
                    reset_url = url_for('reset_password', token=token, _external=True)
                    send_email(
                        subject="Passwort zurücksetzen",
                        recipient=email,
                        body_text=f"Klicken Sie auf den folgenden Link, um Ihr Passwort zurückzusetzen: {reset_url}"
                    )

                    message = {"type": "success", "text": "E-Mail zum Zurücksetzen des Passworts wurde gesendet."}
                else:
                    message = {"type": "error", "text": "E-Mail wurde nicht gefunden."}
            except Exception as e:
                print(f"Fehler: {e}")
                message = {"type": "error", "text": "Serverfehler. Bitte versuchen Sie es später erneut."}
            finally:
                close_connection(connection)
        else:
            message = {"type": "error", "text": "Datenbankverbindung fehlgeschlagen."}

    return render_template("forgot_password.html", message=message)


@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    email = validate_reset_token(token)  # Token validieren
    if not email:
        # Abgelaufener oder ungültiger Token
        return render_template("reset_password.html", message={
            "type": "error",
            "text": "Der Token ist ungültig oder abgelaufen. Bitte fordern Sie einen neuen Link an."
        })

    message = None  # Nachricht für Erfolg oder Fehler
    if request.method == "POST":
        # Passwort aus dem Formular abrufen
        new_password = request.form.get("password")

        # Validierung: Überprüfen, ob das Passwort leer ist
        if not new_password:
            message = {"type": "error", "text": "Passwort darf nicht leer sein."}
        else:
            # Passwort hashen
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

            # Verbindung zur Datenbank herstellen
            connection = create_connection()
            if connection:
                try:
                    cursor = connection.cursor()
                    query = """
                        UPDATE users SET password_hash = %s, reset_token = NULL, token_expiry = NULL WHERE email = %s
                    """
                    cursor.execute(query, (hashed_password.decode('utf-8'), email))
                    connection.commit()

                    # Erfolgsmeldung setzen
                    message = {"type": "success", "text": "Passwort erfolgreich zurückgesetzt. Sie können sich jetzt anmelden."}
                except Exception as e:
                    print(f"Fehler bei der Datenbankabfrage: {e}")
                    message = {"type": "error", "text": "Fehler beim Speichern des Passworts. Bitte versuchen Sie es später erneut."}
                finally:
                    close_connection(connection)

    return render_template("reset_password.html", message=message)



# Token-Handling Funktionen
def generate_reset_token(email):
    serializer = URLSafeTimedSerializer(app.secret_key)
    return serializer.dumps(email, salt='password-reset-salt')

def validate_reset_token(token, expiration=900):  # 15 Minuten = 900 Sekunden
    serializer = URLSafeTimedSerializer(app.secret_key)
    try:
        email = serializer.loads(
            token,
            salt='password-reset-salt',
            max_age=expiration  # Ablaufzeit in Sekunden
        )
        return email
    except Exception as e:
        print(f"Token-Validierungsfehler: {e}")
        return None


# Anwendung starten
if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5001)