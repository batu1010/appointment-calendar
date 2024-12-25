from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import mysql.connector
from mysql.connector import Error
import bcrypt
from functools import wraps
from datetime import timedelta


app = Flask(__name__)
app.secret_key = 'dein_geheimer_schlüssel'  # Ersetze durch einen sicheren Schlüssel
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Sitzungslaufzeit

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
            database="sql7751854"  # Name der Datenbank
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
                return redirect(url_for("show_calendar"))
            except Error as e:
                print(f"Fehler bei der Registrierung: {e}")
                return "Fehler bei der Registrierung", 500
            finally:
                close_connection(connection)
    return render_template("register.html")

@app.route("/logout")
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    print("Sitzung beendet.")
    return redirect(url_for("show_calendar"))

# Middleware: Prüft, ob ein Benutzer angemeldet ist
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:  # Prüfen, ob die Sitzung aktiv ist
            return redirect(url_for('login'))  # Weiterleitung zur Login-Seite
        return f(*args, **kwargs)
    return decorated_function

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



# Anwendung starten
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5001)