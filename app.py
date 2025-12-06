from flask import Flask, render_template, request, redirect, url_for, session
from config import get_db_conn
from hospital_db_setup import encrypt_data, decrypt_data
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # For session management


# Context processor to make is_logged_in available to all templates
@app.context_processor
def inject_user():
    return dict(is_logged_in=session.get('logged_in', False))


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        
        # Check if patient exists by email (email is encrypted, so we need to decrypt and compare)
        try:
            conn = get_db_conn()
            cur = conn.cursor()
            # Get all patients and decrypt emails to find match
            cur.execute("SELECT patient_id, email FROM Patient")
            patients = cur.fetchall()
            
            # Find patient with matching email
            patient_id = None
            error_details = []
            for p in patients:
                try:
                    if p[1] is None:  # Skip if email is NULL
                        continue
                    # Decrypt email and compare
                    decrypted_email = decrypt_data(p[1]).strip().lower()
                    print(f"Debug - Patient {p[0]}: Decrypted email = '{decrypted_email}', Looking for = '{email}'")
                    if decrypted_email == email:
                        patient_id = p[0]
                        print(f"Debug - Match found! Patient ID: {patient_id}")
                        break
                except Exception as e:
                    # If decryption fails, skip this patient
                    error_msg = f"Patient {p[0]}: {str(e)}"
                    print(f"Debug - {error_msg}")
                    error_details.append(error_msg)
                    continue
            
            if not patient_id and error_details:
                print(f"Debug - All decryption errors: {error_details}")
            
            cur.close()
            conn.close()
            
            if patient_id:
                session['logged_in'] = True
                session['patient_id'] = patient_id
                session['email'] = email
                return redirect(url_for("index"))
            else:
                return render_template("login.html", error="Email not found. Please register first.")
        except Exception as e:
            print(f"Login error: {e}")  # Debug
            return render_template("login.html", error=f"Error: {e}")
    
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/patient", methods=["GET", "POST"])
def patient_form():
    if request.method == "POST":
        try:
            # Read form fields
            full_name = request.form.get("full_name", "").strip()
            dob = request.form.get("dob", "").strip()
            email = request.form.get("email", "").strip()
            phone = request.form.get("phone", "").strip()
            mrn = request.form.get("mrn", "").strip()
            diagnosis = request.form.get("diagnosis", "").strip()
            card = request.form.get("card", "").strip()
            amount = request.form.get("amount", "").strip()

            # Basic server-side validation
            if len(full_name) < 2 or "@" not in email or len(mrn) < 3 or len(card) < 4:
                return "Invalid input", 400

            # Split full_name into first_name and last_name
            name_parts = full_name.split(maxsplit=1)
            first_name = name_parts[0] if name_parts else ""
            last_name = name_parts[1] if len(name_parts) > 1 else ""

            # Connect to DB
            conn = get_db_conn()
            cur = conn.cursor()

            # Encrypt sensitive fields
            encrypted_email = encrypt_data(email)
            encrypted_phone = encrypt_data(phone)

            # 1) Store in Patient table (matching existing database schema)
            cur.execute(
                """
                INSERT INTO Patient (first_name, last_name, dob, gender, phone_number, email, ssn, state_id, primary_doctor_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (first_name, last_name, dob, "Unknown", encrypted_phone, encrypted_email, encrypt_data(""), encrypt_data(""), None),
            )
            patient_id = cur.lastrowid

            # 2) Store encrypted diagnosis in Medical_Record
            encrypted_diagnosis = encrypt_data(diagnosis)
            cur.execute(
                """
                INSERT INTO Medical_Record (patient_id, doctor_id, diagnosis, treatment_plan)
                VALUES (%s, %s, %s, %s)
                """,
                (patient_id, None, encrypted_diagnosis, encrypt_data("")),
            )

            # 3) Store billing info in Billing table
            cur.execute(
                """
                INSERT INTO Billing (patient_id, total_amount, status)
                VALUES (%s, %s, %s)
                """,
                (patient_id, amount, "Pending"),
            )
            billing_id = cur.lastrowid

            # 4) Store encrypted card data in Payment table
            encrypted_card = encrypt_data(card)
            cur.execute(
                """
                INSERT INTO Payment (billing_id, payment_amount, payment_date, payment_method, transaction_id)
                VALUES (%s, %s, NOW(), %s, %s)
                """,
                (billing_id, amount, encrypted_card, encrypt_data("")),
            )

            conn.commit()
            cur.close()
            conn.close()

            # Auto-login after registration
            session['logged_in'] = True
            session['patient_id'] = patient_id
            
            # Redirect to the nice success page
            return redirect(url_for("success"))

        except Exception as e:
            # Helpful for debugging & assignment explanation
            print("ERROR IN POST /:", repr(e))
            return f"Error while saving to DB: {e}", 500

    # GET: show the secure intake form
    return render_template("patient_form.html")


@app.route("/staff", methods=["GET", "POST"])
def staff_form():
    if request.method == "POST":
        try:
            conn = get_db_conn()
            cur = conn.cursor()
            
            encrypted_email = encrypt_data(request.form.get("email", ""))
            encrypted_phone = encrypt_data(request.form.get("phone_number", ""))
            
            cur.execute(
                """INSERT INTO Staff (first_name, last_name, role, email, phone_number)
                   VALUES (%s, %s, %s, %s, %s)""",
                (request.form.get("first_name"), request.form.get("last_name"), 
                 request.form.get("role"), encrypted_email, encrypted_phone)
            )
            conn.commit()
            cur.close()
            conn.close()
            return redirect(url_for("success", message="Staff registered successfully!"))
        except Exception as e:
            return f"Error: {e}", 500
    
    return render_template("form.html",
        form_title="Staff Registration",
        form_subtitle="Register a new staff member",
        form_action="/staff",
        submit_button_text="Register Staff",
        form_fields=[
            {'name': 'first_name', 'label': 'First Name', 'type': 'text', 'required': True, 'row': True},
            {'name': 'last_name', 'label': 'Last Name', 'type': 'text', 'required': True, 'row': True},
            {'name': 'role', 'label': 'Role', 'type': 'select', 'required': True,
             'options': [
                 {'value': '', 'label': 'Select Role'},
                 {'value': 'Doctor', 'label': 'Doctor'},
                 {'value': 'Nurse', 'label': 'Nurse'},
                 {'value': 'Administrator', 'label': 'Administrator'},
                 {'value': 'Receptionist', 'label': 'Receptionist'},
                 {'value': 'Technician', 'label': 'Technician'},
                 {'value': 'Other', 'label': 'Other'}
             ]},
            {'name': 'email', 'label': 'Email Address', 'type': 'email', 'required': True},
            {'name': 'phone_number', 'label': 'Phone Number', 'type': 'tel', 'required': True}
        ])


@app.route("/appointment", methods=["GET", "POST"])
def appointment_form():
    if not session.get('logged_in', False):
        return redirect(url_for("login"))
    
    if request.method == "POST":
        try:
            conn = get_db_conn()
            cur = conn.cursor()
            
            cur.execute(
                """INSERT INTO Appointment (patient_id, doctor_id, appointment_date, status)
                   VALUES (%s, %s, %s, %s)""",
                (request.form.get("patient_id"), request.form.get("doctor_id"),
                 request.form.get("appointment_date"), request.form.get("status", "Scheduled"))
            )
            conn.commit()
            cur.close()
            conn.close()
            return redirect(url_for("success", message="Appointment booked successfully!"))
        except Exception as e:
            return f"Error: {e}", 500
    
    return render_template("form.html",
        form_title="Book Appointment",
        form_subtitle="Schedule a new appointment",
        form_action="/appointment",
        submit_button_text="Book Appointment",
        form_fields=[
            {'name': 'patient_id', 'label': 'Patient ID', 'type': 'text', 'required': True, 'placeholder': 'Enter Patient ID'},
            {'name': 'doctor_id', 'label': 'Doctor ID', 'type': 'text', 'required': True, 'placeholder': 'Enter Staff/Doctor ID'},
            {'name': 'appointment_date', 'label': 'Appointment Date & Time', 'type': 'datetime-local', 'required': True},
            {'name': 'status', 'label': 'Status', 'type': 'select', 'required': False,
             'options': [
                 {'value': 'Scheduled', 'label': 'Scheduled', 'selected': True},
                 {'value': 'Confirmed', 'label': 'Confirmed'},
                 {'value': 'Cancelled', 'label': 'Cancelled'},
                 {'value': 'Completed', 'label': 'Completed'}
             ]}
        ])


@app.route("/medical-record", methods=["GET", "POST"])
def medical_record_form():
    if not session.get('logged_in', False):
        return redirect(url_for("login"))
    
    if request.method == "POST":
        try:
            conn = get_db_conn()
            cur = conn.cursor()
            
            encrypted_diagnosis = encrypt_data(request.form.get("diagnosis", ""))
            encrypted_treatment = encrypt_data(request.form.get("treatment_plan", ""))
            
            cur.execute(
                """INSERT INTO Medical_Record (patient_id, doctor_id, diagnosis, treatment_plan)
                   VALUES (%s, %s, %s, %s)""",
                (request.form.get("patient_id"), request.form.get("doctor_id"),
                 encrypted_diagnosis, encrypted_treatment)
            )
            conn.commit()
            cur.close()
            conn.close()
            return redirect(url_for("success", message="Medical record saved successfully!"))
        except Exception as e:
            return f"Error: {e}", 500
    
    return render_template("form.html",
        form_title="Medical Record",
        form_subtitle="Add a new medical record",
        form_action="/medical-record",
        submit_button_text="Save Medical Record",
        form_fields=[
            {'name': 'patient_id', 'label': 'Patient ID', 'type': 'text', 'required': True, 'placeholder': 'Enter Patient ID'},
            {'name': 'doctor_id', 'label': 'Doctor ID', 'type': 'text', 'required': True, 'placeholder': 'Enter Staff/Doctor ID'},
            {'name': 'diagnosis', 'label': 'Diagnosis', 'type': 'textarea', 'required': True, 'placeholder': 'Enter diagnosis details'},
            {'name': 'treatment_plan', 'label': 'Treatment Plan', 'type': 'textarea', 'required': True, 'placeholder': 'Enter treatment plan details'}
        ])


@app.route("/billing", methods=["GET", "POST"])
def billing_form():
    if not session.get('logged_in', False):
        return redirect(url_for("login"))
    
    if request.method == "POST":
        try:
            conn = get_db_conn()
            cur = conn.cursor()
            
            cur.execute(
                """INSERT INTO Billing (patient_id, total_amount, status, payment_due_date)
                   VALUES (%s, %s, %s, %s)""",
                (request.form.get("patient_id"), request.form.get("total_amount"),
                 request.form.get("status", "Pending"), request.form.get("payment_due_date") or None)
            )
            conn.commit()
            cur.close()
            conn.close()
            return redirect(url_for("success", message="Billing record created successfully!"))
        except Exception as e:
            return f"Error: {e}", 500
    
    return render_template("form.html",
        form_title="Billing",
        form_subtitle="Create a new billing record",
        form_action="/billing",
        submit_button_text="Create Billing Record",
        form_fields=[
            {'name': 'patient_id', 'label': 'Patient ID', 'type': 'text', 'required': True, 'placeholder': 'Enter Patient ID'},
            {'name': 'total_amount', 'label': 'Total Amount ($)', 'type': 'number', 'required': True, 'step': '0.01', 'min': '0', 'placeholder': '0.00'},
            {'name': 'status', 'label': 'Status', 'type': 'select', 'required': False,
             'options': [
                 {'value': 'Pending', 'label': 'Pending', 'selected': True},
                 {'value': 'Paid', 'label': 'Paid'},
                 {'value': 'Overdue', 'label': 'Overdue'},
                 {'value': 'Cancelled', 'label': 'Cancelled'}
             ]},
            {'name': 'payment_due_date', 'label': 'Payment Due Date', 'type': 'datetime-local', 'required': False}
        ])


@app.route("/payment", methods=["GET", "POST"])
def payment_form():
    if not session.get('logged_in', False):
        return redirect(url_for("login"))
    
    if request.method == "POST":
        try:
            conn = get_db_conn()
            cur = conn.cursor()
            
            encrypted_method = encrypt_data(request.form.get("payment_method", ""))
            encrypted_transaction = encrypt_data(request.form.get("transaction_id", ""))
            
            cur.execute(
                """INSERT INTO Payment (billing_id, payment_amount, payment_date, payment_method, transaction_id)
                   VALUES (%s, %s, %s, %s, %s)""",
                (request.form.get("billing_id"), request.form.get("payment_amount"),
                 request.form.get("payment_date"), encrypted_method, encrypted_transaction)
            )
            conn.commit()
            cur.close()
            conn.close()
            return redirect(url_for("success", message="Payment processed successfully!"))
        except Exception as e:
            return f"Error: {e}", 500
    
    return render_template("form.html",
        form_title="Payment Processing",
        form_subtitle="Process a payment for a billing record",
        form_action="/payment",
        submit_button_text="Process Payment",
        form_fields=[
            {'name': 'billing_id', 'label': 'Billing ID', 'type': 'text', 'required': True, 'placeholder': 'Enter Billing ID'},
            {'name': 'payment_amount', 'label': 'Payment Amount ($)', 'type': 'number', 'required': True, 'step': '0.01', 'min': '0', 'placeholder': '0.00'},
            {'name': 'payment_date', 'label': 'Payment Date', 'type': 'datetime-local', 'required': True},
            {'name': 'payment_method', 'label': 'Payment Method', 'type': 'text', 'required': True, 'placeholder': 'e.g., Credit Card, Debit Card, Cash'},
            {'name': 'transaction_id', 'label': 'Transaction ID', 'type': 'text', 'required': True, 'placeholder': 'Enter transaction ID'}
        ])


@app.route("/success")
def success():
    message = request.args.get("message", "Your information has been successfully submitted and securely stored in the system.")
    return render_template("success.html", success_message=message)


if __name__ == "__main__":
    # Debug on for development; mention in report this wouldn't be used in prod
    app.run(host="0.0.0.0", port=5000, debug=True)
