from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime,timedelta

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///library.db'
app.config['SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'student' or 'admin'
    seat_number = db.Column(db.String(50), nullable=True)  

class LibraryRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # 'pending', 'approved', 'rejected'
    seat_number = db.Column(db.Integer, nullable=True)
    date_of_joining = db.Column(db.DateTime, nullable=True)

class FeeStatus(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    paid = db.Column(db.Boolean, default=False)
    fee_update_requested = db.Column(db.Boolean, default=False)
    fee_approved_at = db.Column(db.DateTime, nullable=True)
    next_fee_due = db.Column(db.DateTime, nullable=True)  # New field


class FeeApprovalHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    approved_at = db.Column(db.DateTime, default=datetime.utcnow)

    student = db.relationship('User', backref=db.backref('fee_history', lazy=True))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')

        if not username or not password or not role:
            flash('All fields are required', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))

        new_user = User(username=username, password_hash=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Username and Password are required', 'danger')
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('admin_dashboard') if user.role == 'admin' else url_for('student_dashboard'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('home'))

    pending_requests = LibraryRequest.query.filter_by(status='pending').all()
    fee_update_requests = FeeStatus.query.filter_by(fee_update_requested=True).all()
    return render_template('admin_dashboard.html', 
                           pending_requests=pending_requests, 
                           fee_update_requests=fee_update_requests)

@app.route('/student/dashboard')
@login_required
def student_dashboard():
    student_id = current_user.id
    library_request = LibraryRequest.query.filter_by(student_id=student_id).first()
    fee_status = FeeStatus.query.filter_by(student_id=student_id).first()
    fee_history = FeeApprovalHistory.query.filter_by(student_id=student_id).order_by(FeeApprovalHistory.approved_at.desc()).all()

    return render_template('student_dashboard.html',  
                           student_id=student_id,
                           library_request=library_request,
                           fee_status=fee_status,
                           fee_history=fee_history,
                           current_time=datetime.now()) 


@app.route('/request/library', methods=['POST'])
@login_required
def request_library():
    student_id = current_user.id

    if LibraryRequest.query.filter_by(student_id=student_id).first():
        flash('You already have a pending request', 'warning')
        return redirect(url_for('student_dashboard'))

    new_request = LibraryRequest(student_id=student_id)
    db.session.add(new_request)
    db.session.commit()
    flash('Library request submitted', 'success')
    return redirect(url_for('student_dashboard'))

@app.route('/update/fee', methods=['POST'])
@login_required
def update_fee():
    student_id = current_user.id
    fee_status = FeeStatus.query.filter_by(student_id=student_id).first()

    if not fee_status:
        fee_status = FeeStatus(student_id=student_id, fee_update_requested=True)
        db.session.add(fee_status)
    else:
        fee_status.fee_update_requested = True

    db.session.commit()
    flash('Fee status update requested.', 'success')
    return redirect(url_for('student_dashboard'))

# @app.route('/admin/approve_library/<int:request_id>', methods=['POST'])
# @login_required
# def approve_library(request_id):
#     if current_user.role != 'admin':
#         flash('Unauthorized access!', 'danger')
#         return redirect(url_for('home'))

#     req = LibraryRequest.query.get(request_id)
#     if not req:
#         flash('Request not found.', 'danger')
#         return redirect(url_for('admin_dashboard'))

#     seat_number = request.form.get('seat_number')
#     if User.query.filter_by(seat_number=seat_number).first():
#         flash('Seat already assigned to another student.', 'danger')
#         return redirect(url_for('admin_dashboard'))

#     if not seat_number or not seat_number.isdigit():
#         flash('Valid seat number is required.', 'danger')
#         return redirect(url_for('admin_dashboard'))

#     # Assign seat number to the student
#     student = User.query.get(req.student_id)
#     student.seat_number = seat_number
#     req.status = 'approved'
#     req.date_of_joining = datetime.now()
    
#     db.session.commit()
#     flash('Library request approved and seat assigned.', 'success')
#     return redirect(url_for('admin_dashboard'))
@app.route('/admin/approve_library/<int:request_id>', methods=['POST'])
@login_required
def approve_library(request_id):
    if current_user.role != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('home'))

    req = LibraryRequest.query.get(request_id)
    if not req:
        flash('Request not found.', 'danger')
        return redirect(url_for('admin_dashboard'))

    seat_number = request.form.get('seat_number')
    if User.query.filter_by(seat_number=seat_number).first():
        flash('Seat already assigned to another student.', 'danger')
        return redirect(url_for('admin_dashboard'))

    if not seat_number or not seat_number.isdigit():
        flash('Valid seat number is required.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Assign seat number to the student
    student = User.query.get(req.student_id)

    if student:
        student.seat_number = seat_number  # ✅ Update seat number
        db.session.commit()  # ✅ Commit the update
    seat_allocation = LibraryRequest.query.filter_by(student_id=req.student_id).first()
    if seat_allocation:
      seat_allocation.seat_number = seat_number  # ✅ Correct assignment
      db.session.commit()

    req.status = 'approved'
    req.date_of_joining = datetime.now()
    
    db.session.commit()
    flash('Library request approved and seat assigned.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/approve_fee_status/<int:fee_id>', methods=['POST'])
@login_required
def approve_fee_status(fee_id):
    if current_user.role != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('home'))

    fee_status = FeeStatus.query.get(fee_id)
    if not fee_status:
        flash('Fee status record not found.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Mark the fee as paid
    fee_status.paid = True
    fee_status.fee_approved_at = datetime.now()
    fee_status.fee_update_requested = False

    # Set the next fee update to one month later
    fee_status.next_fee_due = datetime.now() + timedelta(minutes=1)
    
    db.session.commit()
    flash('Fee status updated successfully', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/remove_student', methods=['POST'])
@login_required
def remove_student():
    if current_user.role != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('home'))

    student_id = request.form.get('student_id')
    if not student_id or not student_id.isdigit():
        flash('Valid Student ID is required.', 'danger')
        return redirect(url_for('admin_dashboard'))

    student = User.query.get(int(student_id))
    if not student:
        flash('Student not found.', 'danger')
        return redirect(url_for('admin_dashboard'))

    LibraryRequest.query.filter_by(student_id=student_id).delete()
    FeeStatus.query.filter_by(student_id=student_id).delete()
    db.session.delete(student)
    db.session.commit()
    flash('Student removed successfully', 'success')
    return redirect(url_for('admin_dashboard'))
@app.route('/admin/approve_fee_history/<int:student_id>', methods=['POST'])
@login_required
def approve_fee_history(student_id):
    if current_user.role != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('home'))

    # Log the fee approval in history
    fee_history = FeeApprovalHistory(student_id=student_id)
    db.session.add(fee_history)
    db.session.commit()

    flash('Fee approval recorded in history', 'success')
    return redirect(url_for('admin_dashboard'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
