from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from models.database import db, User, UserBehaviourProfile
from modules.authentication import admin_required, log_audit_event
from modules.behaviour_profiler import BehaviourProfiler

user_bp = Blueprint('user', __name__)

@user_bp.route('/users')
@login_required
@admin_required
def list_users():
    users = User.query.order_by(User.id.asc()).all()
    return render_template('users.html', users=users)

@user_bp.route('/users/add', methods=['POST'])
@login_required
@admin_required
def add_user():
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '').strip()
    role = request.form.get('role', 'user').strip()
    department = request.form.get('department', 'General').strip()

    if not username or not email or not password:
        flash('Username, email, and password are required.', 'danger')
        return redirect(url_for('user.list_users'))

    if User.query.filter_by(username=username).first():
        flash(f'Username "{username}" already exists.', 'danger')
        return redirect(url_for('user.list_users'))

    if User.query.filter_by(email=email).first():
        flash(f'Email "{email}" already registered.', 'danger')
        return redirect(url_for('user.list_users'))

    new_user = User(
        username=username,
        email=email,
        role=role,
        department=department,
        is_active=True
    )
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()

    # Generate initial behavioral baseline profile
    BehaviourProfiler.get_or_create_profile(new_user.id)

    log_audit_event('USER_CREATED', f'New user {username} ({role}) created by {current_user.username}.')
    flash(f'User "{username}" successfully provisioned with behavioral profile baseline.', 'success')
    return redirect(url_for('user.list_users'))

@user_bp.route('/users/<int:user_id>/toggle-status', methods=['POST'])
@login_required
@admin_required
def toggle_status(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('user.list_users'))
    if user.id == current_user.id:
        flash('You cannot deactivate your own administrative account.', 'warning')
        return redirect(url_for('user.list_users'))

    user.is_active = not user.is_active
    db.session.commit()

    action = 'ACCOUNT_ACTIVATED' if user.is_active else 'ACCOUNT_DEACTIVATED'
    log_audit_event(action, f'Account status of {user.username} changed to {user.is_active} by {current_user.username}.')
    flash(f'Account for {user.username} is now {"Active" if user.is_active else "Deactivated"}.', 'info')
    return redirect(url_for('user.list_users'))

@user_bp.route('/users/<int:user_id>/unlock', methods=['POST'])
@login_required
@admin_required
def unlock_account(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('user.list_users'))

    user.is_locked = False
    user.lock_reason = None
    user.locked_at = None
    db.session.commit()

    log_audit_event('ACCOUNT_UNLOCKED_BY_ADMIN', f'Account for {user.username} unlocked by administrator {current_user.username}.')
    flash(f'Account for {user.username} has been successfully unlocked and restored.', 'success')
    return redirect(url_for('user.list_users'))

@user_bp.route('/users/<int:user_id>/lock-baseline', methods=['POST'])
@login_required
@admin_required
def toggle_baseline_lock(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('user.list_users'))
    profile = BehaviourProfiler.get_or_create_profile(user.id)
    
    profile.is_baseline_locked = not profile.is_baseline_locked
    db.session.commit()

    status_str = "LOCKED (Protected against contamination)" if profile.is_baseline_locked else "UNLOCKED (Continuous learning active)"
    log_audit_event(
        'BASELINE_LOCK_TOGGLED',
        f'Baseline profile for {user.username} {status_str} by {current_user.username}.'
    )
    flash(f'Baseline profile for {user.username} is now {status_str}.', 'info')
    return redirect(url_for('user.list_users'))

@user_bp.route('/users/<int:user_id>/profile-data')
@login_required
def get_user_profile(user_id):
    user = db.session.get(User, user_id)
    if not user:
        return {'error': 'User not found'}, 404
    profile = BehaviourProfiler.get_or_create_profile(user.id)
    return jsonify({
        'user': user.to_dict(),
        'profile': profile.to_dict()
    })
