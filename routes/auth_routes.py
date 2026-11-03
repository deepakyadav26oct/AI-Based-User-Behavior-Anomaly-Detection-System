from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from models.database import db, User, LoginActivity
from modules.activity_monitor import ActivityMonitor
from modules.authentication import log_audit_event

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.overview'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        remember = bool(request.form.get('remember', False))

        telemetry = ActivityMonitor.parse_client_telemetry(request)
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            if user.is_locked:
                flash(f'CRITICAL LOCKDOWN: Account is locked by Sentinel AI Active Threat Defense ({user.lock_reason or "Anomalous Threat Flagged"}). Contact SOC.', 'danger')
                return render_template('login.html')

            if not user.is_active:
                flash('Account is deactivated. Please contact Security Operations.', 'danger')
                return render_template('login.html')

            # Log verified login event through real-time activity monitor
            ActivityMonitor.record_and_evaluate(
                username=username,
                login_status='SUCCESS',
                ip_address=telemetry['ip_address'],
                device_info=telemetry['device_info'],
                browser=telemetry['browser'],
                operating_system=telemetry['operating_system'],
                accessed_resource='/dashboard',
                resource_sensitivity='LOW',
                failed_login_count=0,
                is_simulated=False,
                location='Internal Portal Ingress'
            )

            login_user(user, remember=remember)
            user.last_login_at = datetime.utcnow()
            db.session.commit()

            log_audit_event('USER_LOGIN_SUCCESS', f'User {username} authenticated successfully.', user=user)
            flash(f'Welcome back, {user.username}. Security session initialized.', 'success')

            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard.overview'))
        else:
            # Dynamic calculation of consecutive failed attempts within last 15 minutes
            recent_fails = 0
            if username:
                recent_fails = LoginActivity.query.filter(
                    LoginActivity.username == username,
                    LoginActivity.login_status == 'FAILED',
                    LoginActivity.timestamp >= datetime.utcnow() - timedelta(minutes=15)
                ).count()
            failed_streak = recent_fails + 1

            # Record failed login attempt in activity monitor & execute ML risk evaluation
            eval_result = ActivityMonitor.record_and_evaluate(
                username=username or 'unknown_principal',
                login_status='FAILED',
                ip_address=telemetry['ip_address'],
                device_info=telemetry['device_info'],
                browser=telemetry['browser'],
                operating_system=telemetry['operating_system'],
                accessed_resource='/login',
                resource_sensitivity='MEDIUM',
                failed_login_count=failed_streak,
                is_simulated=False,
                location='Internal Portal Ingress'
            )
            log_audit_event('USER_LOGIN_FAILED', f'Failed authentication attempt #{failed_streak} for username: {username}')

            # Check if active threat defense locked the user account
            if user and (user.is_locked or eval_result.get('account_locked')):
                flash(f'CRITICAL LOCKDOWN: Account has been locked by Sentinel AI Active Threat Defense ({user.lock_reason or "Brute Force Threshold Reached"}). Security incident dispatched to SOC.', 'danger')
            else:
                remaining = max(0, 5 - failed_streak)
                warning_note = f" (Attempt {failed_streak}/5 &bull; {remaining} attempts before automated SOAR lockdown)" if remaining > 0 else ""
                flash(f'Invalid credentials or unverified security parameters.{warning_note}', 'danger')

    return render_template('login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    username = current_user.username
    log_audit_event('USER_LOGOUT', f'User {username} terminated session.')
    logout_user()
    flash('You have been securely logged out.', 'info')
    return redirect(url_for('auth.login'))
