import os
from pathlib import Path
from datetime import datetime
from flask import Blueprint, render_template, send_from_directory, flash, redirect, url_for, abort
from flask_login import login_required, current_user
from config import Config
from modules.report_generator import SecurityReportGenerator
from modules.authentication import analyst_required, log_audit_event

report_bp = Blueprint('report', __name__)

@report_bp.route('/reports')
@login_required
@analyst_required
def reports_page():
    reports_dir = Path(Config.REPORTS_DIR)
    reports_dir.mkdir(parents=True, exist_ok=True)

    pdf_files = []
    for f in reports_dir.glob('*.pdf'):
        stat = f.stat()
        pdf_files.append({
            'filename': f.name,
            'size_kb': round(stat.st_size / 1024, 1),
            'created_at': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
            'path': str(f)
        })

    pdf_files.sort(key=lambda x: x['created_at'], reverse=True)

    return render_template(
        'reports.html',
        reports=pdf_files
    )

@report_bp.route('/reports/generate', methods=['POST'])
@login_required
@analyst_required
def generate_report():
    try:
        pdf_path = SecurityReportGenerator.generate_pdf_report()
        filename = Path(pdf_path).name
        log_audit_event('SECURITY_REPORT_GENERATED', f"Generated report: {filename} by {current_user.username}")
        flash(f'Security Audit PDF Report "{filename}" generated successfully!', 'success')
    except Exception as e:
        flash(f'Failed to generate PDF report: {e}', 'danger')

    return redirect(url_for('report.reports_page'))

@report_bp.route('/reports/download/<filename>')
@login_required
@analyst_required
def download_report(filename):
    # Sanitize filename
    safe_filename = Path(filename).name
    if not safe_filename.endswith('.pdf'):
        abort(400)
    
    reports_dir = str(Config.REPORTS_DIR)
    file_path = os.path.join(reports_dir, safe_filename)
    if not os.path.exists(file_path):
        flash('Report file not found.', 'danger')
        return redirect(url_for('report.reports_page'))

    log_audit_event('SECURITY_REPORT_DOWNLOADED', f"Downloaded report: {safe_filename} by {current_user.username}")
    return send_from_directory(reports_dir, safe_filename, as_attachment=True)
