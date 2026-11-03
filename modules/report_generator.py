import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

from config import Config
from models.database import LoginActivity, DetectionResult, SecurityAlert, User
from modules.mitre_attack import MitreAttackMapper

class SecurityReportGenerator:
    """
    Generates executive-grade, professional PDF cybersecurity anomaly detection reports.
    """

    @classmethod
    def generate_pdf_report(cls, output_dir: str = None) -> str:
        """Generate comprehensive PDF report and return absolute file path."""
        target_dir = Path(output_dir or Config.REPORTS_DIR)
        target_dir.mkdir(parents=True, exist_ok=True)
        
        report_id = f"SEC-REP-{datetime.utcnow().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"
        filename = f"{report_id}.pdf"
        filepath = target_dir / filename

        doc = SimpleDocTemplate(
            str(filepath),
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()
        
        # Custom styles for cybersecurity aesthetic
        title_style = ParagraphStyle(
            'DocTitle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=18,
            leading=22,
            textColor=colors.HexColor('#002B49')
        )
        subtitle_style = ParagraphStyle(
            'DocSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=10,
            leading=14,
            textColor=colors.HexColor('#007A87')
        )
        header_badge_style = ParagraphStyle(
            'ConfidentialBadge',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=8,
            leading=10,
            textColor=colors.HexColor('#D32F2F'),
            alignment=2
        )
        h2_style = ParagraphStyle(
            'SectionH2',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=12,
            leading=16,
            textColor=colors.HexColor('#0C2340'),
            spaceBefore=10,
            spaceAfter=4
        )
        body_style = ParagraphStyle(
            'ReportBody',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            leading=12,
            textColor=colors.HexColor('#2C3E50')
        )
        table_cell_style = ParagraphStyle(
            'TableCell',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=8,
            leading=10,
            textColor=colors.HexColor('#2C3E50')
        )
        table_header_style = ParagraphStyle(
            'TableHeader',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=8,
            leading=10,
            textColor=colors.white
        )

        story = []

        # 1. Header Banner
        banner_data = [
            [
                Paragraph("<b>CYBERGUARD SENTINEL</b><br/><font size=8 color='#555555'>AI-Based User Behavior Anomaly Detection Platform</font>", title_style),
                Paragraph(f"<b>REPORT CLASSIFICATION: CONFIDENTIAL</b><br/>ID: {report_id}<br/>Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", header_badge_style)
            ]
        ]
        banner_table = Table(banner_data, colWidths=[4.2 * inch, 3.3 * inch])
        banner_table.setStyle(TableStyle([
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(banner_table)
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#002B49'), spaceAfter=12))

        # 2. Executive Metrics Summary
        total_activities = LoginActivity.query.count()
        total_anomalies = DetectionResult.query.filter_by(is_ml_anomaly=True).count()
        high_risk_count = DetectionResult.query.filter(DetectionResult.calculated_risk_score >= 70).count()
        med_risk_count = DetectionResult.query.filter(
            DetectionResult.calculated_risk_score >= 30,
            DetectionResult.calculated_risk_score < 70
        ).count()
        low_risk_count = DetectionResult.query.filter(DetectionResult.calculated_risk_score < 30).count()
        total_alerts = SecurityAlert.query.count()
        open_alerts = SecurityAlert.query.filter_by(status='OPEN').count()

        story.append(Paragraph("1. Executive Security Summary", h2_style))
        story.append(Paragraph(
            "This report summarizes behavioral telemetry, machine learning anomaly detection scores, "
            "and security rule evaluations across monitored user accounts. Anomalies are detected via Scikit-Learn "
            "Isolation Forest paired with behavioral baseline profiling and rule heuristics.",
            body_style
        ))
        story.append(Spacer(1, 6))

        metric_cards = [
            [
                Paragraph(f"<b>Total Monitored Events</b><br/><font size=14 color='#002B49'><b>{total_activities}</b></font>", body_style),
                Paragraph(f"<b>ML Anomaly Detections</b><br/><font size=14 color='#E65100'><b>{total_anomalies}</b></font>", body_style),
                Paragraph(f"<b>High-Risk Incidents</b><br/><font size=14 color='#C62828'><b>{high_risk_count}</b></font>", body_style),
                Paragraph(f"<b>Open Security Alerts</b><br/><font size=14 color='#D32F2F'><b>{open_alerts}</b></font>", body_style)
            ]
        ]
        card_table = Table(metric_cards, colWidths=[1.875 * inch] * 4)
        card_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F4F6F9')),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#CFD8DC')),
            ('INNERGRID', (0,0), (-1,-1), 1, colors.HexColor('#E0E0E0')),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ]))
        story.append(card_table)
        story.append(Spacer(1, 12))

        # 3. Risk Tier Distribution
        story.append(Paragraph("2. Risk Score & Distribution Analysis", h2_style))
        pct_low = (low_risk_count / total_activities * 100) if total_activities > 0 else 0
        pct_med = (med_risk_count / total_activities * 100) if total_activities > 0 else 0
        pct_high = (high_risk_count / total_activities * 100) if total_activities > 0 else 0

        risk_dist_data = [
            [
                Paragraph("<b>Risk Tier</b>", table_header_style),
                Paragraph("<b>Score Range</b>", table_header_style),
                Paragraph("<b>Event Count</b>", table_header_style),
                Paragraph("<b>Proportion (%)</b>", table_header_style),
                Paragraph("<b>Operational Policy</b>", table_header_style)
            ],
            [
                Paragraph("<font color='#2E7D32'><b>LOW RISK</b></font>", table_cell_style),
                Paragraph("0 - 29", table_cell_style),
                Paragraph(str(low_risk_count), table_cell_style),
                Paragraph(f"{pct_low:.1f}%", table_cell_style),
                Paragraph("Standard logging; automatic baseline continuous learning", table_cell_style)
            ],
            [
                Paragraph("<font color='#F57F17'><b>MEDIUM RISK</b></font>", table_cell_style),
                Paragraph("30 - 69", table_cell_style),
                Paragraph(str(med_risk_count), table_cell_style),
                Paragraph(f"{pct_med:.1f}%", table_cell_style),
                Paragraph("Elevated monitoring; baseline freeze; SOC analyst triage queue", table_cell_style)
            ],
            [
                Paragraph("<font color='#C62828'><b>HIGH RISK</b></font>", table_cell_style),
                Paragraph("70 - 100", table_cell_style),
                Paragraph(str(high_risk_count), table_cell_style),
                Paragraph(f"{pct_high:.1f}%", table_cell_style),
                Paragraph("Immediate alert raised; session termination / MFA step-up candidate", table_cell_style)
            ]
        ]
        risk_dist_table = Table(risk_dist_data, colWidths=[1.3 * inch, 1.0 * inch, 1.0 * inch, 1.1 * inch, 3.1 * inch])
        risk_dist_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0C2340')),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#D0D7DE')),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('BACKGROUND', (0,1), (-1,1), colors.HexColor('#E8F5E9')),
            ('BACKGROUND', (0,2), (-1,2), colors.HexColor('#FFFDE7')),
            ('BACKGROUND', (0,3), (-1,3), colors.HexColor('#FFEBEE')),
        ]))
        story.append(risk_dist_table)
        story.append(Spacer(1, 12))

        # 4. Recent Suspicious & High-Risk Incidents Table
        story.append(Paragraph("3. High-Risk & Suspicious Activity Log (Recent 8 Incidents)", h2_style))
        high_risk_events = LoginActivity.query.join(DetectionResult).filter(
            (DetectionResult.calculated_risk_score >= 30) | (DetectionResult.is_ml_anomaly == True)
        ).order_by(LoginActivity.timestamp.desc()).limit(8).all()

        incident_rows = [
            [
                Paragraph("<b>Timestamp (UTC)</b>", table_header_style),
                Paragraph("<b>User</b>", table_header_style),
                Paragraph("<b>IP / Location</b>", table_header_style),
                Paragraph("<b>Target Resource</b>", table_header_style),
                Paragraph("<b>Risk Score</b>", table_header_style),
                Paragraph("<b>Flagged Detection Details</b>", table_header_style),
            ]
        ]

        if not high_risk_events:
            incident_rows.append([
                Paragraph("No suspicious or high-risk incidents detected in current evaluation scope.", table_cell_style),
                "", "", "", "", ""
            ])
        else:
            for act in high_risk_events:
                det = act.detection_result
                reasons_str = "; ".join(det.reasons[:2]) if det and det.reasons else "Deviated from behavioral baseline"
                incident_rows.append([
                    Paragraph(act.timestamp.strftime('%Y-%m-%d %H:%M'), table_cell_style),
                    Paragraph(act.username, table_cell_style),
                    Paragraph(f"{act.ip_address}<br/>{act.location}", table_cell_style),
                    Paragraph(act.accessed_resource, table_cell_style),
                    Paragraph(f"<b>{det.calculated_risk_score:.1f}</b><br/>({det.risk_level})", table_cell_style),
                    Paragraph(reasons_str, table_cell_style),
                ])

        incidents_table = Table(incident_rows, colWidths=[1.1 * inch, 0.9 * inch, 1.4 * inch, 1.4 * inch, 0.9 * inch, 1.8 * inch])
        incidents_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1F2937')),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E5E7EB')),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(incidents_table)
        story.append(Spacer(1, 14))

        # 4. MITRE ATT&CK Threat Alignment
        story.append(Paragraph("4. MITRE ATT&CK Adversarial Tactics & Technique Alignment", h2_style))
        story.append(Paragraph(
            "Security events, behavioral deviations, and Isolation Forest ML anomalies are correlated directly "
            "with official MITRE ATT&CK Enterprise Matrix v14 tactics and techniques to facilitate standardized SOC response:",
            body_style
        ))
        story.append(Spacer(1, 6))

        all_mitre = MitreAttackMapper.get_all_matrix_techniques()
        mitre_rows = [
            [
                Paragraph("<b>Technique ID</b>", table_header_style),
                Paragraph("<b>Tactic Category</b>", table_header_style),
                Paragraph("<b>Adversary Technique Name</b>", table_header_style),
                Paragraph("<b>Detection Heuristic & Indicator</b>", table_header_style),
            ]
        ]
        for m in all_mitre:
            mitre_rows.append([
                Paragraph(f"<b>{m['id']}</b>", table_cell_style),
                Paragraph(m['tactic'], table_cell_style),
                Paragraph(m['name'], table_cell_style),
                Paragraph(m['description'], table_cell_style),
            ])

        mitre_table = Table(mitre_rows, colWidths=[1.1 * inch, 1.6 * inch, 2.0 * inch, 2.8 * inch])
        mitre_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#002B49')),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#D0D7DE')),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(mitre_table)
        story.append(Spacer(1, 14))

        # 5. Security Recommendations
        story.append(Paragraph("5. Recommended Security Actions & Remediation", h2_style))
        recs = [
            "<b>1. Multi-Factor Authentication (MFA) Step-Up:</b> Enforce mandatory FIDO2 / TOTP challenge for logins originating from new IP addresses or unfamiliar client operating systems.",
            "<b>2. Account Lockout & Throttling:</b> Configure automated temporary lockout or exponential rate-limiting for accounts accumulating 3+ failed logins in 5 minutes.",
            "<b>3. Baseline Safeguard Enforcement:</b> Keep behavioral baseline profiles locked for users undergoing internal investigation to prevent adversarial profile poisoning.",
            "<b>4. Geofencing & Off-Hours Ingress Policies:</b> Implement conditional access policies restricting administrative asset access between 23:00 and 06:00 UTC without prior SOC clearance.",
            "<b>5. SOC Incident Response:</b> Review all OPEN High and Critical security alerts within a 15-minute SLA. Resolve alerts with thorough forensic notes."
        ]
        for r in recs:
            story.append(Paragraph(r, body_style))
            story.append(Spacer(1, 3))

        doc.build(story)
        return str(filepath)
