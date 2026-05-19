from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime
import os

def generate_report(alert_data, investigation_data, ai_summary):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"reports/incident_report_{timestamp}.pdf"
    os.makedirs("reports", exist_ok=True)

    doc = SimpleDocTemplate(filename, pagesize=A4,
                            rightMargin=2*cm, leftMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)

    styles = getSampleStyleSheet()
    elements = []

    # Title
    title_style = ParagraphStyle('title', fontSize=20, textColor=colors.HexColor('#1a56db'),
                                  spaceAfter=6, alignment=TA_CENTER, fontName='Helvetica-Bold')
    sub_style = ParagraphStyle('sub', fontSize=10, textColor=colors.grey,
                                spaceAfter=20, alignment=TA_CENTER)
    elements.append(Paragraph("SOC Incident Report", title_style))
    elements.append(Paragraph("AI-Powered Alert Triage & Incident Response", sub_style))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#1a56db')))
    elements.append(Spacer(1, 0.4*cm))

    # Section style
    section_style = ParagraphStyle('section', fontSize=12, textColor=colors.HexColor('#1a56db'),
                                    fontName='Helvetica-Bold', spaceBefore=16, spaceAfter=8)
    normal_style = ParagraphStyle('normal', fontSize=10, spaceAfter=6, leading=16)

    # Report metadata
    elements.append(Paragraph("Report Details", section_style))
    meta_data = [
        ['Report Generated', datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
        ['Analyst', 'SOC Analyst Assistant (AI-Powered)'],
        ['Report ID', f'INC-{timestamp}'],
    ]
    meta_table = Table(meta_data, colWidths=[5*cm, 12*cm])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#f0f4ff')),
        ('TEXTCOLOR', (0,0), (0,-1), colors.HexColor('#1a56db')),
        ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 10),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#d1d5db')),
        ('PADDING', (0,0), (-1,-1), 8),
        ('ROWBACKGROUNDS', (0,0), (-1,-1), [colors.white, colors.HexColor('#f9fafb')]),
    ]))
    elements.append(meta_table)

    # Alert details
    elements.append(Paragraph("Alert Details", section_style))
    alert_rows = [
        ['Field', 'Value'],
        ['Alert Type', alert_data.get('type', 'Unknown')],
        ['Event ID', alert_data.get('event_id', 'Unknown')],
        ['Source IP', alert_data.get('source_ip', 'Unknown')],
        ['Username Targeted', alert_data.get('username', 'Unknown')],
        ['Timestamp', alert_data.get('timestamp', 'Unknown')],
        ['Severity', alert_data.get('severity', 'Unknown')],
    ]
    alert_table = Table(alert_rows, colWidths=[5*cm, 12*cm])
    alert_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1a56db')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTNAME', (0,1), (0,-1), 'Helvetica-Bold'),
        ('BACKGROUND', (0,1), (0,-1), colors.HexColor('#f0f4ff')),
        ('TEXTCOLOR', (0,1), (0,-1), colors.HexColor('#1a56db')),
        ('FONTSIZE', (0,0), (-1,-1), 10),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#d1d5db')),
        ('PADDING', (0,0), (-1,-1), 8),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f9fafb')]),
    ]))
    elements.append(alert_table)

    # Threat intelligence
    elements.append(Paragraph("Threat Intelligence", section_style))
    abuse = investigation_data.get('abuseipdb', {})
    vt = investigation_data.get('virustotal', {})
    threat_level = investigation_data.get('threat_level', 'Unknown')

    threat_color = {
        'Critical': '#ef4444', 'High': '#f97316',
        'Medium': '#f59e0b', 'Low': '#10b981'
    }.get(threat_level, '#6b7280')

    intel_rows = [
        ['Source', 'Field', 'Value'],
        ['Threat Level', '', threat_level],
        ['AbuseIPDB', 'Abuse Score', str(abuse.get('abuse_score', 0)) + '%'],
        ['AbuseIPDB', 'Country', str(abuse.get('country', 'Unknown'))],
        ['AbuseIPDB', 'ISP', str(abuse.get('isp', 'Unknown'))],
        ['AbuseIPDB', 'Total Reports', str(abuse.get('total_reports', 0))],
        ['AbuseIPDB', 'TOR Node', 'Yes' if abuse.get('is_tor') else 'No'],
        ['VirusTotal', 'Malicious Detections', str(vt.get('malicious', 0))],
        ['VirusTotal', 'Suspicious', str(vt.get('suspicious', 0))],
        ['VirusTotal', 'Owner', str(vt.get('owner', 'Unknown'))],
    ]
    intel_table = Table(intel_rows, colWidths=[4*cm, 6*cm, 7*cm])
    intel_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1a56db')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 10),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#d1d5db')),
        ('PADDING', (0,0), (-1,-1), 8),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f9fafb')]),
    ]))
    elements.append(intel_table)

    # AI Summary
    elements.append(Paragraph("AI Investigation Summary", section_style))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#d1d5db')))
    elements.append(Spacer(1, 0.3*cm))
    ai_style = ParagraphStyle('ai', fontSize=10, leading=18, spaceAfter=8,
                               backColor=colors.HexColor('#f0f4ff'), borderPadding=10)
    clean_summary = ai_summary.replace('\n', '<br/>')
    elements.append(Paragraph(clean_summary, ai_style))

    # Footer
    elements.append(Spacer(1, 0.5*cm))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#1a56db')))
    footer_style = ParagraphStyle('footer', fontSize=9, textColor=colors.grey,
                                   alignment=TA_CENTER, spaceBefore=8)
    elements.append(Paragraph("Generated by SOC Analyst Assistant | AI-Powered Incident Response", footer_style))

    doc.build(elements)
    return filename