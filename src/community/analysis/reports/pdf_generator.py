"""
@fileoverview PDF Report Generator - Creates security analysis reports
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

PDF report generation for analysis results.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

from typing import Dict, Any, List
from datetime import datetime
from io import BytesIO
from ...core.logging import get_logger

log = get_logger(__name__)

# Conditional import - reportlab is optional
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    log.warning("reportlab_not_available", message="PDF generation will not be available")


class PDFReportGenerator:
    """Generates PDF reports for analysis results."""
    
    def __init__(self):
        if not REPORTLAB_AVAILABLE:
            log.warning("pdf_generator_initialized_without_reportlab")
        else:
            self.styles = getSampleStyleSheet()
            self._setup_custom_styles()
            log.info("pdf_generator_initialized")
    
    def _setup_custom_styles(self):
        """Setup custom paragraph styles."""
        if not REPORTLAB_AVAILABLE:
            return
        
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=TA_CENTER
        ))
        
        # Section header style
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=12,
            spaceBefore=12
        ))
    
    async def generate_report(
        self,
        session_id: str,
        session_data: Dict[str, Any],
        findings: List[Dict[str, Any]],
        flows: List[Dict[str, Any]]
    ) -> BytesIO:
        """
        Generate PDF report.
        
        Args:
            session_id: Session ID
            session_data: Session metadata
            findings: List of findings
            flows: List of flows
            
        Returns:
            BytesIO buffer with PDF data
            
        Raises:
            RuntimeError: If reportlab is not available
        """
        if not REPORTLAB_AVAILABLE:
            raise RuntimeError("reportlab package is not installed. Install it with: pip install reportlab>=4.0.0")
        
        log.info("generating_pdf_report", 
                session_id=session_id, 
                findings_count=len(findings),
                flows_count=len(flows))
        
        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )
        
        story = []
        
        # Title
        title = Paragraph("AX-TrafficAnalyzer<br/>Security Analysis Report", self.styles['CustomTitle'])
        story.append(title)
        story.append(Spacer(1, 0.3*inch))
        
        # Report metadata
        report_info = f"""
        <b>Report Generated:</b> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}<br/>
        <b>Session ID:</b> {session_id}<br/>
        <b>Session Start:</b> {session_data.get('start_time', 'N/A')}<br/>
        <b>Analysis Duration:</b> {self._format_duration(session_data)}<br/>
        """
        story.append(Paragraph(report_info, self.styles['Normal']))
        story.append(Spacer(1, 0.3*inch))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        
        # Severity breakdown
        severity_counts = self._count_by_severity(findings)
        summary_text = f"""
        This report summarizes the security analysis of captured network traffic.<br/><br/>
        <b>Total Flows Analyzed:</b> {len(flows)}<br/>
        <b>Total Security Findings:</b> {len(findings)}<br/>
        <b>Critical Severity:</b> {severity_counts.get('critical', 0)}<br/>
        <b>High Severity:</b> {severity_counts.get('high', 0)}<br/>
        <b>Medium Severity:</b> {severity_counts.get('medium', 0)}<br/>
        <b>Low Severity:</b> {severity_counts.get('low', 0)}<br/>
        <b>Informational:</b> {severity_counts.get('info', 0)}<br/>
        """
        story.append(Paragraph(summary_text, self.styles['Normal']))
        story.append(Spacer(1, 0.3*inch))
        
        # Risk assessment
        risk_level = self._calculate_risk_level(severity_counts)
        risk_color = self._get_risk_color(risk_level)
        risk_text = f"""
        <b>Overall Risk Level:</b> <font color="{risk_color}">{risk_level.upper()}</font>
        """
        story.append(Paragraph(risk_text, self.styles['Normal']))
        story.append(PageBreak())
        
        # Detailed Findings
        if findings:
            story.append(Paragraph("Security Findings", self.styles['SectionHeader']))
            story.append(Spacer(1, 0.2*inch))
            
            # Group findings by severity
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                severity_findings = [f for f in findings if f.get('severity') == severity]
                if severity_findings:
                    # Severity section header
                    severity_header = Paragraph(
                        f"{severity.capitalize()} Severity ({len(severity_findings)} findings)",
                        self.styles['Heading3']
                    )
                    story.append(severity_header)
                    story.append(Spacer(1, 0.1*inch))
                    
                    # Findings table
                    findings_data = [['#', 'Category', 'Title', 'Recommendation']]
                    for idx, finding in enumerate(severity_findings[:20], 1):  # Limit to 20 per severity
                        findings_data.append([
                            str(idx),
                            finding.get('category', 'unknown')[:20],
                            finding.get('title', 'Unknown')[:40],
                            finding.get('recommendation', 'N/A')[:50]
                        ])
                    
                    findings_table = Table(findings_data, colWidths=[0.5*inch, 1.5*inch, 2.5*inch, 2*inch])
                    findings_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 9),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                        ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ]))
                    story.append(findings_table)
                    story.append(Spacer(1, 0.2*inch))
        
        # Traffic Summary
        story.append(PageBreak())
        story.append(Paragraph("Traffic Summary", self.styles['SectionHeader']))
        
        # Top domains/hosts
        top_hosts = self._get_top_hosts(flows)
        if top_hosts:
            story.append(Paragraph("Top 10 Contacted Hosts", self.styles['Heading3']))
            hosts_data = [['Host', 'Request Count']]
            for host, count in top_hosts[:10]:
                hosts_data.append([host[:50], str(count)])
            
            hosts_table = Table(hosts_data, colWidths=[4*inch, 1.5*inch])
            hosts_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('FONTSIZE', (0, 1), (-1, -1), 9),
            ]))
            story.append(hosts_table)
            story.append(Spacer(1, 0.2*inch))
        
        # Recommendations
        story.append(PageBreak())
        story.append(Paragraph("Recommendations", self.styles['SectionHeader']))
        recommendations = self._generate_recommendations(severity_counts, findings)
        for rec in recommendations:
            story.append(Paragraph(f"• {rec}", self.styles['Normal']))
            story.append(Spacer(1, 0.1*inch))
        
        # Footer
        story.append(Spacer(1, 0.5*inch))
        footer_text = """
        <i>This report was generated by AX-TrafficAnalyzer Community Edition.<br/>
        Copyright © 2025 MMeTech (Macau) Ltd. All rights reserved.</i>
        """
        story.append(Paragraph(footer_text, self.styles['Normal']))
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        
        log.info("pdf_report_generated", 
                session_id=session_id, 
                size_bytes=len(buffer.getvalue()),
                pages_estimated=(len(findings) // 20) + 3)
        
        return buffer
    
    def _count_by_severity(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count findings by severity."""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for finding in findings:
            severity = finding.get('severity', 'info')
            counts[severity] = counts.get(severity, 0) + 1
        return counts
    
    def _calculate_risk_level(self, severity_counts: Dict[str, int]) -> str:
        """Calculate overall risk level based on findings."""
        if severity_counts.get('critical', 0) > 0:
            return "critical"
        elif severity_counts.get('high', 0) >= 3:
            return "high"
        elif severity_counts.get('high', 0) > 0 or severity_counts.get('medium', 0) >= 5:
            return "medium"
        elif severity_counts.get('medium', 0) > 0 or severity_counts.get('low', 0) > 0:
            return "low"
        else:
            return "minimal"
    
    def _get_risk_color(self, risk_level: str) -> str:
        """Get color for risk level."""
        colors_map = {
            "critical": "#d32f2f",
            "high": "#f57c00",
            "medium": "#fbc02d",
            "low": "#388e3c",
            "minimal": "#1976d2"
        }
        return colors_map.get(risk_level, "#757575")
    
    def _format_duration(self, session_data: Dict[str, Any]) -> str:
        """Format session duration."""
        # Simplified - in production would calculate from start/end times
        return "N/A"
    
    def _get_top_hosts(self, flows: List[Dict[str, Any]]) -> List[tuple]:
        """Get top contacted hosts."""
        host_counts = {}
        for flow in flows:
            host = flow.get('host', 'unknown')
            host_counts[host] = host_counts.get(host, 0) + 1
        
        return sorted(host_counts.items(), key=lambda x: x[1], reverse=True)
    
    def _generate_recommendations(
        self, 
        severity_counts: Dict[str, int], 
        findings: List[Dict[str, Any]]
    ) -> List[str]:
        """Generate actionable recommendations based on findings."""
        recommendations = []
        
        if severity_counts.get('critical', 0) > 0:
            recommendations.append(
                "Address all CRITICAL severity findings immediately. "
                "These represent serious security vulnerabilities."
            )
        
        if severity_counts.get('high', 0) > 0:
            recommendations.append(
                "Prioritize HIGH severity findings for remediation within 7 days."
            )
        
        # Check for specific patterns
        categories = [f.get('category') for f in findings]
        
        if 'insecure_cookies' in categories:
            recommendations.append(
                "Implement secure cookie attributes (Secure, HttpOnly, SameSite) "
                "for all cookies to prevent session hijacking."
            )
        
        if 'http_security_headers' in categories:
            recommendations.append(
                "Add missing security headers (HSTS, CSP, X-Frame-Options) "
                "to protect against common web attacks."
            )
        
        if 'sensitive_data_exposure' in categories:
            recommendations.append(
                "Never transmit sensitive data (passwords, API keys) in URLs. "
                "Use POST bodies or Authorization headers instead."
            )
        
        if 'authentication_security' in categories:
            recommendations.append(
                "Ensure all authentication happens over HTTPS. "
                "Consider migrating to token-based auth (JWT, OAuth2)."
            )
        
        if not recommendations:
            recommendations.append(
                "Continue monitoring traffic for security issues. "
                "Regularly review and update security policies."
            )
        
        return recommendations

