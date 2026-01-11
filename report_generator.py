"""
PDF Report Generation Module

This module generates downloadable PDF reports containing the complete
threat analysis results, including IOC reputation data.
"""

from datetime import datetime
from typing import Dict, Any, List
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from io import BytesIO


class ReportGenerator:
    """
    Generates PDF reports from threat analysis results.
    """
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom paragraph styles for the report."""
        # Title style
        self.title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1f77b4'),
            spaceAfter=30,
            alignment=1  # Center
        )
        
        # Heading style
        self.heading_style = ParagraphStyle(
            'CustomHeading',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#1f77b4'),
            spaceAfter=12,
            spaceBefore=12
        )
        
        # Subheading style
        self.subheading_style = ParagraphStyle(
            'CustomSubheading',
            parent=self.styles['Heading3'],
            fontSize=12,
            textColor=colors.HexColor('#666666'),
            spaceAfter=8,
            spaceBefore=8
        )
        
        # Risk badge styles
        self.risk_critical = ParagraphStyle(
            'RiskCritical',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=colors.HexColor('#d62728'),
            fontName='Helvetica-Bold'
        )
        
        self.risk_high = ParagraphStyle(
            'RiskHigh',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=colors.HexColor('#ff7f0e'),
            fontName='Helvetica-Bold'
        )
        
        self.risk_medium = ParagraphStyle(
            'RiskMedium',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=colors.HexColor('#ffbb78'),
            fontName='Helvetica-Bold'
        )
        
        self.risk_low = ParagraphStyle(
            'RiskLow',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=colors.HexColor('#2ca02c'),
            fontName='Helvetica-Bold'
        )
    
    def _get_risk_style(self, risk_level: str):
        """Get the appropriate style for risk level."""
        risk_map = {
            "Critical": self.risk_critical,
            "High": self.risk_high,
            "Medium": self.risk_medium,
            "Low": self.risk_low
        }
        return risk_map.get(risk_level, self.styles['Normal'])
    
    def _format_ioc_reputation(self, ioc: str, reputation: Dict[str, Any]) -> str:
        """Format IOC reputation data for display."""
        status = reputation.get("status", "unknown")
        status_emoji = {
            "malicious": "🔴",
            "suspicious": "🟠",
            "clean": "🟢",
            "error": "⚪"
        }.get(status, "⚪")
        
        lines = [f"{status_emoji} <b>{ioc}</b> - Status: {status.upper()}"]
        
        if status == "error":
            lines.append(f"Error: {reputation.get('error', 'Unknown error')}")
        else:
            if "abuse_confidence" in reputation:
                lines.append(f"Abuse Confidence: {reputation['abuse_confidence']}%")
                lines.append(f"Reports: {reputation.get('reports', 0)}")
                lines.append(f"ISP: {reputation.get('isp', 'Unknown')}")
                lines.append(f"Country: {reputation.get('country', 'Unknown')}")
            
            if "positives" in reputation:
                lines.append(f"Detection: {reputation['positives']}/{reputation.get('total', 0)} engines")
                if reputation.get("scan_date"):
                    lines.append(f"Last Scanned: {reputation['scan_date']}")
        
        return "<br/>".join(lines)
    
    def generate_report(self, analysis_result: Dict[str, Any], input_text: str = "") -> BytesIO:
        """
        Generate a PDF report from analysis results.
        
        Args:
            analysis_result: Complete analysis result dictionary
            input_text: Original input text (optional)
        
        Returns:
            BytesIO object containing the PDF
        """
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.75*inch, bottomMargin=0.75*inch)
        
        story = []
        
        # Title
        story.append(Paragraph("🛡️ Cyber Threat Analysis Report", self.title_style))
        story.append(Spacer(1, 0.2*inch))
        
        # Report metadata
        story.append(Paragraph(f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", self.styles['Normal']))
        story.append(Spacer(1, 0.3*inch))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", self.heading_style))
        
        risk_level = analysis_result.get("risk_level", "Unknown")
        risk_style = self._get_risk_style(risk_level)
        story.append(Paragraph(f"<b>Risk Level:</b> {risk_level}", risk_style))
        
        confidence = analysis_result.get("confidence", 0)
        story.append(Paragraph(f"<b>Analysis Confidence:</b> {confidence}%", self.styles['Normal']))
        
        mitre_id = analysis_result.get("mitre_id", "N/A")
        if mitre_id != "N/A":
            story.append(Paragraph(f"<b>MITRE ATT&CK ID:</b> {mitre_id}", self.styles['Normal']))
        
        story.append(Spacer(1, 0.2*inch))
        
        # Attack Summary
        attack_summary = analysis_result.get("attack_summary", "No summary available.")
        story.append(Paragraph(f"<b>Attack Summary:</b> {attack_summary}", self.styles['Normal']))
        story.append(Spacer(1, 0.3*inch))
        
        # Input Text (if provided)
        if input_text:
            story.append(Paragraph("Input Text", self.heading_style))
            story.append(Paragraph(input_text[:500] + ("..." if len(input_text) > 500 else ""), self.styles['Normal']))
            story.append(Spacer(1, 0.3*inch))
        
        # MITRE Mapping
        story.append(Paragraph("MITRE ATT&CK Mapping", self.heading_style))
        
        mapped_technique = analysis_result.get("mapped_technique", "N/A")
        nice_name = analysis_result.get("nice_technique_name", "N/A")
        mapped_tactics = analysis_result.get("mapped_tactics", [])
        
        mitre_data = [
            ["Technique (Ontology)", mapped_technique],
            ["Technique (MITRE Name)", nice_name],
            ["MITRE ID", mitre_id if mitre_id != "N/A" else "Not Mapped"],
            ["Tactics", ", ".join(mapped_tactics) if mapped_tactics else "None"]
        ]
        
        mitre_table = Table(mitre_data, colWidths=[2*inch, 4*inch])
        mitre_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f0f0')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey)
        ]))
        story.append(mitre_table)
        story.append(Spacer(1, 0.3*inch))
        
        # LLM Extraction
        story.append(Paragraph("LLM Extraction Results", self.heading_style))
        llm_raw = analysis_result.get("llm_raw", {})
        
        llm_data = [
            ["CVE ID", llm_raw.get("cve_id", "N/A")],
            ["Vulnerability Type", llm_raw.get("vulnerability_type", "N/A")],
            ["Possible Tactic", llm_raw.get("possible_tactic", "N/A")],
            ["Possible Technique", llm_raw.get("possible_technique_name", "N/A")]
        ]
        
        llm_table = Table(llm_data, colWidths=[2*inch, 4*inch])
        llm_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f0f0')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey)
        ]))
        story.append(llm_table)
        
        if llm_raw.get("brief_reasoning"):
            story.append(Spacer(1, 0.1*inch))
            story.append(Paragraph(f"<b>Reasoning:</b> {llm_raw['brief_reasoning']}", self.styles['Normal']))
        
        story.append(Spacer(1, 0.3*inch))
        
        # IOCs
        story.append(Paragraph("Indicators of Compromise (IOCs)", self.heading_style))
        iocs = analysis_result.get("iocs", {})
        ioc_reputation = analysis_result.get("ioc_reputation", {})
        
        has_iocs = any(iocs.get(k) for k in ["ip_addresses", "urls", "emails", "hashes"])
        
        if not has_iocs:
            story.append(Paragraph("No IOCs detected in the analyzed text.", self.styles['Normal']))
        else:
            # IP Addresses
            if iocs.get("ip_addresses"):
                story.append(Paragraph("IP Addresses", self.subheading_style))
                for ip in iocs["ip_addresses"]:
                    if ip in ioc_reputation.get("ip_addresses", {}):
                        rep_text = self._format_ioc_reputation(ip, ioc_reputation["ip_addresses"][ip])
                        story.append(Paragraph(rep_text, self.styles['Normal']))
                    else:
                        story.append(Paragraph(f"• {ip}", self.styles['Normal']))
                story.append(Spacer(1, 0.1*inch))
            
            # URLs
            if iocs.get("urls"):
                story.append(Paragraph("URLs", self.subheading_style))
                for url in iocs["urls"]:
                    if url in ioc_reputation.get("urls", {}):
                        rep_text = self._format_ioc_reputation(url, ioc_reputation["urls"][url])
                        story.append(Paragraph(rep_text, self.styles['Normal']))
                    else:
                        story.append(Paragraph(f"• {url}", self.styles['Normal']))
                story.append(Spacer(1, 0.1*inch))
            
            # Domains (from reputation check)
            if ioc_reputation.get("domains"):
                story.append(Paragraph("Domains", self.subheading_style))
                for domain, rep_data in ioc_reputation["domains"].items():
                    rep_text = self._format_ioc_reputation(domain, rep_data)
                    story.append(Paragraph(rep_text, self.styles['Normal']))
                story.append(Spacer(1, 0.1*inch))
            
            # Emails
            if iocs.get("emails"):
                story.append(Paragraph("Email Addresses", self.subheading_style))
                for email in iocs["emails"]:
                    story.append(Paragraph(f"• {email}", self.styles['Normal']))
                story.append(Spacer(1, 0.1*inch))
            
            # Hashes
            if iocs.get("hashes"):
                story.append(Paragraph("File Hashes", self.subheading_style))
                for hash_val in iocs["hashes"]:
                    if hash_val in ioc_reputation.get("hashes", {}):
                        rep_text = self._format_ioc_reputation(hash_val, ioc_reputation["hashes"][hash_val])
                        story.append(Paragraph(rep_text, self.styles['Normal']))
                    else:
                        story.append(Paragraph(f"• {hash_val}", self.styles['Normal']))
                story.append(Spacer(1, 0.1*inch))
        
        story.append(Spacer(1, 0.3*inch))
        
        # Defense Recommendations
        story.append(Paragraph("Defense Recommendations", self.heading_style))
        
        defense_pre = analysis_result.get("defense_recommendations", [])
        if defense_pre:
            story.append(Paragraph("Prevention Measures", self.subheading_style))
            for i, item in enumerate(defense_pre, 1):
                story.append(Paragraph(f"{i}. {item}", self.styles['Normal']))
            story.append(Spacer(1, 0.1*inch))
        
        defense_d3 = analysis_result.get("defense_d3fend", [])
        if defense_d3:
            story.append(Paragraph("D3FEND-Style Defenses", self.subheading_style))
            for i, item in enumerate(defense_d3, 1):
                story.append(Paragraph(f"{i}. {item}", self.styles['Normal']))
        
        story.append(Spacer(1, 0.3*inch))
        
        # Symbolic Consistency
        story.append(Paragraph("Symbolic Consistency Check", self.heading_style))
        symbolic_note = analysis_result.get("symbolic_note", "No note available.")
        story.append(Paragraph(symbolic_note, self.styles['Normal']))
        
        story.append(Spacer(1, 0.3*inch))
        
        # Related Entities
        related_malware = analysis_result.get("related_malware", [])
        related_actors = analysis_result.get("related_actors", [])
        
        if related_malware or related_actors:
            story.append(Paragraph("Related Entities", self.heading_style))
            
            if related_malware:
                story.append(Paragraph("Related Malware Families", self.subheading_style))
                for malware in related_malware:
                    story.append(Paragraph(f"• {malware}", self.styles['Normal']))
                story.append(Spacer(1, 0.1*inch))
            
            if related_actors:
                story.append(Paragraph("Related Threat Actors", self.subheading_style))
                for actor in related_actors:
                    story.append(Paragraph(f"• {actor}", self.styles['Normal']))
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        return buffer


if __name__ == "__main__":
    # Test report generation
    generator = ReportGenerator()
    print("Report Generator initialized successfully")

