import smtplib
import os
from email.message import EmailMessage
from typing import Dict, Any
from modules.security import SecureLogger, InputValidator, get_env_or_config

class AlertManager:
    def __init__(self, config: Dict[str, Any] = None):
        self.logger = SecureLogger("darkhound.alerting")
        self.config = config or {}
        
        # Get email configuration with environment variable support
        alerting_config = self.config.get('alerting', {})
        self.email_to = get_env_or_config(
            'DARKHOUND_EMAIL_TO', 
            alerting_config.get('email_to', ''),
            'soc@osborneclarke.com'
        )
        
        # Validate email configuration
        if not InputValidator.validate_email(self.email_to):
            self.logger.error("Invalid email configuration")
            self.email_to = None
        
        # SMTP configuration from environment
        self.smtp_host = get_env_or_config('DARKHOUND_SMTP_HOST', '', 'localhost')
        self.smtp_port = int(get_env_or_config('DARKHOUND_SMTP_PORT', '', '587'))
        self.smtp_user = os.getenv('DARKHOUND_SMTP_USER')
        self.smtp_pass = os.getenv('DARKHOUND_SMTP_PASS')

    def send_alert(self, finding: Dict[str, Any]):
        """Send alert with secure handling of sensitive data"""
        if not finding or not isinstance(finding, dict):
            self.logger.error("Invalid finding data for alert")
            return
        
        if not self.email_to:
            self.logger.error("No valid email configuration for alerts")
            return
        
        try:
            # Sanitize finding data for alert
            keyword = str(finding.get('keyword', 'Unknown'))[:50]  # Limit length
            risk_score = finding.get('risk_score', 0)
            
            # Create sanitized context (remove potentially sensitive data)
            context = str(finding.get('context', ''))[:200]  # Limit context length
            
            msg = EmailMessage()
            msg['Subject'] = f"DarkHound Leak Alert: Risk Level {risk_score}"
            msg['From'] = get_env_or_config('DARKHOUND_EMAIL_FROM', '', 'darkhound@osborneclarke.com')
            msg['To'] = self.email_to
            
            # Create sanitized alert content
            alert_content = f"""
DarkHound Leak Detection Alert

Risk Score: {risk_score}
Keyword: {keyword}
Context: [SANITIZED_CONTEXT]

This is an automated alert from DarkHound monitoring system.
Please investigate immediately if risk score is above 7.
"""
            msg.set_content(alert_content)
            
            # Send email with proper error handling
            try:
                with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                    if self.smtp_user and self.smtp_pass:
                        server.starttls()
                        server.login(self.smtp_user, self.smtp_pass)
                    server.send_message(msg)
                
                self.logger.info("Security alert sent successfully")
                
            except smtplib.SMTPAuthenticationError:
                self.logger.error("SMTP authentication failed")
            except smtplib.SMTPServerDisconnected:
                self.logger.error("SMTP server disconnected")
            except smtplib.SMTPException as e:
                self.logger.error(f"SMTP error: {type(e).__name__}")
            except ConnectionError:
                self.logger.error("Unable to connect to SMTP server")
                
        except Exception as e:
            self.logger.error(f"Error sending alert: {type(e).__name__}")