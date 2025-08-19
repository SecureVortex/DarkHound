import smtplib
from email.message import EmailMessage

class AlertManager:
    def __init__(self):
        # Could load Slack/Teams/email config from file
        self.email_to = "soc@osborneclarke.com"

    def send_alert(self, finding):
        # For demo: email alert only
        msg = EmailMessage()
        msg['Subject'] = f"DarkHound Leak Alert: {finding['keyword']}"
        msg['From'] = "darkhound@osborneclarke.com"
        msg['To'] = self.email_to
        msg.set_content(f"Leak found!\n\nContext:\n{finding['context']}\n\nEntities: {finding['entities']}")
        try:
            with smtplib.SMTP('localhost') as s:
                s.send_message(msg)
            print("[*] Alert sent!")
        except Exception as e:
            print(f"[!] Failed to send alert: {e}")