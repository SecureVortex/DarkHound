import re
import asyncio
from modules.intel import check_threat_feeds
from modules.nlp import analyze_text
from modules.tor_requests import tor_get
from modules.storage import save_leak

KEYWORDS = [
    "osborneclarke.com", "@osborneclarke.com", "osborne clarke", "OC", "osborneclarke"
]

class DarkWebMonitor:
    def __init__(self):
        # Load config, set up targets, etc.
        self.sources = [
            # Add dark web URLs, onion links, breach forums, etc.
            "http://exampleonionurl.onion/",
            # More can be loaded from config
        ]

    async def scan(self):
        for url in self.sources:
            print(f"[*] Scanning: {url}")
            try:
                html = await tor_get(url)
                findings = self.extract_findings(html)
                for finding in findings:
                    yield finding
            except Exception as e:
                print(f"[!] Error scanning {url}: {str(e)}")

    def extract_findings(self, html):
        results = []
        # Check for keywords (simple example)
        for keyword in KEYWORDS:
            for match in re.finditer(keyword, html, re.IGNORECASE):
                context = html[max(0, match.start()-50):match.end()+50]
                entity_info = analyze_text(context)
                risk_score = self.score_leak(entity_info)
                finding = {
                    "keyword": keyword,
                    "context": context,
                    "entities": entity_info,
                    "risk_score": risk_score,
                }
                results.append(finding)
        # Enrich with threat intel
        results += check_threat_feeds(KEYWORDS)
        return results

    def save_finding(self, finding):
        save_leak(finding)

    def score_leak(self, entities):
        # Naive example; expand to real scoring
        if "password" in entities:
            return 10
        elif "email" in entities:
            return 7
        else:
            return 3