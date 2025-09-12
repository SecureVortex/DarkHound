import re
import asyncio
from typing import Dict, List, Any
from modules.intel import check_threat_feeds
from modules.nlp import analyze_text
from modules.tor_requests import tor_get
from modules.storage import save_leak
from modules.security import SecureLogger, InputValidator, get_env_or_config

class DarkWebMonitor:
    def __init__(self, config: Dict[str, Any] = None):
        self.logger = SecureLogger("darkhound.monitor")
        self.config = config or {}
        
        # Load keywords from environment or config
        default_keywords = [
            "osborneclarke.com", "@osborneclarke.com", "osborne clarke", "OC", "osborneclarke"
        ]
        self.keywords = self.config.get('keywords', default_keywords)
        
        # Load sources with validation
        self.sources = []
        config_sources = self.config.get('dark_web_sources', [])
        for source in config_sources:
            if InputValidator.validate_url(str(source)):
                self.sources.append(source)
            else:
                self.logger.warning(f"Invalid URL in configuration, skipping")
        
        if not self.sources:
            self.logger.warning("No valid sources configured, using default")
            self.sources = ["http://exampleonionurl.onion/"]

    async def scan(self):
        for url in self.sources:
            self.logger.info(f"Scanning source: [URL_SANITIZED]")
            try:
                html = await tor_get(url)
                if html:
                    # Sanitize HTML content before processing
                    sanitized_html = InputValidator.sanitize_html_content(html)
                    findings = self.extract_findings(sanitized_html)
                    for finding in findings:
                        if finding:  # Additional validation
                            yield finding
                else:
                    self.logger.warning("Received empty content from source")
            except asyncio.TimeoutError:
                self.logger.error("Timeout while scanning source")
            except ConnectionError:
                self.logger.error("Connection error while scanning source")
            except Exception as e:
                self.logger.error(f"Error scanning source: {type(e).__name__}")

    def extract_findings(self, html: str) -> List[Dict[str, Any]]:
        results = []
        if not html or not isinstance(html, str):
            return results
        
        try:
            # Check for keywords with length limits
            for keyword in self.keywords[:10]:  # Limit keywords processed
                if not keyword or len(keyword) > 100:  # Validate keyword
                    continue
                    
                for match in re.finditer(re.escape(keyword), html, re.IGNORECASE):
                    # Limit context extraction
                    start_pos = max(0, match.start() - 50)
                    end_pos = min(len(html), match.end() + 50)
                    context = html[start_pos:end_pos]
                    
                    # Sanitize context before analysis
                    if len(context) > 200:  # Limit context size
                        context = context[:200] + "..."
                    
                    try:
                        entity_info = analyze_text(context)
                        risk_score = self.score_leak(entity_info)
                        finding = {
                            "keyword": keyword,
                            "context": context,
                            "entities": entity_info,
                            "risk_score": risk_score,
                        }
                        results.append(finding)
                    except Exception as e:
                        self.logger.error(f"Error analyzing text: {type(e).__name__}")
            
            # Enrich with threat intel (with error handling)
            try:
                threat_results = check_threat_feeds(self.keywords)
                if isinstance(threat_results, list):
                    results.extend(threat_results[:5])  # Limit threat intel results
            except Exception as e:
                self.logger.error(f"Error checking threat feeds: {type(e).__name__}")
                
        except Exception as e:
            self.logger.error(f"Error extracting findings: {type(e).__name__}")
        
        return results

    def save_finding(self, finding: Dict[str, Any]):
        if not finding or not isinstance(finding, dict):
            self.logger.error("Invalid finding data provided")
            return
        
        try:
            save_leak(finding)
            self.logger.info("Finding saved successfully")
        except Exception as e:
            self.logger.error(f"Error saving finding: {type(e).__name__}")

    def score_leak(self, entities: Dict[str, Any]) -> int:
        """Calculate risk score for a leak with input validation"""
        if not isinstance(entities, dict):
            return 1
            
        try:
            # Naive example; expand to real scoring
            score = 1  # Default minimum score
            
            entity_str = str(entities).lower()
            if "password" in entity_str:
                score = 10
            elif "email" in entity_str:
                score = 7
            elif "credential" in entity_str:
                score = 8
            else:
                score = 3
                
            # Ensure score is within valid range
            return max(1, min(10, score))
        except Exception as e:
            self.logger.error(f"Error calculating risk score: {type(e).__name__}")
            return 1