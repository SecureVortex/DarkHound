import sqlite3
import os
from typing import Dict, Any
from modules.security import SecureLogger

logger = SecureLogger("darkhound.storage")

def save_leak(finding: Dict[str, Any]):
    """Save leak finding to database with security validation"""
    if not finding or not isinstance(finding, dict):
        logger.error("Invalid finding data provided to storage")
        return False
    
    try:
        # Validate required fields
        required_fields = ['keyword', 'context', 'entities', 'risk_score']
        for field in required_fields:
            if field not in finding:
                logger.error(f"Missing required field in finding: {field}")
                return False
        
        # Validate and sanitize data
        keyword = str(finding.get('keyword', ''))[:100]  # Limit length
        context = str(finding.get('context', ''))[:1000]  # Limit context
        entities = str(finding.get('entities', ''))[:500]  # Limit entities
        
        # Validate risk score
        risk_score = finding.get('risk_score', 1)
        if not isinstance(risk_score, (int, float)) or risk_score < 1 or risk_score > 10:
            logger.warning("Invalid risk score, setting to 1")
            risk_score = 1
        
        # Database operations with proper error handling
        db_path = "darkhound.db"
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        
        conn = sqlite3.connect(db_path, timeout=10.0)
        try:
            # Enable WAL mode for better concurrency
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            
            c = conn.cursor()
            
            # Create table with proper constraints
            c.execute("""
                CREATE TABLE IF NOT EXISTS leaks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    keyword TEXT NOT NULL CHECK(length(keyword) <= 100),
                    context TEXT CHECK(length(context) <= 1000),
                    entities TEXT CHECK(length(entities) <= 500),
                    risk_score INTEGER NOT NULL CHECK(risk_score >= 1 AND risk_score <= 10),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Insert with parameterized query (prevents SQL injection)
            c.execute("""
                INSERT INTO leaks (keyword, context, entities, risk_score)
                VALUES (?, ?, ?, ?)
            """, (keyword, context, entities, int(risk_score)))
            
            conn.commit()
            logger.info("Finding saved to database successfully")
            return True
            
        finally:
            conn.close()
            
    except sqlite3.IntegrityError as e:
        logger.error(f"Database integrity error: {type(e).__name__}")
        return False
    except sqlite3.OperationalError as e:
        logger.error(f"Database operational error: {type(e).__name__}")
        return False
    except sqlite3.Error as e:
        logger.error(f"Database error: {type(e).__name__}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error saving finding: {type(e).__name__}")
        return False