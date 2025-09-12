import streamlit as st
import sqlite3
import os
import yaml
from typing import Dict, Any
from modules.security import SecureLogger

logger = SecureLogger("darkhound.dashboard")

def load_dashboard_config(config_path: str) -> Dict[str, Any]:
    """Load configuration for dashboard with error handling"""
    try:
        if os.path.exists(config_path):
            with open(config_path, 'r') as file:
                return yaml.safe_load(file) or {}
    except Exception as e:
        logger.error(f"Error loading dashboard config: {type(e).__name__}")
    return {}

def run_dashboard(config_path: str = "config.yaml"):
    """Run dashboard with security considerations"""
    logger.info("Starting DarkHound dashboard")
    
    config = load_dashboard_config(config_path)
    db_config = config.get('database', {})
    db_path = db_config.get('path', 'darkhound.db')
    
    # Validate database path
    if not isinstance(db_path, str) or len(db_path) > 255:
        logger.error("Invalid database path in configuration")
        st.error("Database configuration error")
        return
    
    st.title("DarkHound Leak Dashboard")
    st.warning("🔒 This dashboard contains sensitive security information")
    
    try:
        # Use absolute path and validate existence
        if not os.path.exists(db_path):
            st.error("Database file not found. Run monitoring first to create data.")
            return
            
        conn = sqlite3.connect(db_path, timeout=10.0)
        conn.execute("PRAGMA journal_mode=WAL")  # Better concurrency
        
        c = conn.cursor()
        
        # Validate table exists
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='leaks'")
        if not c.fetchone():
            st.info("No leak data available yet.")
            conn.close()
            return
        
        # Use parameterized query and limit results
        c.execute("""
            SELECT keyword, context, entities, risk_score, id 
            FROM leaks 
            ORDER BY risk_score DESC, id DESC 
            LIMIT 100
        """)
        leaks = c.fetchall()
        
        if not leaks:
            st.info("No leaks detected yet.")
        else:
            st.success(f"Found {len(leaks)} potential security issues")
            
            for leak in leaks:
                keyword, context, entities, risk_score, leak_id = leak
                
                # Color code by risk level
                if risk_score >= 8:
                    st.error(f"🚨 HIGH RISK - Keyword: {keyword} (Score: {risk_score})")
                elif risk_score >= 5:
                    st.warning(f"⚠️ MEDIUM RISK - Keyword: {keyword} (Score: {risk_score})")
                else:
                    st.info(f"ℹ️ LOW RISK - Keyword: {keyword} (Score: {risk_score})")
                
                # Sanitize and limit context display
                safe_context = str(context)[:300] if context else "No context available"
                st.code(safe_context, language="text")
                
                # Display entities safely
                try:
                    if entities and entities != "None":
                        st.json({"entities": str(entities)[:200]})
                except:
                    st.text("Entity data unavailable")
                
                st.divider()
        
        conn.close()
        logger.info("Dashboard loaded successfully")
        
    except sqlite3.Error as e:
        logger.error(f"Database error: {type(e).__name__}")
        st.error("Database access error. Please check logs.")
    except Exception as e:
        logger.error(f"Dashboard error: {type(e).__name__}")
        st.error("Dashboard error. Please check logs.")