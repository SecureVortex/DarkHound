import sqlite3

def save_leak(finding):
    # Save to SQLite for demo; expand to Postgres if needed
    conn = sqlite3.connect("darkhound.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS leaks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            keyword TEXT,
            context TEXT,
            entities TEXT,
            risk_score INTEGER
        )
    """)
    c.execute("""
        INSERT INTO leaks (keyword, context, entities, risk_score)
        VALUES (?, ?, ?, ?)
    """, (
        finding["keyword"], finding["context"], str(finding["entities"]), finding["risk_score"]
    ))
    conn.commit()
    conn.close()