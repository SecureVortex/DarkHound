import streamlit as st
import sqlite3

def run_dashboard():
    st.title("DarkHound Leak Dashboard")
    conn = sqlite3.connect("darkhound.db")
    c = conn.cursor()
    c.execute("SELECT keyword, context, entities, risk_score FROM leaks ORDER BY risk_score DESC")
    leaks = c.fetchall()
    for leak in leaks:
        st.warning(f"Keyword: {leak[0]}")
        st.write(f"Risk Score: {leak[3]}")
        st.code(leak[1])
        st.json({"entities": leak[2]})