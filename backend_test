# ================================================
# NETSHIELD ANGOLA - Backend do Site de Teste
# Autor: Grok + Jalussiel
# Comentários em português explicando tudo
# ================================================

from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = 'netshield_super_secreto_2026'  # Necessário para sessões

# ====================== BANCO DE DADOS ======================
DB_PATH = '../database/netshield.db'

def init_db():
    """Cria as tabelas se não existirem"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Tabela de utilizadores do site de teste
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            full_name TEXT,
            role TEXT DEFAULT 'user'
        )
    ''')
    
    # Tabela de logs de tentativas de login (usado por todo o sistema)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip TEXT,
            username TEXT,
            success INTEGER,           # 1 = sucesso, 0 = falha
            user_agent TEXT
        )
    ''')
    
    # Inserir utilizadores de teste (senhas com hash)
    users = [
        ('aluno1', generate_password_hash('123456'), 'João Silva', 'user'),
        ('professor', generate_password_hash('prof2026'), 'Ana Costa', 'user'),
        ('admin_test', generate_password_hash('admin123'), 'Administrador Teste', 'admin')
    ]
    for user in users:
        cursor.execute("INSERT OR IGNORE INTO users (username, password, full_name, role) VALUES (?, ?, ?, ?)", user)
    
    conn.commit()
    conn.close()

# ====================== ROTAS ======================
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        ip = request.remote_addr
        user_agent = request.headers.get('User-Agent')
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Busca utilizador
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        
        success = 0
        if result and check_password_hash(result[0], password):
            success = 1
            session['username'] = username
            return redirect(url_for('dashboard_user'))
        
        # Regista tentativa (sucesso ou falha)
        cursor.execute('''
            INSERT INTO login_logs (timestamp, ip, username, success, user_agent)
            VALUES (?, ?, ?, ?, ?)
        ''', (now, ip, username, success, user_agent))
        conn.commit()
        conn.close()
        
        return render_template('login.html', error="Credenciais inválidas!")
    
    return render_template('login.html', error=None)

@app.route('/dashboard')
def dashboard_user():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard_user.html', username=session['username'])

@app.route('/api/logs', methods=['GET'])
def get_logs():
    """API que o ESP32 vai chamar para receber os logs (JSON)"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM login_logs ORDER BY id DESC LIMIT 100")
    logs = cursor.fetchall()
    conn.close()
    
    return jsonify([{
        'id': r[0],
        'timestamp': r[1],
        'ip': r[2],
        'username': r[3],
        'success': r[4],
        'user_agent': r[5]
    } for r in logs])

if __name__ == '__main__':
    os.makedirs('../database', exist_ok=True)
    init_db()
    print("🚀 Site de Teste NETSHIELD rodando em http://0.0.0.0:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)
