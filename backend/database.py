# =============================================================================
# NETSHIELD v2 — database.py
# Base de dados completa: utilizadores, admins, logs, IPs bloqueados
# =============================================================================

import sqlite3
import hashlib
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "netshield.db")

def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    conn = get_conn()
    c = conn.cursor()

    # Tabela de utilizadores
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT UNIQUE NOT NULL,
            email       TEXT UNIQUE NOT NULL,
            password    TEXT NOT NULL,
            role        TEXT NOT NULL DEFAULT 'user',  -- 'user' ou 'admin'
            full_name   TEXT DEFAULT '',
            created_at  TEXT NOT NULL,
            last_login  TEXT DEFAULT NULL,
            active      INTEGER DEFAULT 1
        )
    """)

    # Tabela de sessões (tokens simples)
    c.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token       TEXT PRIMARY KEY,
            user_id     INTEGER NOT NULL,
            created_at  TEXT NOT NULL,
            expires_at  TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    # Tabela de logs de tráfego/análise
    c.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp           TEXT NOT NULL,
            device_id           TEXT NOT NULL,
            flow_duration       REAL DEFAULT 0,
            fwd_packets         REAL DEFAULT 0,
            bwd_packets         REAL DEFAULT 0,
            bytes_per_sec       REAL DEFAULT 0,
            packets_per_sec     REAL DEFAULT 0,
            avg_packet_size     REAL DEFAULT 0,
            syn_count           REAL DEFAULT 0,
            inter_arrival_time  REAL DEFAULT 0,
            active_mean         REAL DEFAULT 0,
            resultado           TEXT NOT NULL,
            risk_score          REAL DEFAULT 0,
            confidence          REAL DEFAULT 0,
            attack_type         TEXT DEFAULT 'N/A',
            explanation         TEXT DEFAULT '',
            source_ip           TEXT DEFAULT 'N/A',
            blocked             INTEGER DEFAULT 0
        )
    """)

    # Tabela de IPs bloqueados
    c.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip          TEXT UNIQUE NOT NULL,
            reason      TEXT DEFAULT '',
            blocked_at  TEXT NOT NULL,
            blocked_by  TEXT DEFAULT 'sistema',
            active      INTEGER DEFAULT 1
        )
    """)

    # Tabela de alertas
    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            level       TEXT NOT NULL,
            message     TEXT NOT NULL,
            read        INTEGER DEFAULT 0
        )
    """)

    conn.commit()

    # Criar admin padrão se não existir
    c.execute("SELECT id FROM users WHERE username='admin'")
    if not c.fetchone():
        _create_user(c, 'admin', 'admin@netshield.ao', 'admin123', 'Administrador NetShield', 'admin')
        print("[DB] Admin criado — user: admin | senha: admin123")

    conn.commit()
    conn.close()
    print(f"[DB] Base de dados pronta: {DB_PATH}")


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def _create_user(cursor, username, email, password, full_name, role='user'):
    cursor.execute("""
        INSERT INTO users (username, email, password, full_name, role, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (username, email, hash_password(password), full_name, role, datetime.now().isoformat()))


# =============================================================================
# AUTH
# =============================================================================
def register_user(username, email, password, full_name, role='user'):
    conn = get_conn()
    c = conn.cursor()
    try:
        c.execute("SELECT id FROM users WHERE username=? OR email=?", (username, email))
        if c.fetchone():
            return None, "Utilizador ou email já existe"
        _create_user(c, username, email, password, full_name, role)
        conn.commit()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = dict(c.fetchone())
        user.pop('password', None)
        return user, None
    except Exception as e:
        return None, str(e)
    finally:
        conn.close()

def login_user(username, password):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE (username=? OR email=?) AND active=1", (username, username))
    row = c.fetchone()
    if not row:
        conn.close()
        return None, "Utilizador não encontrado"
    user = dict(row)
    if user['password'] != hash_password(password):
        conn.close()
        return None, "Senha incorrecta"
    # Gerar token
    import secrets
    token = secrets.token_hex(32)
    now = datetime.now().isoformat()
    from datetime import timedelta
    expires = (datetime.now() + timedelta(hours=24)).isoformat()
    c.execute("INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?,?,?,?)",
              (token, user['id'], now, expires))
    c.execute("UPDATE users SET last_login=? WHERE id=?", (now, user['id']))
    conn.commit()
    conn.close()
    user.pop('password', None)
    return {"token": token, "user": user}, None

def get_user_by_token(token):
    conn = get_conn()
    c = conn.cursor()
    now = datetime.now().isoformat()
    c.execute("""
        SELECT u.* FROM users u
        JOIN sessions s ON s.user_id = u.id
        WHERE s.token=? AND s.expires_at > ? AND u.active=1
    """, (token, now))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    user = dict(row)
    user.pop('password', None)
    return user

def logout_user(token):
    conn = get_conn()
    conn.execute("DELETE FROM sessions WHERE token=?", (token,))
    conn.commit()
    conn.close()

def get_all_users():
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT id, username, email, full_name, role, created_at, last_login, active FROM users ORDER BY id")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def toggle_user_active(user_id, active):
    conn = get_conn()
    conn.execute("UPDATE users SET active=? WHERE id=?", (active, user_id))
    conn.commit()
    conn.close()


# =============================================================================
# LOGS
# =============================================================================
def insert_log(data: dict):
    conn = get_conn()
    c = conn.cursor()
    c.execute("""
        INSERT INTO logs (timestamp, device_id, flow_duration, fwd_packets, bwd_packets,
            bytes_per_sec, packets_per_sec, avg_packet_size, syn_count, inter_arrival_time,
            active_mean, resultado, risk_score, confidence, attack_type, explanation, source_ip, blocked)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        datetime.now().isoformat(),
        data.get('device_id', 'unknown'),
        data.get('flow_duration', 0),
        data.get('fwd_packets', 0),
        data.get('bwd_packets', 0),
        data.get('bytes_per_sec', 0),
        data.get('packets_per_sec', 0),
        data.get('avg_packet_size', 0),
        data.get('syn_count', 0),
        data.get('inter_arrival_time', 0),
        data.get('active_mean', 0),
        data.get('resultado', 'normal'),
        data.get('risk_score', 0),
        data.get('confidence', 0),
        data.get('attack_type', 'N/A'),
        data.get('explanation', ''),
        data.get('source_ip', 'N/A'),
        data.get('blocked', 0),
    ))
    conn.commit()
    log_id = c.lastrowid
    conn.close()
    return log_id

def get_logs(limit=50, resultado=None, date_from=None, date_to=None):
    conn = get_conn()
    c = conn.cursor()
    q = "SELECT * FROM logs WHERE 1=1"
    params = []
    if resultado:
        q += " AND resultado=?"
        params.append(resultado)
    if date_from:
        q += " AND timestamp >= ?"
        params.append(date_from)
    if date_to:
        q += " AND timestamp <= ?"
        params.append(date_to)
    q += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    c.execute(q, params)
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def get_stats():
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM logs")
    total = c.fetchone()[0]
    c.execute("SELECT resultado, COUNT(*) FROM logs GROUP BY resultado")
    por_resultado = {r[0]: r[1] for r in c.fetchall()}
    c.execute("SELECT timestamp, packets_per_sec, risk_score, resultado FROM logs ORDER BY id DESC LIMIT 30")
    recentes = [dict(r) for r in c.fetchall()]
    recentes.reverse()
    c.execute("SELECT COUNT(*) FROM blocked_ips WHERE active=1")
    blocked_count = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM alerts WHERE read=0")
    unread_alerts = c.fetchone()[0]
    conn.close()
    return {
        "total": total,
        "por_resultado": por_resultado,
        "recentes": recentes,
        "blocked_ips_count": blocked_count,
        "unread_alerts": unread_alerts
    }

def clear_logs():
    conn = get_conn()
    conn.execute("DELETE FROM logs")
    conn.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()


# =============================================================================
# BLOCKED IPs
# =============================================================================
def block_ip(ip, reason='', blocked_by='sistema'):
    conn = get_conn()
    c = conn.cursor()
    try:
        c.execute("SELECT id FROM blocked_ips WHERE ip=?", (ip,))
        existing = c.fetchone()
        if existing:
            c.execute("UPDATE blocked_ips SET active=1, reason=?, blocked_at=?, blocked_by=? WHERE ip=?",
                      (reason, datetime.now().isoformat(), blocked_by, ip))
        else:
            c.execute("INSERT INTO blocked_ips (ip, reason, blocked_at, blocked_by) VALUES (?,?,?,?)",
                      (ip, reason, datetime.now().isoformat(), blocked_by))
        conn.commit()
        return True
    except:
        return False
    finally:
        conn.close()

def unblock_ip(ip):
    conn = get_conn()
    conn.execute("UPDATE blocked_ips SET active=0 WHERE ip=?", (ip,))
    conn.commit()
    conn.close()

def get_blocked_ips():
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM blocked_ips WHERE active=1 ORDER BY blocked_at DESC")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def is_ip_blocked(ip):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT id FROM blocked_ips WHERE ip=? AND active=1", (ip,))
    result = c.fetchone() is not None
    conn.close()
    return result


# =============================================================================
# ALERTS
# =============================================================================
def insert_alert(level, message):
    conn = get_conn()
    conn.execute("INSERT INTO alerts (timestamp, level, message) VALUES (?,?,?)",
                 (datetime.now().isoformat(), level, message))
    conn.commit()
    conn.close()

def get_alerts(limit=20):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def mark_alerts_read():
    conn = get_conn()
    conn.execute("UPDATE alerts SET read=1")
    conn.commit()
    conn.close()
