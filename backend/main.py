# =============================================================================
# NETSHIELD v2 — main.py
# =============================================================================

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import Optional
import uvicorn, os

from database import (
    init_db, insert_log, get_logs, get_stats, clear_logs,
    register_user, login_user, get_user_by_token, logout_user,
    get_all_users, toggle_user_active,
    block_ip, unblock_ip, get_blocked_ips, is_ip_blocked,
    insert_alert, get_alerts, mark_alerts_read
)
from analyzer import analyze_with_ai, generate_attack_data

app = FastAPI(title="NetShield Angola v2")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── helpers ──────────────────────────────────────────────────────────────────
def require_auth(authorization: str = ""):
    token = authorization.replace("Bearer ", "").strip()
    user = get_user_by_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Sessão inválida ou expirada")
    return user

def require_admin(authorization: str = ""):
    user = require_auth(authorization)
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Acesso restrito a administradores")
    return user

# ── startup ───────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    init_db()
    fe = os.path.join(os.path.dirname(__file__), "..", "frontend")
    if os.path.exists(fe):
        app.mount("/app", StaticFiles(directory=fe, html=True), name="frontend")
    ts = os.path.join(os.path.dirname(__file__), "..", "target_site")
    if os.path.exists(ts):
        app.mount("/site", StaticFiles(directory=ts, html=True), name="target_site")
    print("[OK] NetShield v2 pronto em http://0.0.0.0:8000/app")

# ══════════════════════════════════════════════════════════════════════════════
# AUTH
# ══════════════════════════════════════════════════════════════════════════════
class RegisterBody(BaseModel):
    username: str
    email: str
    password: str
    full_name: Optional[str] = ""

class LoginBody(BaseModel):
    username: str
    password: str

@app.post("/auth/register")
async def register(body: RegisterBody):
    user, err = register_user(body.username, body.email, body.password, body.full_name)
    if err:
        raise HTTPException(400, detail=err)
    return {"ok": True, "user": user}

@app.post("/auth/login")
async def login(body: LoginBody):
    result, err = login_user(body.username, body.password)
    if err:
        raise HTTPException(401, detail=err)
    return result

@app.post("/auth/logout")
async def logout(authorization: str = Header("")):
    token = authorization.replace("Bearer ", "").strip()
    logout_user(token)
    return {"ok": True}

@app.get("/auth/me")
async def me(authorization: str = Header("")):
    return require_auth(authorization)

# ══════════════════════════════════════════════════════════════════════════════
# ANÁLISE — recebe dados do ESP32 ou simulador
# ══════════════════════════════════════════════════════════════════════════════
class TrafficData(BaseModel):
    device_id:           str
    flow_duration:       Optional[float] = 0
    fwd_packets:         Optional[float] = 0
    bwd_packets:         Optional[float] = 0
    bytes_per_sec:       Optional[float] = 0
    packets_per_sec:     Optional[float] = 0
    avg_packet_size:     Optional[float] = 0
    syn_count:           Optional[float] = 0
    inter_arrival_time:  Optional[float] = 0
    active_mean:         Optional[float] = 0
    source_ip:           Optional[str]   = "N/A"

@app.post("/analyze")
async def analyze(data: TrafficData, request: Request):
    d = data.dict()

    # Verificar se IP está bloqueado
    if d["source_ip"] != "N/A" and is_ip_blocked(d["source_ip"]):
        return {"resultado": "bloqueado", "risk_score": 100,
                "message": f"IP {d['source_ip']} bloqueado"}

    result = analyze_with_ai(d)
    d.update(result)

    # Auto-bloquear se ataque e IP conhecido
    if result["resultado"] == "ataque" and d["source_ip"] != "N/A":
        block_ip(d["source_ip"], reason=result.get("attack_type","ataque"), blocked_by="auto")
        d["blocked"] = 1

    log_id = insert_log(d)

    # Gerar alerta
    if result["resultado"] == "ataque":
        insert_alert("critical",
            f"ATAQUE detectado! Tipo: {result['attack_type']} | Score: {result['risk_score']:.0f}/100 | Device: {d['device_id']}")
    elif result["resultado"] == "suspeito":
        insert_alert("warning",
            f"Tráfego suspeito | Score: {result['risk_score']:.0f}/100 | Device: {d['device_id']}")

    emoji = {"normal":"✅","suspeito":"⚠️","ataque":"🚨"}.get(result["resultado"],"?")
    print(f"{emoji} [{d['device_id']}] {result['resultado'].upper()} | score:{result['risk_score']:.0f} | {result['explanation'][:60]}")

    return {**result, "log_id": log_id, "device_id": d["device_id"]}

# ══════════════════════════════════════════════════════════════════════════════
# SIMULAÇÃO DE ATAQUE (botão no dashboard)
# ══════════════════════════════════════════════════════════════════════════════
class SimulateBody(BaseModel):
    attack_type: Optional[str] = "ddos"
    rounds:      Optional[int] = 5

@app.post("/simulate")
async def simulate(body: SimulateBody, authorization: str = Header("")):
    require_auth(authorization)
    results = []
    for i in range(min(body.rounds, 10)):
        attack_data = generate_attack_data(body.attack_type)
        attack_data["device_id"] = "simulador"
        attack_data["source_ip"] = f"192.168.99.{100+i}"
        result = analyze_with_ai(attack_data)
        attack_data.update(result)
        insert_log(attack_data)
        if result["resultado"] == "ataque":
            insert_alert("critical",
                f"[SIMULAÇÃO] {result['attack_type']} | Score: {result['risk_score']:.0f}/100")
        results.append({**result, "round": i+1})
    return {"ok": True, "rounds": len(results), "results": results}

# ══════════════════════════════════════════════════════════════════════════════
# LOGS & STATS
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/logs")
async def logs(authorization: str = Header(""), limit: int = 50,
               resultado: Optional[str] = None,
               date_from: Optional[str] = None,
               date_to: Optional[str] = None):
    require_auth(authorization)
    return get_logs(limit, resultado, date_from, date_to)

@app.get("/stats")
async def stats(authorization: str = Header("")):
    require_auth(authorization)
    return get_stats()

@app.delete("/logs")
async def delete_logs(authorization: str = Header("")):
    require_admin(authorization)
    clear_logs()
    return {"ok": True}

@app.get("/status")
async def status():
    return {"status": "online", "sistema": "NetShield Angola v2"}

# ══════════════════════════════════════════════════════════════════════════════
# IPs BLOQUEADOS
# ══════════════════════════════════════════════════════════════════════════════
class BlockIPBody(BaseModel):
    ip: str
    reason: Optional[str] = ""

@app.get("/blocked")
async def blocked(authorization: str = Header("")):
    require_auth(authorization)
    return get_blocked_ips()

@app.post("/blocked")
async def block(body: BlockIPBody, authorization: str = Header("")):
    user = require_auth(authorization)
    block_ip(body.ip, body.reason, blocked_by=user["username"])
    insert_alert("info", f"IP {body.ip} bloqueado manualmente por {user['username']}")
    return {"ok": True}

@app.delete("/blocked/{ip}")
async def unblock(ip: str, authorization: str = Header("")):
    require_admin(authorization)
    unblock_ip(ip)
    return {"ok": True}

# ══════════════════════════════════════════════════════════════════════════════
# ALERTAS
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/alerts")
async def alerts(authorization: str = Header(""), limit: int = 20):
    require_auth(authorization)
    return get_alerts(limit)

@app.post("/alerts/read")
async def read_alerts(authorization: str = Header("")):
    require_auth(authorization)
    mark_alerts_read()
    return {"ok": True}

# ══════════════════════════════════════════════════════════════════════════════
# ADMIN — gestão de utilizadores
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/admin/users")
async def admin_users(authorization: str = Header("")):
    require_admin(authorization)
    return get_all_users()

class ToggleUserBody(BaseModel):
    active: int

@app.patch("/admin/users/{user_id}")
async def admin_toggle_user(user_id: int, body: ToggleUserBody,
                             authorization: str = Header("")):
    require_admin(authorization)
    toggle_user_active(user_id, body.active)
    return {"ok": True}

# ── entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
