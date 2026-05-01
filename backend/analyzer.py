# =============================================================================
# NETSHIELD v2 — analyzer.py
# Motor de IA usando o modelo TFLite treinado no Edge Impulse
#
# Modelo: 9 features de entrada, 2 classes de saída
# Input:  [flow_duration, fwd_packets, bwd_packets, bytes_per_sec,
#           packets_per_sec, avg_packet_size, syn_count, inter_arrival_time, active_mean]
# Output: [prob_normal, prob_ataque]  (classe 0 = normal, classe 1 = ataque/DDoS)
# =============================================================================

import numpy as np
import os
import math

MODEL_PATH = os.path.join(os.path.dirname(__file__), "modelo.tflite")

# Carregar o modelo TFLite uma única vez no arranque (eficiente)
_interpreter = None

def _get_interpreter():
    global _interpreter
    if _interpreter is None:
        try:
            import tensorflow as tf
            _interpreter = tf.lite.Interpreter(model_path=MODEL_PATH)
            _interpreter.allocate_tensors()
            print(f"[IA] Modelo TFLite carregado: {MODEL_PATH}")
        except Exception as e:
            print(f"[IA] ERRO ao carregar modelo: {e}")
            _interpreter = None
    return _interpreter


# =============================================================================
# Parâmetros de normalização baseados nos dados CICIDS2017
# O modelo foi treinado com estes ranges — normalizar os inputs é essencial
# para que o modelo funcione correctamente com dados reais do ESP32
# =============================================================================
FEATURE_RANGES = {
    # feature: (min_normal, max_normal, max_attack)
    'flow_duration':      (0,       200000,   500000),
    'fwd_packets':        (1,       500,      60000),
    'bwd_packets':        (0,       400,      2000),
    'bytes_per_sec':      (0,       500000,   10000000),
    'packets_per_sec':    (0,       500,      15000),
    'avg_packet_size':    (40,      1500,     1500),
    'syn_count':          (0,       50,       10000),
    'inter_arrival_time': (0,       5000,     5000),
    'active_mean':        (0,       10000,    10000),
}


def extract_features(data: dict) -> np.ndarray:
    """
    Extrai e organiza as 9 features na ordem exacta que o modelo espera.
    Valores em falta são substituídos por 0.
    """
    features = [
        float(data.get('flow_duration',      0)),
        float(data.get('fwd_packets',        0)),
        float(data.get('bwd_packets',        0)),
        float(data.get('bytes_per_sec',      0)),
        float(data.get('packets_per_sec',    0)),
        float(data.get('avg_packet_size',    0)),
        float(data.get('syn_count',          0)),
        float(data.get('inter_arrival_time', 0)),
        float(data.get('active_mean',        0)),
    ]
    return np.array([features], dtype=np.float32)


def analyze_with_ai(data: dict) -> dict:
    """
    Função principal de análise.
    Recebe dados do ESP32, classifica com IA, gera explicação.
    Devolve: resultado, risk_score (0-100), confidence, attack_type, explanation
    """
    features = extract_features(data)
    interp = _get_interpreter()

    prob_normal = 0.5
    prob_ataque = 0.5

    if interp is not None:
        try:
            inp = interp.get_input_details()
            out = interp.get_output_details()
            interp.set_tensor(inp[0]['index'], features)
            interp.invoke()
            output = interp.get_tensor(out[0]['index'])[0]
            prob_normal = float(output[0])
            prob_ataque = float(output[1])
        except Exception as e:
            print(f"[IA] Erro na inferência: {e}")
            # Fallback para análise por regras
            return _fallback_analysis(data)
    else:
        return _fallback_analysis(data)

    # ==========================================================================
    # Calcular risk_score (0–100)
    # Não é apenas a probabilidade bruta — considera múltiplos factores
    # ==========================================================================
    base_score = prob_ataque * 100

    # Ajuste por features individuais (indicadores clássicos de ataque)
    pps         = float(data.get('packets_per_sec', 0))
    fwd         = float(data.get('fwd_packets', 0))
    syn         = float(data.get('syn_count', 0))
    avg_pkt     = float(data.get('avg_packet_size', 700))
    bytes_ps    = float(data.get('bytes_per_sec', 0))

    boost = 0
    if pps > 3000:    boost += 8
    if pps > 7000:    boost += 12
    if fwd > 10000:   boost += 10
    if fwd > 30000:   boost += 15
    if syn > 500:     boost += 8
    if syn > 3000:    boost += 12
    if avg_pkt < 100: boost += 5    # pacotes muito pequenos = flood
    if bytes_ps > 2000000: boost += 8

    risk_score = min(100, base_score + boost)

    # Determinar resultado e tipo de ataque
    resultado, attack_type, explanation = _classify_result(
        risk_score, prob_ataque, data
    )

    return {
        "resultado":    resultado,
        "risk_score":   round(risk_score, 1),
        "confidence":   round(max(prob_normal, prob_ataque) * 100, 1),
        "attack_type":  attack_type,
        "explanation":  explanation,
        "prob_normal":  round(prob_normal, 4),
        "prob_ataque":  round(prob_ataque, 4),
    }


def _classify_result(risk_score, prob_ataque, data):
    """
    Determina resultado, tipo e explicação com base no score e features.
    """
    pps      = float(data.get('packets_per_sec', 0))
    fwd      = float(data.get('fwd_packets', 0))
    syn      = float(data.get('syn_count', 0))
    avg_pkt  = float(data.get('avg_packet_size', 700))
    bwd      = float(data.get('bwd_packets', 0))
    bytes_ps = float(data.get('bytes_per_sec', 0))

    # Identificar tipo de ataque pelas características
    attack_type = "N/A"
    reasons = []

    if risk_score >= 60:
        # DDoS: muitos pacotes, muitos SYN, pacotes pequenos
        if pps > 2000 or fwd > 10000:
            attack_type = "DDoS (Flood de pacotes)"
            reasons.append(f"Flood detectado: {pps:.0f} pkt/s")
        # SYN Flood
        if syn > 500 and avg_pkt < 200:
            attack_type = "SYN Flood"
            reasons.append(f"SYN excessivo: {syn:.0f} pacotes SYN")
        # Assimetria extrema (mais envio que recepção)
        if fwd > 0 and bwd < fwd * 0.05:
            attack_type = "DDoS Unidireccional"
            reasons.append("Tráfego fortemente assimétrico")
        if bytes_ps > 3000000:
            reasons.append(f"Volume anormal: {bytes_ps/1000000:.1f} MB/s")
        if not reasons:
            attack_type = "Ataque (padrão anormal)"
            reasons.append("Múltiplos indicadores de anomalia detectados")

    # Determinar resultado
    if risk_score >= 65:
        resultado = "ataque"
    elif risk_score >= 35:
        resultado = "suspeito"
        if not reasons:
            reasons.append("Comportamento fora do padrão normal da rede")
        if attack_type == "N/A":
            attack_type = "Suspeito"
    else:
        resultado = "normal"
        reasons = ["Tráfego dentro dos parâmetros normais"]
        attack_type = "N/A"

    return resultado, attack_type, " | ".join(reasons)


def _fallback_analysis(data):
    """Análise por regras — usado quando o modelo TFLite não está disponível."""
    pps      = float(data.get('packets_per_sec', 0))
    fwd      = float(data.get('fwd_packets', 0))
    syn      = float(data.get('syn_count', 0))
    bytes_ps = float(data.get('bytes_per_sec', 0))

    score = 0
    reasons = []

    if pps > 7000:   score += 40; reasons.append(f"Flood crítico: {pps:.0f} pkt/s")
    elif pps > 2000: score += 20; reasons.append(f"Pico de pacotes: {pps:.0f} pkt/s")

    if fwd > 20000:  score += 35; reasons.append(f"Pacotes encaminhados: {fwd:.0f}")
    elif fwd > 5000: score += 18

    if syn > 3000:   score += 20; reasons.append(f"SYN flood: {syn:.0f}")

    if bytes_ps > 3000000: score += 15; reasons.append(f"Volume: {bytes_ps/1e6:.1f}MB/s")

    score = min(100, score)

    if score >= 65:
        return {"resultado": "ataque",  "risk_score": score, "confidence": 80,
                "attack_type": "DDoS (fallback)", "explanation": " | ".join(reasons),
                "prob_normal": 0.1, "prob_ataque": 0.9}
    elif score >= 35:
        return {"resultado": "suspeito", "risk_score": score, "confidence": 65,
                "attack_type": "Suspeito", "explanation": " | ".join(reasons) or "Padrão anormal",
                "prob_normal": 0.4, "prob_ataque": 0.6}
    else:
        return {"resultado": "normal", "risk_score": score, "confidence": 90,
                "attack_type": "N/A", "explanation": "Tráfego normal",
                "prob_normal": 0.9, "prob_ataque": 0.1}


# =============================================================================
# Gerador de dados de simulação de ataque (para botão "Simular Ataque")
# Baseado exactamente nas features que o modelo conhece
# =============================================================================
def generate_attack_data(attack_type="ddos"):
    """Gera dados realistas de ataque para simulação no dashboard."""
    import random

    if attack_type == "ddos":
        return {
            "flow_duration":      random.uniform(50, 300),
            "fwd_packets":        random.uniform(25000, 55000),
            "bwd_packets":        random.uniform(2, 20),
            "bytes_per_sec":      random.uniform(3000000, 8000000),
            "packets_per_sec":    random.uniform(6000, 12000),
            "avg_packet_size":    random.uniform(40, 80),
            "syn_count":          random.uniform(5000, 9000),
            "inter_arrival_time": random.uniform(5, 30),
            "active_mean":        random.uniform(10, 100),
        }
    elif attack_type == "syn_flood":
        return {
            "flow_duration":      random.uniform(100, 500),
            "fwd_packets":        random.uniform(15000, 40000),
            "bwd_packets":        random.uniform(0, 5),
            "bytes_per_sec":      random.uniform(500000, 2000000),
            "packets_per_sec":    random.uniform(3000, 8000),
            "avg_packet_size":    random.uniform(40, 60),
            "syn_count":          random.uniform(8000, 15000),
            "inter_arrival_time": random.uniform(1, 10),
            "active_mean":        random.uniform(5, 50),
        }
    else:  # normal
        return {
            "flow_duration":      random.uniform(30000, 80000),
            "fwd_packets":        random.uniform(80, 250),
            "bwd_packets":        random.uniform(60, 180),
            "bytes_per_sec":      random.uniform(50000, 150000),
            "packets_per_sec":    random.uniform(80, 200),
            "avg_packet_size":    random.uniform(600, 900),
            "syn_count":          random.uniform(3, 15),
            "inter_arrival_time": random.uniform(500, 2000),
            "active_mean":        random.uniform(3000, 8000),
        }
