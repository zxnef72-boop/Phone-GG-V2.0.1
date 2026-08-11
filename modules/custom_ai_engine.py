# ============================================
# PhoneGG Tool
# Author: NefZx
# ============================================
"""
Custom AI Engine - Analisis kustom dengan heuristik dan pattern matching
Menggabungkan statistik data + aturan pengenalan pola untuk menghasilkan skor risiko
"""
from __future__ import annotations
import re
from typing import Dict, Any, List
from datetime import datetime

# Threshold skor untuk keputusan analisis
SCORE_THRESHOLDS = {
    "CLEAN": 0,      # 0-30: Aman/Clean
    "SUSPICIOUS": 30, # 31-70: Mencurigakan
    "DANGEROUS": 70   # 71-100: Berbahaya
}

# Pola suspicious yang dapat dideteksi
SUSPICIOUS_PATTERNS = {
    "suspicious_keywords": [
        r"hack", r"exploit", r"malware", r"phishing", r"spam", 
        r"bot", r"crawler", r"attack", r"injection", r"xss", r"sql"
    ],
    "suspicious_domains": [
        r"bit\.ly", r"tinyurl\.com", r"short\.link", r"tempmail",
        r"10minutemail", r"guerrillamail", r"disposable"
    ],
    "suspicious_chars": [
        r"[<>\"']", r"script:", r"javascript:", r"data:",
    ]
}

# Pola dangerous yang dapat dideteksi
DANGEROUS_PATTERNS = {
    "dangerous_keywords": [
        r"trojan", r"ransomware", r"keylogger", r"backdoor",
        r"shell", r"rootkit", r"payload", r"exploit.*kit"
    ],
    "dangerous_commands": [
        r"eval\(", r"exec\(", r"system\(", r"passthru\(",
        r"shell_exec\(", r"base64_decode", r"assert\("
    ],
    "dangerous_encodings": [
        r"base64", r"rot13", r"hex.*encode", r"unicode.*escape"
    ]
}


def _calculate_pattern_score(text: str, patterns: Dict[str, List[str]]) -> Dict[str, Any]:
    """
    Hitung skor berdasarkan pattern matching
    
    Args:
        text: Teks yang akan dianalisis
        patterns: Dictionary pattern yang akan dicari
    
    Returns:
        Dictionary dengan skor dan pattern yang ditemukan
    """
    if not text:
        return {"score": 0, "found_patterns": []}
    
    text_lower = text.lower()
    total_score = 0
    found_patterns = []
    
    for category, pattern_list in patterns.items():
        for pattern in pattern_list:
            if re.search(pattern, text_lower, re.IGNORECASE):
                total_score += 10  # +10 skor per pattern yang ditemukan
                found_patterns.append({
                    "category": category,
                    "pattern": pattern,
                    "matched": True
                })
    
    return {"score": total_score, "found_patterns": found_patterns}


def _analyze_data_statistics(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analisis statistik dasar dari input data
    
    Args:
        data: Dictionary input data
    
    Returns:
        Dictionary dengan statistik yang dihitung
    """
    stats = {
        "total_fields": len(data),
        "empty_fields": 0,
        "numeric_fields": 0,
        "text_fields": 0,
        "avg_field_length": 0
    }
    
    total_length = 0
    for key, value in data.items():
        if value is None or value == "":
            stats["empty_fields"] += 1
        elif isinstance(value, (int, float)):
            stats["numeric_fields"] += 1
        elif isinstance(value, str):
            stats["text_fields"] += 1
            total_length += len(value)
    
    if stats["text_fields"] > 0:
        stats["avg_field_length"] = total_length / stats["text_fields"]
    
    return stats


def _apply_custom_rules(data: Dict[str, Any], custom_rules: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Terapkan aturan kustom yang didefinisikan user
    
    Args:
        data: Input data
        custom_rules: Dictionary aturan kustom
    
    Returns:
        Dictionary hasil analisis aturan kustom
    """
    if not custom_rules:
        return {"applied": False, "results": []}
    
    results = []
    total_rule_score = 0
    
    for rule_name, rule_config in custom_rules.items():
        rule_score = 0
        rule_triggered = False
        
        # Cek field condition
        if "field" in rule_config and "condition" in rule_config:
            field = rule_config["field"]
            condition = rule_config["condition"]
            
            if field in data:
                field_value = str(data[field]).lower()
                
                if condition == "contains":
                    if "value" in rule_config and rule_config["value"] in field_value:
                        rule_triggered = True
                        rule_score = rule_config.get("score", 15)
                elif condition == "equals":
                    if "value" in rule_config and field_value == rule_config["value"].lower():
                        rule_triggered = True
                        rule_score = rule_config.get("score", 15)
                elif condition == "length_gt":
                    if "value" in rule_config and len(field_value) > rule_config["value"]:
                        rule_triggered = True
                        rule_score = rule_config.get("score", 10)
        
        if rule_triggered:
            total_rule_score += rule_score
            results.append({
                "rule": rule_name,
                "triggered": True,
                "score": rule_score
            })
    
    return {
        "applied": True,
        "total_score": total_rule_score,
        "results": results
    }


def _generate_ai_summary(score: int, verdict: str, details: Dict[str, Any]) -> str:
    """
    Generate ringkasan analisis AI berdasarkan hasil
    
    Args:
        score: Skor risiko
        verdict: Keputusan analisis
        details: Detail temuan
    
    Returns:
        Teks ringkasan penjelasan
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if verdict == "CLEAN":
        summary = f"Analisis pada {timestamp}: Data terdeteksi CLEAN dengan skor risiko {score}/100. "
        summary += "Tidak ditemukan pola mencurigakan atau berbahaya. Data aman untuk digunakan."
    elif verdict == "SUSPICIOUS":
        suspicious_count = len(details.get("suspicious_patterns", {}).get("found_patterns", []))
        summary = f"Analisis pada {timestamp}: Data terdeteksi SUSPICIOUS dengan skor risiko {score}/100. "
        summary += f"Ditemukan {suspicious_count} pola mencurigakan. Disarankan untuk review manual sebelum digunakan."
    else:  # DANGEROUS
        dangerous_count = len(details.get("dangerous_patterns", {}).get("found_patterns", []))
        summary = f"Analisis pada {timestamp}: Data terdeteksi DANGEROUS dengan skor risiko {score}/100. "
        summary += f"Ditemukan {dangerous_count} pola berbahaya. Sangat tidak disarankan untuk digunakan."
    
    return summary


def analyze_custom_data(data_type: str, input_payload: dict, custom_rules: dict = None) -> dict:
    """
    Fungsi utama Custom AI Engine untuk analisis data kustom
    
    Args:
        data_type: Tipe data yang dianalisis (text, url, email, phone, generic)
        input_payload: Dictionary berisi data yang akan dianalisis
        custom_rules: Dictionary aturan kustom opsional
    
    Returns:
        Dictionary hasil analisis terstruktur:
        {
            "status": "success" / "error",
            "score": 0-100,
            "verdict": "CLEAN" / "SUSPICIOUS" / "DANGEROUS",
            "details": {...},
            "ai_summary": "Teks penjelasan"
        }
    """
    try:
        # Validasi input
        if not input_payload or not isinstance(input_payload, dict):
            return {
                "status": "error",
                "error": "Input payload tidak valid atau kosong"
            }
        
        # Gabungkan semua text untuk pattern matching
        combined_text = " ".join(str(v) for v in input_payload.values() if v)
        
        # Analisis statistik data
        statistics = _analyze_data_statistics(input_payload)
        
        # Analisis pattern suspicious
        suspicious_analysis = _calculate_pattern_score(combined_text, SUSPICIOUS_PATTERNS)
        
        # Analisis pattern dangerous
        dangerous_analysis = _calculate_pattern_score(combined_text, DANGEROUS_PATTERNS)
        
        # Terapkan aturan kustom jika ada
        custom_analysis = _apply_custom_rules(input_payload, custom_rules)
        
        # Hitung total skor
        base_score = suspicious_analysis["score"] + dangerous_analysis["score"]
        custom_score = custom_analysis.get("total_score", 0) if custom_analysis.get("applied") else 0
        
        # Tambahkan skor dari statistik (jika ada indikator anomali)
        stats_score = 0
        if statistics["empty_fields"] > len(input_payload) * 0.5:
            stats_score += 5  # Banyak field kosong
        if statistics["avg_field_length"] > 1000:
            stats_score += 5  # Text terlalu panjang
        
        total_score = min(base_score + custom_score + stats_score, 100)
        
        # Tentukan verdict berdasarkan threshold
        if total_score <= SCORE_THRESHOLDS["SUSPICIOUS"]:
            verdict = "CLEAN"
        elif total_score <= SCORE_THRESHOLDS["DANGEROUS"]:
            verdict = "SUSPICIOUS"
        else:
            verdict = "DANGEROUS"
        
        # Compile details
        details = {
            "data_type": data_type,
            "statistics": statistics,
            "suspicious_patterns": suspicious_analysis,
            "dangerous_patterns": dangerous_analysis,
            "custom_rules": custom_analysis,
            "input_fields": list(input_payload.keys())
        }
        
        # Generate AI summary
        ai_summary = _generate_ai_summary(total_score, verdict, details)
        
        return {
            "status": "success",
            "score": total_score,
            "verdict": verdict,
            "details": details,
            "ai_summary": ai_summary,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        return {
            "status": "error",
            "error": f"Error dalam analisis: {str(e)}"
        }


# Fungsi helper untuk testing dan debugging
def get_default_test_data() -> dict:
    """
    Mengembalikan data test default untuk testing modul
    
    Returns:
        Dictionary sample data untuk testing
    """
    return {
        "text": "Sample text for analysis",
        "url": "https://example.com",
        "email": "test@example.com",
        "metadata": "test metadata"
    }


def get_default_custom_rules() -> dict:
    """
    Mengembalikan aturan kustom default untuk testing
    
    Returns:
        Dictionary sample custom rules
    """
    return {
        "check_short_url": {
            "field": "url",
            "condition": "contains",
            "value": "bit.ly",
            "score": 20
        },
        "check_email_domain": {
            "field": "email",
            "condition": "contains",
            "value": "tempmail",
            "score": 25
        }
    }
