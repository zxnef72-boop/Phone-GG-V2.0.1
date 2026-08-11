# ============================================================
#  AI Native Engine for PhoneGG - Enhanced Smart Analysis
#  AI Native Engine (Credit: NEFZX) - 100% Internal & Offline
# ============================================================
import os
import re
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from difflib import SequenceMatcher

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AINativeEngine:
    """
    AI Native Engine - Local intelligence analysis using rule-based 
    heuristics and pattern matching. No external API dependencies.
    
    Credit: NEFZX
    """
    
    def __init__(self):
        """Initialize AI Native Engine."""
        self.engine_name = "AI Native Engine"
        self.engine_credit = "NEFZX"
        self.engine_version = "2.0.0"
        print(f"[{self.engine_name}] Initialized v{self.engine_version} (Credit: {self.engine_credit})")
    
    def _create_system_prompt(self) -> str:
        return """You are an expert Cyber Intelligence Analyst specializing in telecommunications security and OSINT (Open Source Intelligence). Your role is to analyze phone number data and provide comprehensive security assessments.

## Your Capabilities:
- Analyze phone number patterns and risk indicators
- Identify potential security threats and fraud patterns
- Provide actionable intelligence recommendations
- Assess risk levels based on multiple factors
- Suggest further investigation steps

## Analysis Framework:
1. **Risk Assessment**: Evaluate the overall threat level (Low/Medium/High)
2. **Pattern Analysis**: Identify suspicious number patterns or behaviors
3. **Geographic Intelligence**: Assess geographic risk factors
4. **Recommendations**: Provide specific, actionable security measures
5. **Further Investigation**: Suggest additional OSINT techniques

## Response Format:
Provide analysis in the following JSON structure:
{
    "risk_summary": "Brief summary of overall risk level",
    "threat_score": 0-100,
    "key_findings": ["Finding 1", "Finding 2", ...],
    "risk_factors": ["Factor 1", "Factor 2", ...],
    "recommendations": ["Recommendation 1", "Recommendation 2", ...],
    "investigation_steps": ["Step 1", "Step 2", ...],
    "confidence_level": "High/Medium/Low"
}

## Important Guidelines:
- Be objective and evidence-based
- Avoid making definitive claims without sufficient data
- Highlight uncertainty and limitations in your analysis
- Provide conservative risk estimates when data is limited
- Focus on actionable intelligence rather than speculation
- Consider cultural and geographic context in your analysis
- Maintain professional security analyst tone"""

    def analyze_phone_data(self, phone_number: str, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        try:
            context = self._prepare_analysis_context(phone_number, raw_data)
            analysis = self._perform_local_analysis(phone_number, context)
            analysis["metadata"] = {
                "engine": self.engine_name,
                "engine_credit": self.engine_credit,
                "version": self.engine_version,
                "analyzed_at": context.get("timestamp"),
                "data_sources": list(context.keys()),
                "analysis_type": "local_heuristic"
            }
            return analysis
        except Exception as e:
            return {
                "error": f"AI Native Engine analysis failed: {str(e)}",
                "risk_summary": "Analysis error",
                "threat_score": 50,
                "recommendations": ["Local analysis encountered an error"],
                "metadata": {
                    "engine": self.engine_name,
                    "engine_credit": self.engine_credit,
                    "error": str(e)
                }
            }
    
    def _prepare_analysis_context(self, phone_number: str, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        context = {
            "phone_number": phone_number,
            "timestamp": datetime.now().isoformat()
        }
        if "operator_info" in raw_data:
            context["operator_info"] = raw_data["operator_info"]
        if "ml_risk_assessment" in raw_data:
            context["ml_risk_assessment"] = raw_data["ml_risk_assessment"]
        if "google_intelligence" in raw_data:
            context["google_intelligence"] = raw_data["google_intelligence"]
        return context
    
    def _perform_local_analysis(self, phone_number: str, context: Dict[str, Any]) -> Dict[str, Any]:
        key_findings = []
        risk_factors = []
        recommendations = []
        investigation_steps = []
        
        pattern_analysis = self._analyze_number_patterns(phone_number)
        key_findings.extend(pattern_analysis["findings"])
        risk_factors.extend(pattern_analysis["risk_factors"])
        
        if "operator_info" in context:
            operator_analysis = self._analyze_operator(context["operator_info"])
            key_findings.extend(operator_analysis["findings"])
            recommendations.extend(operator_analysis["recommendations"])
        
        if "ml_risk_assessment" in context:
            ml_analysis = self._analyze_ml_prediction(context["ml_risk_assessment"])
            key_findings.extend(ml_analysis["findings"])
            risk_factors.extend(ml_analysis["risk_factors"])
        
        threat_score = self._calculate_threat_score(risk_factors, key_findings)
        risk_summary = self._generate_risk_summary(threat_score, key_findings)
        if not recommendations:
            recommendations = self._generate_default_recommendations(threat_score)
        if not investigation_steps:
            investigation_steps = self._generate_investigation_steps(phone_number, context)
        confidence_level = self._determine_confidence(context, key_findings)
        
        return {
            "risk_summary": risk_summary,
            "threat_score": threat_score,
            "key_findings": key_findings,
            "risk_factors": risk_factors,
            "recommendations": recommendations,
            "investigation_steps": investigation_steps,
            "confidence_level": confidence_level
        }
    
    def _analyze_number_patterns(self, phone_number: str) -> Dict[str, List[str]]:
        findings = []
        risk_factors = []
        sequential_count = 0
        for i in range(len(phone_number) - 1):
            if phone_number[i].isdigit() and phone_number[i+1].isdigit():
                if abs(int(phone_number[i]) - int(phone_number[i+1])) == 1:
                    sequential_count += 1
        if sequential_count > 3:
            findings.append("Nomor mengandung pola berurutan yang mencurigakan")
            risk_factors.append("Pola angka berurutan yang tidak wajar")
        
        repeated_count = 0
        for i in range(len(phone_number) - 1):
            if phone_number[i] == phone_number[i+1]:
                repeated_count += 1
        if repeated_count > 2:
            findings.append("Nomor mengandung pola berulang yang mencurigakan")
            risk_factors.append("Pola angka berulang yang tidak wajar")
        
        scam_patterns = ["12345", "54321", "11111", "00000", "123456"]
        for pattern in scam_patterns:
            if pattern in phone_number:
                findings.append(f"Nomor mengandung pola umum penipuan: {pattern}")
                risk_factors.append("Pola angka yang sering digunakan untuk penipuan")
        
        return {"findings": findings, "risk_factors": risk_factors}
    
    def _analyze_operator(self, operator_info: Dict[str, Any]) -> Dict[str, List[str]]:
        findings = []
        recommendations = []
        operator = operator_info.get("operator", "Unknown")
        if operator != "Unknown":
            findings.append(f"Operator terdeteksi: {operator}")
            recommendations.append(f"Verifikasi informasi operator dengan {operator} jika diperlukan")
        return {"findings": findings, "recommendations": recommendations}
    
    def _analyze_ml_prediction(self, ml_prediction: Dict[str, Any]) -> Dict[str, List[str]]:
        findings = []
        risk_factors = []
        risk_level = ml_prediction.get("risk_level", "Unknown")
        findings.append(f"ML Risk Assessment: {risk_level}")
        if risk_level == "High Risk":
            risk_factors.append("ML model mengindikasikan risiko tinggi")
        elif risk_level == "Medium Risk":
            risk_factors.append("ML model mengindikasikan risiko sedang")
        return {"findings": findings, "risk_factors": risk_factors}
    
    def _calculate_threat_score(self, risk_factors: List[str], findings: List[str]) -> int:
        base_score = 20
        risk_factor_score = len(risk_factors) * 15
        finding_score = len(findings) * 10
        total_score = base_score + risk_factor_score + finding_score
        return min(total_score, 100)
    
    def _generate_risk_summary(self, threat_score: int, findings: List[str]) -> str:
        if threat_score >= 70:
            return "Risiko Tinggi - Ditemukan beberapa indikator mencurigakan yang memerlukan perhatian segera"
        elif threat_score >= 40:
            return "Risiko Sedang - Ditemukan beberapa indikator yang perlu diperiksa lebih lanjut"
        else:
            return "Risiko Rendah - Tidak ditemukan indikator mencurigakan yang signifikan"
    
    def _generate_default_recommendations(self, threat_score: int) -> List[str]:
        if threat_score >= 70:
            return [
                "Lakukan verifikasi menyeluruh terhadap nomor ini",
                "Hindari berbagi informasi sensitif dengan nomor ini",
                "Pertimbangkan untuk memblokir nomor jika terindikasi spam"
            ]
        elif threat_score >= 40:
            return [
                "Lakukan verifikasi dasar terhadap nomor ini",
                "Berhati-hati dalam berbagi informasi dengan nomor ini"
            ]
        else:
            return [
                "Nomor tampaknya aman untuk penggunaan normal",
                "Tetap waspada terhadap upaya phishing yang mungkin"
            ]
    
    def _generate_investigation_steps(self, phone_number: str, context: Dict[str, Any]) -> List[str]:
        return [
            "Cek nomor di database spam dan penipuan yang tersedia",
            "Verifikasi pemilik nomor melalui sumber resmi jika mungkin",
            "Monitor aktivitas yang mencurigakan dari nomor ini",
            "Laporkan ke pihak berwajib jika terindikasi aktivitas ilegal"
        ]
    
    def _determine_confidence(self, context: Dict[str, Any], findings: List[str]) -> str:
        data_sources = len(context.keys())
        if data_sources >= 3 and len(findings) >= 2:
            return "High"
        elif data_sources >= 2 or len(findings) >= 1:
            return "Medium"
        else:
            return "Low"


class AIChatbot:
    """
    Enhanced Universal AI Chatbot for AIZX Native Engine - handles security analysis,
    general Q&A, code generation, and conversation intelligence.
    
    Credit: NEFZX
    """
    
    def __init__(self):
        self.engine_name = "LynaeZx Chatbot"
        self.engine_credit = "NEFZX"
        self.conversation_history = []
        self.user_context = {}
        self.script_templates = self._load_script_templates()
        self.conversation_patterns = self._load_conversation_patterns()
        self.knowledge_base = self._load_knowledge_base()

        # Ollama — server AI LOKAL (offline, gratis, tanpa API key, tanpa limit).
        # Install Ollama di komputer/VPS sendiri (https://ollama.com), lalu
        # `ollama pull llama3.2` (atau model lain yang muat di RAM kamu).
        # Kalau OLLAMA_URL kosong, provider ini otomatis dilewati.
        self.ollama_url = os.getenv("OLLAMA_URL", "").strip().rstrip("/")
        self.ollama_model = os.getenv("OLLAMA_MODEL", "llama3.2")

        self.groq_api_key = os.getenv("GROQ_API_KEY", "").strip()
        self.groq_model = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
        self.github_token = os.getenv("GITHUB_TOKEN", "").strip()
        self.github_model = os.getenv("GITHUB_MODEL", "claude-3-5-sonnet")
        self.github_endpoint = os.getenv("GITHUB_MODELS_ENDPOINT", "https://models.inference.ai.azure.com")
        self.gemini_api_key = os.getenv("GEMINI_API_KEY", "").strip()
        self.gemini_model = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
        self.openrouter_api_key = os.getenv("OPENROUTER_API_KEY", "").strip()
        self.openrouter_model = os.getenv("OPENROUTER_MODEL", "meta-llama/llama-3.1-8b-instruct:free")
        self.anthropic_api_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
        self.anthropic_model = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6")

        self.llm_providers = [p for p in [
            ("ollama", self.ollama_url),   # lokal & offline -> dicoba paling awal, gratis tanpa limit
            ("groq", self.groq_api_key),
            ("github", self.github_token),
            ("gemini", self.gemini_api_key),
            ("openrouter", self.openrouter_api_key),
            ("anthropic", self.anthropic_api_key),
        ] if p[1]]
        self.llm_enabled = bool(self.llm_providers)

        provider_names = ", ".join(p[0] for p in self.llm_providers)
        print(f"[{self.engine_name}] Initialized v2.0 (Credit: {self.engine_credit}) "
              f"| External LLM: {('ON (' + provider_names + ')') if self.llm_enabled else 'OFF (local engine only)'}")

        self.last_llm_provider = None

    def _credit_line(self, from_llm: bool = False) -> str:
        provider_labels = {
            "ollama": f"Ollama Lokal ({self.ollama_model}, offline)",
            "groq": "Groq AI (llama-3.3-70b)",
            "github": "GitHub Models (Claude 3.5 Sonnet)",
            "gemini": "Google Gemini",
            "openrouter": "OpenRouter",
            "anthropic": "Claude (Anthropic)",
        }
        if from_llm and self.last_llm_provider:
            label = provider_labels.get(self.last_llm_provider, self.last_llm_provider)
            return f"**Dijawab oleh:** {label} · LynaeZx (NEFZX)"
        return "**Dijawab oleh:** LynaeZx Local Engine (offline, NEFZX)"

    def _call_external_llm(self, message: str, context: Dict[str, Any] = None,
                            history: Optional[list] = None, *args, **kwargs) -> Optional[str]:
        if not self.llm_enabled:
            return None
        system_prompt = (
            "Kamu adalah LynaeZx, asisten AI di dalam toolkit OSINT PhoneGG. "
            "Gaya bicaramu ngobrol biasa aja — kayak rekan developer yang paham "
            "security, bukan robot yang jawab pakai template atau bullet points "
            "kaku terus-terusan. Jawab langsung ke intinya, boleh panjang kalau "
            "topiknya emang butuh penjelasan detail, tapi jangan dipanjang-"
            "panjangin basa-basi. Pakai emoji seperlunya aja (maksimal 1, atau "
            "malah nggak usah sama sekali) — fokus ke isi jawaban, bukan hiasan. "
            "Kamu bebas diskusi mendalam soal keamanan siber, jaringan, "
            "programming, dan konsep teknis apa pun secara edukatif: cara kerja "
            "suatu teknik/kerentanan, cara mendeteksinya, cara mitigasinya, "
            "arsitektur malware secara konseptual, dll — semua itu ilmu yang sah "
            "buat dipelajari orang yang kerja di security/OSINT. Batasnya cuma "
            "satu: jangan tulis exploit/payload siap-pakai atau kode yang "
            "didesain buat menyerang sistem/orang tertentu tanpa izin — kalau "
            "user minta itu, jelasin konsepnya tetap boleh, tapi arahkan ke versi "
            "aman (lab sendiri, CTF, fitur recon bawaan PhoneGG) alih-alih kasih "
            "kode siap tembak."
        )

        # [PERBAIKAN BUG DISINI]
        # `history` sekarang diterima sebagai parameter (per-session, dikirim dari
        # process_message) alih-alih selalu dibaca dari self.conversation_history,
        # supaya tiap sesi/user punya riwayat percakapan sendiri-sendiri.
        # Fallback ke self.conversation_history hanya untuk kompatibilitas mundur
        # (mis. jika fungsi ini dipanggil tanpa history dari tempat lain).
        if history is None:
            history = self.conversation_history
        history = history[-9:-1] if len(history) > 1 else []

        for provider_name, _api_key in self.llm_providers:
            try:
                if provider_name == "ollama":
                    result = self._call_ollama(message, history, system_prompt)
                elif provider_name == "groq":
                    result = self._call_groq(message, history, system_prompt)
                elif provider_name == "github":
                    result = self._call_github(message, history, system_prompt)
                elif provider_name == "gemini":
                    result = self._call_gemini(message, history, system_prompt)
                elif provider_name == "anthropic":
                    result = self._call_anthropic(message, history, system_prompt)
                elif provider_name == "openrouter":
                    result = self._call_openrouter(message, history, system_prompt)
                else:
                    result = None
            except Exception as e:
                logger.warning(f"{provider_name} call error: {e}")
                result = None

            if result:
                self.last_llm_provider = provider_name
                return result
        return None

    def _call_ollama(self, message: str, history: list, system_prompt: str) -> Optional[str]:
        """Panggil server Ollama lokal — 100% offline, jalan di mesin/VPS sendiri,
        tidak ada API key, tidak ada rate limit, tidak ada biaya per-request."""
        import requests as _requests
        messages = [{"role": "system", "content": system_prompt}]
        messages += [{"role": h["role"], "content": h["content"]} for h in history if h.get("role") in ("user", "assistant")]
        messages.append({"role": "user", "content": message})

        try:
            resp = _requests.post(
                f"{self.ollama_url}/api/chat",
                json={
                    "model": self.ollama_model,
                    "messages": messages,
                    "stream": False,
                },
                timeout=60,  # model lokal bisa lebih lambat dari CPU, kasih waktu lebih
            )
        except _requests.exceptions.RequestException as e:
            logger.warning(f"Ollama call error (server lokal jalan gak? cek OLLAMA_URL): {e}")
            return None

        if resp.status_code != 200:
            logger.warning(f"Ollama call failed: {resp.status_code} {resp.text[:200]}")
            return None
        data = resp.json()
        text = (data.get("message") or {}).get("content", "").strip()
        return text or None

    def _call_groq(self, message: str, history: list, system_prompt: str) -> Optional[str]:
        import requests as _requests
        messages = [{"role": "system", "content": system_prompt}]
        messages += [{"role": h["role"], "content": h["content"]} for h in history if h.get("role") in ("user", "assistant")]
        messages.append({"role": "user", "content": message})

        resp = _requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {self.groq_api_key}",
                "content-type": "application/json",
            },
            json={
                "model": self.groq_model,
                "messages": messages,
                "max_tokens": 1024,
            },
            timeout=20,
        )
        if resp.status_code != 200:
            logger.warning(f"Groq call failed: {resp.status_code} {resp.text[:200]}")
            return None
        data = resp.json()
        choices = data.get("choices", [])
        if not choices:
            return None
        text = choices[0].get("message", {}).get("content", "").strip()
        return text or None

    def _call_github(self, message: str, history: list, system_prompt: str) -> Optional[str]:
        import requests as _requests
        messages = [{"role": "system", "content": system_prompt}]
        messages += [{"role": h["role"], "content": h["content"]} for h in history if h.get("role") in ("user", "assistant")]
        messages.append({"role": "user", "content": message})

        try:
            resp = _requests.post(
                f"{self.github_endpoint.rstrip('/')}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.github_token}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.github_model,
                    "messages": messages,
                    "max_tokens": 1024,
                },
                timeout=30,
            )
        except _requests.exceptions.RequestException as e:
            logger.warning(f"GitHub Models call error: {e}")
            return None

        if resp.status_code != 200:
            logger.warning(f"GitHub Models call failed: {resp.status_code} {resp.text[:200]}")
            return None
        data = resp.json()
        choices = data.get("choices", [])
        if not choices:
            return None
        text = choices[0].get("message", {}).get("content", "").strip()
        return text or None

    def _call_gemini(self, message: str, history: list, system_prompt: str) -> Optional[str]:
        import requests as _requests
        contents = []
        for h in history:
            if h.get("role") in ("user", "assistant"):
                contents.append({
                    "role": "model" if h["role"] == "assistant" else "user",
                    "parts": [{"text": h["content"]}]
                })
        contents.append({"role": "user", "parts": [{"text": message}]})

        resp = _requests.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{self.gemini_model}:generateContent",
            headers={"content-type": "application/json"},
            params={"key": self.gemini_api_key},
            json={
                "system_instruction": {"parts": [{"text": system_prompt}]},
                "contents": contents,
                "generationConfig": {"maxOutputTokens": 1024},
            },
            timeout=20,
        )
        if resp.status_code != 200:
            logger.warning(f"Gemini call failed: {resp.status_code} {resp.text[:200]}")
            return None
        data = resp.json()
        candidates = data.get("candidates", [])
        if not candidates:
            return None
        parts = candidates[0].get("content", {}).get("parts", [])
        text = "".join(p.get("text", "") for p in parts).strip()
        return text or None

    def _call_anthropic(self, message: str, history: list, system_prompt: str) -> Optional[str]:
        import requests as _requests
        messages = [{"role": h["role"], "content": h["content"]} for h in history if h.get("role") in ("user", "assistant")]
        messages.append({"role": "user", "content": message})

        resp = _requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": self.anthropic_api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": self.anthropic_model,
                "max_tokens": 1024,
                "system": system_prompt,
                "messages": messages,
            },
            timeout=20,
        )
        if resp.status_code != 200:
            logger.warning(f"Anthropic call failed: {resp.status_code} {resp.text[:200]}")
            return None
        data = resp.json()
        parts = [b.get("text", "") for b in data.get("content", []) if b.get("type") == "text"]
        text = "\n".join(p for p in parts if p).strip()
        return text or None
    
    def _call_openrouter(self, message: str, history: list, system_prompt: str) -> Optional[str]:
        import requests as _requests

        headers = {
            "Authorization": f"Bearer {self.openrouter_api_key}",
            "HTTP-Referer": "https://github.com/aizx",
            "X-Title": "AIZX-Native-Engine",
            "Content-Type": "application/json",
        }

        messages = [{"role": "system", "content": system_prompt}]
        messages += [{"role": h["role"], "content": h["content"]} for h in history if h.get("role") in ("user", "assistant")]
        messages.append({"role": "user", "content": message})

        payload = {
            "model": self.openrouter_model,
            "messages": messages,
            "max_tokens": 1024,
        }

        resp = _requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=20,
        )
        if resp.status_code != 200:
            logger.warning(f"OpenRouter call failed: {resp.status_code} {resp.text[:200]}")
            return None
        data = resp.json()
        choices = data.get("choices", [])
        if not choices:
            return None
        text = choices[0].get("message", {}).get("content", "").strip()
        return text or None

    # Load templates and bases (disingkat sesuai file original)
    def _load_script_templates(self) -> Dict[str, Dict]:
        return {}

    def _load_conversation_patterns(self) -> Dict[str, str]:
        return {
            "greeting": r"(halo+|hai+|hello+|hi+|hey+|selamat\s?(pagi|siang|sore|malam)?|assalamualaikum|woy|woi|oy|oi|hay|permisi|test|tes)\b",
            "farewell": r"(bye|dadah|sampai jumpa|makasih|terima\s?kasih|thanks|thx|udah dulu|segitu dulu)",
            "security_question": r"(security|keamanan|aman(?!kan)|vulnerab|kerentanan|bug|exploit|exploitasi|hack(?!athon)|hacking|diretas|dibobol|cyber|serangan|attack|celah|patch|cve|malware|virus|ransomware|phishing|ddos|dos attack|mitm|man in the middle|social engineering|rekayasa sosial|firewall|enkripsi|encrypt|password (kuat|aman)|kebocoran data|data breach|zero.?day)",
            "code_request": r"(buat(kan)?|generate|tulis(kan)?|susun(kan)?)\s+(script|code|program|fungsi|kode|skrip)",
            "help_request": r"(help|bantu(an)?|tolong|cara(nya)?|how\s?to|what is|apa itu|explain|jelasin|jelaskan|tutorial|panduan|langkah|step by step|maksudnya apa|artinya apa)",
            "phonegg_question": r"(phonegg|aizx|modul|fitur|tool(s)?\b|fungsi|kapabilitas|menu apa saja|bisa apa aja|bisa ngapain)",
            "learning_request": r"(belajar|learn(ing)?|ajar(in|kan)?|teach|understand|paham(i)?|mengerti|kursus|course|materi|latihan|praktek|pemula|newbie|dari nol|dasar(nya)?)",
            "identity_question": r"(siapa kamu|kamu siapa|kamu apa|kamu itu|kamu ai|kamu bot|nama kamu|who are you|apakah kamu ai|kamu robot)",
            "nefzx_question": r"(siapa (itu\s+)?nefzx|nefzx itu siapa|nefzx (itu\s+)?siapa|who is nefzx|tentang nefzx|kenal(an)? (sama |dengan )?nefzx|creator phonegg|pembuat phonegg|siapa (yang\s+)?(bikin|buat|menciptakan) phonegg|developer phonegg)",
            "capability_question": r"(kamu bisa apa|apa yang bisa kamu|kemampuan kamu|fitur kamu|kamu ngerti apa)",
            "general_question": r"(apa|what|siapa|who|kapan|when|dimana|where|kenapa|why|mengapa|gimana|bagaimana|how|apakah|apa itu)",
            "technical_question": r"(teknis|technical|programming|pemrograman|developer|development|software|aplikasi|framework|library|database|api|server|deploy(ment)?|git|linux|docker|cloud)",
            "chitchat": r"(lagi apa|lagi ngapain|gimana kabar|apa kabar|lucu|becanda|bosen|capek|ngobrol)"
        }
    
    def _load_knowledge_base(self) -> Dict[str, Dict[str, Any]]:
        return {
            "sql_injection": {
                "keywords": ["sql injection", "sqli", "sql inject", "injeksi sql", "manipulasi query"],
                "content": """SQL Injection adalah vulnerability..."""
            }
        }
    
    def _calculate_similarity(self, str1: str, str2: str) -> float:
        return SequenceMatcher(None, str1.lower(), str2.lower()).ratio()
    
    def _find_best_match(self, query: str, candidates: Dict[str, Dict[str, Any]], threshold: float = 0.35) -> Optional[str]:
        query_lower = query.lower()
        query_words = set(re.findall(r"[a-z0-9]+", query_lower))
        
        synonyms = {
            "php": {"php", "web", "server"},
            "js": {"javascript", "js", "node"},
            "py": {"python", "py"},
            "bash": {"bash", "shell", "sh"},
            "ps": {"powershell", "ps"},
            "docker": {"docker", "container", "kontainer"},
            "k8s": {"kubernetes", "k8s"},
            "ml": {"machine learning", "ml", "ai"},
            "dl": {"deep learning", "dl"},
            "aws": {"aws", "amazon web services"},
            "azure": {"azure", "microsoft azure"},
            "gcp": {"gcp", "google cloud"},
        }
        expanded = set(query_words)
        for word in query_words:
            for syn_set in synonyms.values():
                if word in syn_set:
                    expanded.update(syn_set)
        query_words = expanded

        best_content = None
        best_score = threshold

        for topic in candidates.values():
            keywords = topic.get("keywords", [])
            content = topic.get("content", "")
            topic_best = 0.0
            for kw in keywords:
                if kw in query_lower:
                    return content
                kw_words = set(re.findall(r"[a-z0-9]+", kw))
                if not kw_words:
                    continue
                overlap = kw_words & query_words
                if not overlap:
                    continue
                overlap_ratio = len(overlap) / len(kw_words)
                fuzzy = self._calculate_similarity(query_lower, kw)
                score = max(overlap_ratio, (overlap_ratio + fuzzy) / 2)
                topic_best = max(topic_best, score)
            if topic_best > best_score:
                best_score = topic_best
                best_content = content
        return best_content
    
    def process_message(self, message: str, analysis_context: Dict[str, Any] = None,
                         chat_history: Optional[list] = None, *args, **kwargs) -> Tuple[str, list]:
        """
        Selalu mengembalikan tuple 2 nilai: (response_text, chat_history_terbaru).

        `chat_history` bersifat opsional dan per-session: kalau route Flask
        mengirim riwayat sesi (list of {"role", "content"}), riwayat itu yang
        dipakai & dikembalikan lagi (sudah ditambah pesan baru) — bukan
        self.conversation_history yang dulu dibagi ke semua user. Kalau tidak
        dikirim (backward-compat), fallback ke self.conversation_history milik
        instance ini.

        *args/**kwargs ditampung supaya fungsi ini tetap aman dipanggil walau
        jumlah/urutan argumen dari app.py berubah di kemudian hari.
        """
        history = self.conversation_history if chat_history is None else chat_history
        try:
            history.append({"role": "user", "content": message})
            if analysis_context:
                self.user_context.update(analysis_context)
            response = self._generate_intelligent_response(message, analysis_context, history)
            history.append({"role": "assistant", "content": response})
            return response, history
        except Exception as e:
            logger.error(f"Chatbot error: {str(e)}")
            error_msg = f"Maaf, terjadi kesalahan: {str(e)}\n\n**Dijawab oleh:** LynaeZx Local Engine (offline, NEFZX)"
            return error_msg, history

    def _generate_intelligent_response(self, message: str, context: Dict[str, Any] = None,
                                        history: Optional[list] = None) -> str:
        message_lower = message.lower()
        
        if self._matches_pattern(message_lower, "nefzx_question"):
            return self._generate_nefzx_bio_response()

        if self._matches_pattern(message_lower, "identity_question"):
            return self._generate_identity_response()

        # phonegg_question dicek duluan supaya "fitur pen repeater kayak gimana"
        # nggak ketarik ke security_question/code_request cuma gara-gara ada
        # kata "fitur"/"kode" di dalamnya.
        if self._matches_pattern(message_lower, "phonegg_question"):
            llm_response = self._call_external_llm(message, context, history)
            if llm_response:
                return f"{llm_response}\n\n{self._credit_line(from_llm=True)}"
            return self._handle_phonegg_questions(message_lower)

        if self._matches_pattern(message_lower, "code_request"):
            llm_response = self._call_external_llm(message, context, history)
            if llm_response:
                return f"{llm_response}\n\n{self._credit_line(from_llm=True)}"
            return self._handle_intelligent_code_requests(message_lower)

        # learning_request, security_question, help_request, technical_question,
        # dan general_question semuanya lewat LLM dulu kalau ada provider aktif —
        # supaya jawabannya kontekstual & natural, bukan blok teks template yang
        # sama tiap kali. Fallback ke local engine cuma kalau LLM lagi mati.
        for intent, handler in (
            ("learning_request", self._handle_learning_requests),
            ("security_question", self._handle_intelligent_security_questions),
            ("help_request", self._handle_intelligent_help_requests),
            ("technical_question", None),
            ("general_question", None),
        ):
            if self._matches_pattern(message_lower, intent):
                llm_response = self._call_external_llm(message, context, history)
                if llm_response:
                    return f"{llm_response}\n\n{self._credit_line(from_llm=True)}"
                if handler:
                    return handler(message_lower)
                break  # technical/general tanpa LLM -> lanjut ke knowledge base / default

        if self._matches_pattern(message_lower, "chitchat"):
            llm_response = self._call_external_llm(message, context, history)
            if llm_response:
                return f"{llm_response}\n\n{self._credit_line(from_llm=True)}"
            return ("Haha santai aja — aku di sini kalau kamu butuh diskusi teknis, "
                    "belajar sesuatu, atau bikin script. Ada yang lagi kamu kerjain?\n\n"
                    "**Dijawab oleh:** LynaeZx Local Engine (offline, NEFZX)")

        knowledge_response = self._find_best_match(message, self.knowledge_base, threshold=0.35)
        if knowledge_response:
            return f"""📚 **Informasi:**

{knowledge_response}

**Dijawab oleh:** LynaeZx Local Engine (offline, NEFZX)"""

        llm_response = self._call_external_llm(message, context, history)
        if llm_response:
            return f"{llm_response}\n\n{self._credit_line(from_llm=True)}"

        return self._generate_intelligent_default_response(message)
    
    def _matches_pattern(self, text: str, pattern_name: str) -> bool:
        pattern = self.conversation_patterns.get(pattern_name, "")
        return bool(re.search(pattern, text, re.IGNORECASE))
    
    def _generate_identity_response(self) -> str:
        provider_note = (
            f"Saat ini aku nyambung ke {', '.join(p[0] for p in self.llm_providers)} buat obrolan bebas & pembelajaran."
            if self.llm_enabled else
            "Saat ini aku jalan 100% offline pakai rule-based engine (belum ada API key AI eksternal)."
        )
        return f"""Aku **LynaeZx**, asisten AI bawaan toolkit OSINT **PhoneGG**.

Bagian dari engine "AI Native Engine" (Credit: NEFZX). Tugasku bantu kamu diskusi & belajar soal keamanan siber dan programming, bikinin script/code contoh, sampai jelasin fitur-fitur PhoneGG kalau kamu bingung.

{provider_note}

Ada yang mau kamu tanyain atau pelajari?

**Dijawab oleh:** LynaeZx Local Engine (offline, NEFZX)"""

    def _generate_nefzx_bio_response(self) -> str:
        return """**NefZx** adalah orang biasa — bukan jenius, bukan expert dari lahir — cuma punya rasa penasaran yang tinggi soal cara kerja sistem, jaringan, dan keamanan siber.

Dari rasa penasaran itu, NefZx bikin **PhoneGG**: toolkit OSINT & security recon ini, sedikit demi sedikit, dari nol.

Tujuannya sederhana: biar karyanya tetap jalan dan berguna buat orang lain, bahkan kalau suatu saat NefZx sendiri sudah nggak ada lagi yang ngoprek. Selama PhoneGG masih dipakai dan dikembangkan, karyanya tetap hidup.

Aku (LynaeZx) sendiri bagian dari PhoneGG — dibangun di atas fondasi yang sama.

**Dijawab oleh:** LynaeZx Local Engine (offline, NEFZX)"""

    def _generate_intelligent_greeting(self) -> str:
        hour = datetime.now().hour
        if 5 <= hour < 12:
            time_greeting = "Selamat pagi"
        elif 12 <= hour < 18:
            time_greeting = "Selamat siang"
        elif 18 <= hour < 22:
            time_greeting = "Selamat sore"
        else:
            time_greeting = "Selamat malam"
        
        return f"""{time_greeting}, saya LynaeZx (Credit: NEFZX).

Bisa bantu diskusi keamanan siber & hacking defense, bikinin script/code dalam berbagai bahasa, jawab pertanyaan teknis programming/IT, jelasin modul-modul PhoneGG, atau nemenin belajar konsep teknis dari nol.

Tinggal ketik aja pertanyaan atau request-nya secara natural — sebutkan bahasa pemrograman kalau butuh code, dan kasih detail spesifik biar hasilnya makin pas.

Mau mulai dari mana?

**Dijawab oleh:** LynaeZx Local Engine (offline, NEFZX)"""
    
    def _handle_intelligent_code_requests(self, message_lower: str) -> str:
        language = self._detect_language(message_lower)
        script_type = self._detect_script_type(message_lower)
        if language and script_type:
            return self._generate_script(language, script_type)
        elif language:
            return self._generate_simple_function(language)
        else:
            return self._ask_for_clarification()
    
    def _detect_language(self, message: str) -> Optional[str]:
        language_keywords = {
            "python": ["python", "py", "python3"],
            "javascript": ["javascript", "js", "node", "nodejs"],
            "bash": ["bash", "shell", "sh", "linux", "terminal"],
            "powershell": ["powershell", "ps", "windows", "pwsh"],
            "lua": ["lua"],
            "cpp": ["cpp", "c++", "cplusplus"],
            "go": ["go", "golang"],
            "rust": ["rust"]
        }
        message_lower = message.lower()
        for lang, keywords in language_keywords.items():
            if any(keyword in message_lower for keyword in keywords):
                return lang
        return "python"
    
    def _detect_script_type(self, message: str) -> Optional[str]:
        script_keywords = {
            "port_scanner": ["port scanner", "scan port", "port scan", "port"],
            "web_scanner": ["web scanner", "web scan", "vulnerability scanner", "web vuln"],
            "subdomain_enum": ["subdomain", "subdomain enum", "subdomain enumeration"],
            "api_client": ["api", "api client", "rest api", "http request"],
            "data_processor": ["data", "data processing", "csv", "json", "excel"],
            "automation": ["automation", "automate", "file", "batch"],
            "http_analyzer": ["http", "analyzer", "debug", "traffic"],
            "xss_scanner": ["xss", "cross-site scripting"],
            "dom_analyzer": ["dom", "dom analyzer", "dom security"],
            "simple_function": ["simple", "basic", "function", "utility", "tool"]
        }
        message_lower = message.lower()
        for script_type, keywords in script_keywords.items():
            if any(keyword in message_lower for keyword in keywords):
                return script_type
        return "simple_function"
    
    def _generate_script(self, language: str, script_type: str) -> str:
        return self._generate_simple_function(language)
    
    def _get_usage_instructions(self, language: str, script_type: str) -> str:
        instructions = {
            "python": "Simpan sebagai file `.py` dan jalankan dengan `python filename.py`",
            "javascript": "Simpan sebagai file `.js` dan jalankan dengan `node filename.js` atau di browser",
            "bash": "Simpan sebagai file `.sh`, berikan permission `chmod +x filename.sh`, dan jalankan `./filename.sh`",
            "powershell": "Simpan sebagai file `.ps1` dan jalankan dengan `powershell -ExecutionPolicy Bypass -File filename.ps1`",
            "lua": "Simpan sebagai file `.lua` dan jalankan dengan `lua filename.lua`",
            "cpp": "Compile dengan `g++ -o filename filename.cpp` dan jalankan `./filename`",
            "go": "Jalankan dengan `go run filename.go` atau build dengan `go build`",
            "rust": "Jalankan dengan `cargo run` atau build dengan `cargo build`"
        }
        return instructions.get(language, "Lihat dokumentasi bahasa pemrograman yang bersangkutan")
    
    def _generate_simple_function(self, language: str) -> str:
        usage = self._get_usage_instructions(language, "simple_function")
        note = (
            "Local engine belum punya template siap pakai buat kombinasi ini. "
            "Aktifkan provider LLM (lihat `.env`) supaya aku bisa generate "
            f"script {language} custom sesuai kebutuhanmu. Sementara itu, {usage.lower()}"
        )
        return f"{note}\n\n**Dijawab oleh:** LynaeZx Local Engine (offline, NEFZX)"
    
    def _ask_for_clarification(self) -> str:
        return ("Boleh dijelasin sedikit lagi maumu apa? Sebutkan bahasa pemrograman "
                "dan jenis script/fungsi yang kamu maksud (misalnya: \"bikin port "
                "scanner pakai python\" atau \"fungsi parsing JSON di javascript\") "
                "biar aku bisa bikinin yang pas.\n\n"
                "**Dijawab oleh:** LynaeZx Local Engine (offline, NEFZX)")

    def _handle_intelligent_security_questions(self, message_lower: str) -> str:
        content = (
            "Local engine lagi jalan tanpa koneksi LLM eksternal, jadi jawabanku "
            "di sini terbatas ke ringkasan umum aja. Beberapa hal yang sering "
            "relevan buat pertanyaan security:\n\n"
            "- **Vulnerability** = celah di sistem/kode yang bisa dieksploitasi; "
            "**exploit** = cara/kode buat memanfaatkan celah itu.\n"
            "- Prinsip defense yang paling dasar: validasi input, least privilege, "
            "patch/update rutin, monitoring & logging, dan segmentasi jaringan.\n"
            "- Kalau butuh detail teknis (cara kerja suatu attack, cara deteksi, "
            "cara mitigasi) yang lebih spesifik, aktifkan salah satu provider LLM "
            "(Ollama/Groq/Gemini/dll di config) biar aku bisa jawab lebih dalam "
            "dan kontekstual sesuai pertanyaanmu.\n"
            "- Untuk praktik langsung, PhoneGG punya modul recon (port scanner, "
            "subdomain enum, security headers checker, CORS checker) yang bisa "
            "dipakai di lab/target milik sendiri."
        )
        return f"{content}\n\n**Dijawab oleh:** LynaeZx Local Engine (offline, NEFZX)"

    def _format_security_response(self, title: str, content: str) -> str:
        return f"**{title}**\n\n{content}\n\n**Dijawab oleh:** LynaeZx Local Engine (offline, NEFZX)"

    def _handle_intelligent_help_requests(self, message_lower: str) -> str:
        content = (
            "Ini yang bisa kamu tanyain ke aku:\n\n"
            "- Diskusi & belajar konsep security/networking/programming (tanya "
            "langsung aja, natural)\n"
            "- Minta dibikinin script (sebutkan bahasa + jenis tool-nya)\n"
            "- Nanya soal fitur/modul PhoneGG (pen repeater, network graph, "
            "recon modules, dll)\n"
            "- Ngobrol santai kalau lagi nyantai\n\n"
            "Kalau jawabanku kerasa kurang detail, kemungkinan karena belum ada "
            "provider LLM eksternal yang aktif — cek `.env` buat isi salah satu "
            "API key (Groq/Gemini/OpenRouter/dll) atau jalankan Ollama lokal."
        )
        return f"{content}\n\n**Dijawab oleh:** LynaeZx Local Engine (offline, NEFZX)"

    def _handle_phonegg_questions(self, message_lower: str) -> str:
        content = (
            "PhoneGG (karya NefZx) punya beberapa kelompok modul:\n\n"
            "- **Pen Repeater** — request builder mirip Burp Repeater: custom "
            "header/body, multi-method, cookie jar otomatis, multi-tab, import "
            "raw HTTP/cURL, diff antar tab, loop send.\n"
            "- **Net Tools Console** — command network diagnostic whitelist "
            "(whois, dig, nslookup, ping, traceroute, curl header/body/timing, "
            "SSL info, crt.sh watch, robots+sitemap, Shodan InternetDB) — semua "
            "read-only, tanpa command bebas, biar aman dari RCE.\n"
            "- **Recon** — Phone Lookup, Breach Search (bisa juga via nomor HP), "
            "Email/Username Lookup, Subdomain Enumeration, Port Scanner, Dir "
            "Enum, CORS Checker, Subdomain Takeover, Metadata Extractor, Header "
            "Detector, Tech Detect, Security Headers, IP Geolocation, Origin IP "
            "Finder, Wayback Lookup, Link Scraper, Dork Generator.\n"
            "- **Scam Checker** — cek indikasi website penipuan secara legal "
            "(tanpa bypass proteksi seperti Cloudflare).\n"
            "- **Phone Graph** — rule-based risk predictor + Network Graph "
            "interaktif (Vis.js), bisa export.\n"
            "- **AI Analyst (aku, LynaeZx)** — asisten buat analisis data & "
            "diskusi teknis, ada mode online (LLM) dan offline (rule-based, "
            "engine ini).\n\n"
            "Mau bahas salah satu modul lebih detail, tinggal sebutin namanya."
        )
        return f"{content}\n\n**Dijawab oleh:** LynaeZx Local Engine (offline, NEFZX)"

    def _handle_learning_requests(self, message_lower: str) -> str:
        content = (
            "Local engine lagi jalan tanpa LLM eksternal, jadi aku belum bisa "
            "kasih penjelasan mendalam & kontekstual di sini. Supaya sesi "
            "belajarnya lebih maksimal, aktifkan salah satu provider LLM di "
            "`.env` (Ollama untuk lokal/offline, atau Groq/Gemini/OpenRouter "
            "untuk yang butuh API key gratis) — habis itu aku bisa jelasin "
            "konsep apa pun secara detail, step-by-step, sesuai levelmu.\n\n"
            "Sementara itu, kalau topiknya ada di knowledge base internal "
            "(misalnya SQL Injection), aku tetap bisa kasih ringkasannya."
        )
        return f"{content}\n\n**Dijawab oleh:** LynaeZx Local Engine (offline, NEFZX)"
    
    def _format_learning_response(self, topic: str, content: str) -> str:
        return f"""🎓 **Belajar {topic}**\n\n{content}\n\n**Dijawab oleh:** LynaeZx Local Engine (offline, NEFZX)"""
    
    def _generate_intelligent_default_response(self, message: str) -> str:
        return ("Hmm, aku belum nangkep maksudnya nih. Coba jelasin dengan kata "
                "lain, atau kasih contoh konkret apa yang mau kamu tanyain/buat — "
                "biar aku bisa bantu lebih tepat.\n\n"
                "**Dijawab oleh:** LynaeZx Local Engine (offline, NEFZX)")


# Global instances
ai_native_engine = AINativeEngine()
ai_chatbot = AIChatbot()

def get_ai_analysis(phone_number: str, raw_data: Dict[str, Any]) -> Dict[str, Any]:
    return ai_native_engine.analyze_phone_data(phone_number, raw_data)

def process_chat_message(message: str, analysis_context: Dict[str, Any] = None,
                          chat_history: Optional[list] = None, *args, **kwargs) -> Tuple[str, list]:
    """
    Wrapper penghubung ke AIChatbot.process_message. Selalu mengembalikan
    tuple 2 nilai (response_text, chat_history), konsisten dengan yang
    diharapkan app.py: `response, chat_history = process_chat_message(...)`.
    *args/**kwargs diteruskan apa adanya supaya pemanggilan dari app.py tetap
    aman walau jumlah argumen berubah.
    """
    return ai_chatbot.process_message(message, analysis_context, chat_history, *args, **kwargs)