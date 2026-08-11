"""
Graph Builder Module v2.0 — Convert phone/email lookup data to interactive graph format
Enhanced for SpiderFoot-style OSINT visualization with advanced node clustering,
categorization, and relationship mapping. Uses Vis.js Network for rendering.

v2.0 Improvements:
- Better null/empty value handling dengan default fallbacks
- Optimized node creation dengan lazy initialization
- Enhanced error recovery dan safe defaults
- Improved metadata generation dengan validation
- Better category distribution tracking
- Performance optimization untuk large datasets
"""
import logging
from collections import defaultdict
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


def _safe_get(data: Any, *keys, default: Any = None) -> Any:
    """Safely navigate nested dictionary dengan multiple keys."""
    if not isinstance(data, dict):
        return default
    result = data
    for key in keys:
        if isinstance(result, dict):
            result = result.get(key)
        else:
            return default
    return result if result is not None else default


def _safe_str(value: Any, default: str = "Unknown", max_len: int = 0) -> str:
    """Safely convert value to string dengan optional length limit."""
    try:
        s = str(value).strip() if value else default
        return s[:max_len] if max_len > 0 and len(s) > max_len else s
    except Exception:
        return default


def _safe_list(value: Any, default: Optional[List] = None) -> List:
    """Safely convert value to list."""
    try:
        if isinstance(value, list):
            return value
        if isinstance(value, (tuple, set)):
            return list(value)
        return default if default is not None else []
    except Exception:
        return default if default is not None else []


def _safe_int(value: Any, default: int = 0, min_val: int = None, max_val: int = None) -> int:
    """Safely convert value to int dengan range validation."""
    try:
        i = int(value) if value is not None else default
        if min_val is not None:
            i = max(i, min_val)
        if max_val is not None:
            i = min(i, max_val)
        return i
    except (TypeError, ValueError):
        return default


def _empty_graph(phone_data: dict, error: str) -> dict:
    """Fallback graph aman kalau build_phone_graph gagal — tetap punya
    struktur nodes/edges/metadata yang valid supaya frontend tidak crash."""
    number = _safe_str(phone_data.get("number") if isinstance(phone_data, dict) else None, "Unknown")
    error_msg = _safe_str(error, "Unknown error", max_len=200)
    return {
        "nodes": [{
            "id": 0, "label": number, "title": f"Error building graph: {error_msg}",
            "shape": "diamond", "size": 30,
            "color": {"background": "#ef4444", "border": "#ef4444"},
            "font": {"size": 14, "color": "#ffffff"},
        }],
        "edges": [],
        "metadata": {
            "phone": number, "operator": "Unknown", "country": "Unknown",
            "risk_score": 0, "risk_level": "Unknown",
            "node_count": 1, "edge_count": 0, "error": error_msg,
        },
    }


def build_phone_graph(phone_data: dict) -> dict:
    """
    Convert phone lookup result to graph data (nodes + edges).

    Args:
        phone_data: Dictionary containing phone lookup results with keys:
                   - number, operator, country, prefix, wa_status, links, etc.

    Returns:
        Dictionary with 'nodes' and 'edges' arrays for Vis.js rendering.
        Never raises — on any malformed input, returns a minimal valid
        graph (single error node) instead of propagating the exception.
    """
    try:
        return _build_phone_graph_inner(phone_data if isinstance(phone_data, dict) else {})
    except Exception as e:
        logger.error(f"build_phone_graph gagal: {str(e)}", exc_info=True)
        return _empty_graph(phone_data if isinstance(phone_data, dict) else {}, str(e))


def _build_phone_graph_inner(phone_data: dict) -> dict:
    if not isinstance(phone_data, dict):
        phone_data = {}
    
    nodes = []
    edges = []
    node_id_counter = 0
    categories = defaultdict(list)
    
    # Central phone node
    central_node_id = node_id_counter
    node_id_counter += 1
    
    # Extract risk data dengan safe fallbacks
    risk_score = _safe_int(_safe_get(phone_data, "ml_risk_prediction", "risk_score"), default=0, min_val=0, max_val=100)
    risk_level = _safe_get(phone_data, "ml_risk_prediction", "risk_level", default="Unknown")
    
    # Determine risk color dan icon
    if risk_level == "High Risk":
        color = "#ef4444"
        title_risk = "🔴 High Risk"
    elif risk_level == "Medium Risk":
        color = "#f59e0b"
        title_risk = "🟠 Medium Risk"
    else:
        color = "#10b981"
        title_risk = "🟢 Low Risk"
    
    phone_number = _safe_str(phone_data.get("number"), "Unknown")
    
    central_node = {
        "id": central_node_id,
        "label": phone_number,
        "title": f"{phone_number}\n{title_risk}\nRisk Score: {risk_score}%",
        "shape": "diamond",
        "size": 40,
        "color": {"background": color, "border": color, "highlight": {"background": color}},
        "font": {"size": 16, "bold": {"color": "#ffffff"}},
        "physics": True,
        "mass": 2,
        "category": "target"
    }
    nodes.append(central_node)
    categories["target"].append(central_node_id)
    
    # Geographic info cluster
    operator = _safe_str(phone_data.get("operator"), "Unknown")
    country = _safe_str(phone_data.get("country"), "Unknown")
    prefix = _safe_str(phone_data.get("prefix"), "Unknown")
    
    geo_node_id = node_id_counter
    node_id_counter += 1
    nodes.append({
        "id": geo_node_id,
        "label": f"📍 {country}",
        "title": f"Location: {country}\nPrefix: {prefix}\nOperator: {operator}",
        "shape": "box",
        "size": 22,
        "color": {"background": "#06b6d4", "border": "#0891b2"},
        "font": {"size": 12, "color": "#ffffff"},
        "category": "geography"
    })
    categories["geography"].append(geo_node_id)
    edges.append({
        "from": central_node_id,
        "to": geo_node_id,
        "label": "Located",
        "width": 2.5,
        "color": {"color": "#06b6d4"},
        "arrows": "to"
    })
    
    # Operator detail
    operator_node_id = node_id_counter
    node_id_counter += 1
    nodes.append({
        "id": operator_node_id,
        "label": f"🏢 {operator}",
        "title": f"Telecommunications Operator: {operator}",
        "shape": "box",
        "size": 18,
        "color": {"background": "#3b82f6", "border": "#1e40af"},
        "font": {"size": 11},
        "category": "telecom"
    })
    categories["telecom"].append(operator_node_id)
    edges.append({
        "from": geo_node_id,
        "to": operator_node_id,
        "label": "Provider",
        "width": 1.5,
        "color": {"color": "#3b82f6"},
        "arrows": "to"
    })
    
    # Risk prediction cluster
    ml_risk = phone_data.get("ml_risk_prediction", {})
    if ml_risk:
        risk_node_id = node_id_counter
        node_id_counter += 1
        confidence = ml_risk.get('confidence', 0)
        nodes.append({
            "id": risk_node_id,
            "label": f"⚡ Risk: {risk_score}%",
            "title": f"Risk Level: {risk_level}\nConfidence: {confidence}%\nBased on ML Analysis",
            "shape": "star",
            "size": 20,
            "color": {"background": color, "border": color},
            "font": {"size": 11, "color": "#ffffff"},
            "category": "risk"
        })
        categories["risk"].append(risk_node_id)
        edges.append({
            "from": central_node_id,
            "to": risk_node_id,
            "label": "Risk",
            "width": 2,
            "color": {"color": color},
            "arrows": "to"
        })
    
    # WhatsApp status
    wa_status = phone_data.get("wa_status", {})
    if wa_status and wa_status.get("status"):
        wa_node_id = node_id_counter
        node_id_counter += 1
        wa_icon = "✅" if wa_status.get("status") == "Active" else "❌"
        wa_color = "#10b981" if wa_status.get("status") == "Active" else "#ef4444"
        nodes.append({
            "id": wa_node_id,
            "label": f"{wa_icon} WhatsApp",
            "title": f"WhatsApp Status: {wa_status.get('status')}\n{wa_status.get('note', '')}",
            "shape": "ellipse",
            "size": 18,
            "color": {"background": wa_color, "border": wa_color},
            "font": {"size": 11, "color": "#ffffff"},
            "category": "communication"
        })
        categories["communication"].append(wa_node_id)
        edges.append({
            "from": central_node_id,
            "to": wa_node_id,
            "label": "Platform",
            "width": 1.5,
            "color": {"color": wa_color},
            "arrows": "to"
        })
    
    # Links / Dork URLs cluster
    links = phone_data.get("links", {}) or {}
    if isinstance(links, dict) and len(links) > 0:
        links_container_id = node_id_counter
        node_id_counter += 1
        link_count = len(links)
        nodes.append({
            "id": links_container_id,
            "label": f"🔗 Links ({link_count})",
            "title": f"Total dork/search engine links: {link_count}",
            "shape": "box",
            "size": 20,
            "color": {"background": "#f97316", "border": "#c2410c"},
            "font": {"size": 11, "color": "#ffffff"},
            "category": "intelligence"
        })
        categories["intelligence"].append(links_container_id)
        edges.append({
            "from": central_node_id,
            "to": links_container_id,
            "label": "Found in",
            "width": 2,
            "color": {"color": "#f97316"},
            "arrows": "to"
        })
        
        for idx, (label, url) in enumerate(list(links.items())[:8]):
            try:
                link_label = _safe_str(label, "Link", max_len=20)
                link_url = _safe_str(url, "")
                if not link_url:
                    continue
                
                link_node_id = node_id_counter
                node_id_counter += 1
                nodes.append({
                    "id": link_node_id,
                    "label": link_label if len(link_label) <= 20 else link_label[:17] + "...",
                    "title": f"{link_label}\nURL: {link_url}",
                    "shape": "dot",
                    "size": 10,
                    "color": {"background": "#fbbf24", "border": "#d97706"},
                    "font": {"size": 9},
                    "category": "url"
                })
                categories["url"].append(link_node_id)
                edges.append({
                    "from": links_container_id,
                    "to": link_node_id,
                    "label": "index",
                    "width": 1,
                    "color": {"color": "#fbbf24"},
                    "arrows": "to",
                    "smooth": {"type": "curvedCW"}
                })
            except Exception as e:
                logger.warning(f"[graph_builder] Error processing link {idx}: {e}")
                continue
    
    # Google results cluster
    google_results = phone_data.get("google_results", [])
    if google_results and len(google_results) > 0:
        google_container_id = node_id_counter
        node_id_counter += 1
        nodes.append({
            "id": google_container_id,
            "label": f"🔍 Google ({len(google_results)})",
            "title": f"Google search results: {len(google_results)} matches",
            "shape": "box",
            "size": 20,
            "color": {"background": "#4f46e5", "border": "#312e81"},
            "font": {"size": 11, "color": "#ffffff"},
            "category": "search"
        })
        categories["search"].append(google_container_id)
        edges.append({
            "from": central_node_id,
            "to": google_container_id,
            "label": "Search",
            "width": 2,
            "color": {"color": "#4f46e5"},
            "arrows": "to"
        })
    
    # Breach data cluster
    breach_info = phone_data.get("breach_info", {})
    if breach_info and (breach_info.get("breached") or breach_info.get("breach_count", 0) > 0):
        breach_node_id = node_id_counter
        node_id_counter += 1
        breach_count = breach_info.get("breach_count", 0)
        nodes.append({
            "id": breach_node_id,
            "label": f"⚠️ Breaches ({breach_count})",
            "title": f"Found in {breach_count} data breach(es)\nLeaked Databases: {breach_info.get('databases', [])}",
            "shape": "diamond",
            "size": 18,
            "color": {"background": "#dc2626", "border": "#991b1b"},
            "font": {"size": 11, "color": "#ffffff"},
            "category": "security"
        })
        categories["security"].append(breach_node_id)
        edges.append({
            "from": central_node_id,
            "to": breach_node_id,
            "label": "Exposure",
            "width": 2.5,
            "color": {"color": "#dc2626"},
            "arrows": "to"
        })
    
    # Associated emails
    emails = _safe_list(phone_data.get("associated_emails"))
    if emails and len(emails) > 0:
        email_container_id = node_id_counter
        node_id_counter += 1
        email_preview = ", ".join([_safe_str(e) for e in emails[:3]])
        nodes.append({
            "id": email_container_id,
            "label": f"📧 Emails ({len(emails)})",
            "title": f"Associated email addresses: {email_preview}",
            "shape": "box",
            "size": 18,
            "color": {"background": "#8b5cf6", "border": "#6d28d9"},
            "font": {"size": 11, "color": "#ffffff"},
            "category": "contact"
        })
        categories["contact"].append(email_container_id)
        edges.append({
            "from": central_node_id,
            "to": email_container_id,
            "label": "Associated",
            "width": 1.5,
            "color": {"color": "#8b5cf6"},
            "arrows": "to"
        })
        
        for email in emails[:5]:
            try:
                email_str = _safe_str(email)
                if not email_str or "@" not in email_str:
                    continue
                
                email_node_id = node_id_counter
                node_id_counter += 1
                email_display = email_str[:25] + ("..." if len(email_str) > 25 else "")
                nodes.append({
                    "id": email_node_id,
                    "label": email_display,
                    "title": f"Email: {email_str}",
                    "shape": "dot",
                    "size": 10,
                    "color": {"background": "#a78bfa", "border": "#7c3aed"},
                    "font": {"size": 8},
                    "category": "email"
                })
                categories["email"].append(email_node_id)
                edges.append({
                    "from": email_container_id,
                    "to": email_node_id,
                    "width": 1,
                    "color": {"color": "#a78bfa"},
                    "arrows": "to",
                    "smooth": {"type": "curvedCW"}
                })
            except Exception as e:
                logger.warning(f"[graph_builder] Error processing email: {e}")
                continue
    
    return {
        "nodes": nodes,
        "edges": edges,
        "metadata": {
            "phone": phone_data.get("number"),
            "operator": operator,
            "country": country,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "categories": dict(categories),
            "category_summary": {cat: len(ids) for cat, ids in categories.items()}
        }
    }
