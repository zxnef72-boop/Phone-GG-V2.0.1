# ============================================================
#  Phone Risk Analysis Module (Rule-Based)
#  Simplified version for production stability and low memory usage
# ============================================================
import logging

logger = logging.getLogger(__name__)

class PhoneRiskPredictor:
    """
    Rule-based phone number risk analysis for production stability.
    
    This simplified version uses pattern matching and heuristics instead of
    machine learning to avoid memory issues and improve startup time.
    """
    
    def __init__(self):
        """Initialize the risk predictor (no model loading)."""
        logger.info("[AI Model] Rule-based risk predictor initialized")
    
    def predict_risk(self, phone_number: str) -> dict:
        """
        Predict risk level for a phone number using rule-based analysis.
        
        Args:
            phone_number: Normalized phone number (62xxxxxxxxxx format)
        
        Returns:
            Dictionary with risk prediction results
        """
        try:
            # Extract features
            length = len(phone_number)
            sequential_count = 0
            repeated_count = 0
            digit_sum = 0
            
            for i in range(len(phone_number) - 1):
                if phone_number[i].isdigit() and phone_number[i+1].isdigit():
                    current = int(phone_number[i])
                    next_digit = int(phone_number[i+1])
                    
                    # Sequential patterns
                    if abs(current - next_digit) == 1:
                        sequential_count += 1
                    
                    # Repeated patterns
                    if current == next_digit:
                        repeated_count += 1
            
            # Calculate digit sum
            for char in phone_number:
                if char.isdigit():
                    digit_sum += int(char)
            
            # Rule-based risk scoring
            risk_score = 0
            
            # Sequential patterns increase risk
            if sequential_count > 3:
                risk_score += 30
            elif sequential_count > 1:
                risk_score += 15
            
            # Repeated patterns increase risk
            if repeated_count > 2:
                risk_score += 25
            elif repeated_count > 0:
                risk_score += 10
            
            # Abnormal length
            if length > 15:
                risk_score += 15
            elif length < 10:
                risk_score += 10
            
            # Digit distribution patterns
            if digit_sum > 70 or digit_sum < 20:
                risk_score += 10
            
            # Cap risk score at 100
            risk_score = min(risk_score, 100)
            
            # Determine risk level
            if risk_score >= 70:
                risk_level = "High Risk"
            elif risk_score >= 40:
                risk_level = "Medium Risk"
            else:
                risk_level = "Low Risk"
            
            # Calculate confidence based on pattern strength
            confidence = 80.0
            if sequential_count > 3 or repeated_count > 2:
                confidence = 90.0
            elif risk_score < 20:
                confidence = 75.0
            
            return {
                "risk_level": risk_level,
                "risk_score": risk_score,
                "confidence": confidence,
                "probabilities": {
                    "low": round(100 - risk_score, 2),
                    "medium": round(risk_score * 0.4, 2),
                    "high": round(risk_score * 0.6, 2)
                },
                "features": {
                    "length": length,
                    "sequential_patterns": sequential_count,
                    "repeated_patterns": repeated_count,
                    "digit_sum": digit_sum
                }
            }
            
        except Exception as e:
            logger.error(f"[AI Model] Prediction error: {str(e)}")
            return {
                "risk_level": "Low Risk",
                "risk_score": 20,
                "confidence": 50.0,
                "probabilities": {
                    "low": 80.0,
                    "medium": 15.0,
                    "high": 5.0
                },
                "error": str(e)
            }

# Global instance
_predictor = None

def get_phone_risk_prediction(phone_number: str) -> dict:
    """
    Get risk prediction for a phone number.
    
    Args:
        phone_number: Normalized phone number (62xxxxxxxxxx format)
    
    Returns:
        Dictionary with risk prediction results
    """
    global _predictor
    if _predictor is None:
        _predictor = PhoneRiskPredictor()
    
    return _predictor.predict_risk(phone_number)