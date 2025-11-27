"""
@fileoverview ML Traffic Classifier - Machine learning-based traffic categorization
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Machine learning-based traffic classifier for categorizing flows.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

from typing import Dict, Any, List, Optional
import numpy as np
from ...core.logging import get_logger

log = get_logger(__name__)

# Conditional import - scikit-learn is optional
try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    log.warning("scikit-learn_not_available", message="ML classification will not be available")


class MLTrafficClassifier:
    """
    Machine learning-based traffic classifier.
    
    Classifies traffic into categories:
    - normal: Regular traffic
    - suspicious: Potentially malicious
    - malicious: Known malicious patterns
    """
    
    def __init__(self):
        """Initialize ML classifier."""
        if not SKLEARN_AVAILABLE:
            self.model = None
            self.scaler = None
            self.trained = False
            log.warning("ml_classifier_initialized_without_sklearn")
            return
        
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        self.scaler = StandardScaler()
        self.trained = False
        self.feature_names = [
            "request_size",
            "response_size",
            "duration_ms",
            "method_encoded",
            "status_code",
            "has_auth",
            "is_https"
        ]
        log.info("ml_classifier_initialized")
    
    def extract_features(self, flow: Dict[str, Any]) -> np.ndarray:
        """
        Extract features from flow for classification.
        
        Features:
        - Request size
        - Response size
        - Duration
        - HTTP method (encoded)
        - Status code
        - Has authentication
        - Is HTTPS
        
        Args:
            flow: Flow data dictionary
            
        Returns:
            NumPy array of features
        """
        if not SKLEARN_AVAILABLE:
            return np.array([])
        
        # Encode HTTP method
        method_map = {"GET": 1, "POST": 2, "PUT": 3, "DELETE": 4, "PATCH": 5, "HEAD": 6, "OPTIONS": 7}
        method = flow.get("method", "GET")
        method_encoded = method_map.get(method, 0)
        
        # Extract features
        features = [
            flow.get("request_size", 0),
            flow.get("response_size", 0),
            flow.get("duration_ms", 0),
            method_encoded,
            flow.get("status_code", 0),
            1 if flow.get("auth_detected") else 0,
            1 if flow.get("url", "").startswith("https://") else 0
        ]
        
        return np.array(features).reshape(1, -1)
    
    async def classify(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classify traffic.
        
        Args:
            flow: Flow data dictionary
            
        Returns:
            Classification result with category and confidence
        """
        if not SKLEARN_AVAILABLE:
            return {
                "category": "unknown",
                "confidence": 0.0,
                "message": "scikit-learn not available"
            }
        
        if not self.trained:
            log.warning("ml_classifier_not_trained")
            return {
                "category": "unknown",
                "confidence": 0.0,
                "message": "Model not trained"
            }
        
        try:
            features = self.extract_features(flow)
            
            # Scale features
            features_scaled = self.scaler.transform(features)
            
            # Predict
            prediction = self.model.predict(features_scaled)[0]
            probabilities = self.model.predict_proba(features_scaled)[0]
            confidence = float(max(probabilities))
            
            categories = ["normal", "suspicious", "malicious"]
            category = categories[prediction] if prediction < len(categories) else "unknown"
            
            log.debug("traffic_classified", 
                     flow_id=flow.get("flow_id"), 
                     category=category, 
                     confidence=round(confidence, 2))
            
            return {
                "category": category,
                "confidence": confidence,
                "probabilities": {
                    "normal": float(probabilities[0]) if len(probabilities) > 0 else 0.0,
                    "suspicious": float(probabilities[1]) if len(probabilities) > 1 else 0.0,
                    "malicious": float(probabilities[2]) if len(probabilities) > 2 else 0.0
                },
                "features": features.tolist()[0]
            }
        except Exception as e:
            log.error("ml_classification_failed", error=str(e), error_type=type(e).__name__)
            return {
                "category": "unknown",
                "confidence": 0.0,
                "error": str(e)
            }
    
    def train(self, flows: List[Dict[str, Any]], labels: List[int]) -> None:
        """
        Train classifier on labeled data.
        
        Args:
            flows: List of flow data dictionaries
            labels: List of labels (0=normal, 1=suspicious, 2=malicious)
        """
        if not SKLEARN_AVAILABLE:
            log.warning("ml_classifier_train_skipped", reason="scikit-learn_not_available")
            return
        
        if len(flows) != len(labels):
            raise ValueError(f"Flows ({len(flows)}) and labels ({len(labels)}) must have same length")
        
        if len(flows) < 10:
            log.warning("ml_classifier_insufficient_data", samples=len(flows))
            return
        
        try:
            # Extract features
            X = np.array([self.extract_features(flow).flatten() for flow in flows])
            y = np.array(labels)
            
            # Scale features
            X_scaled = self.scaler.fit_transform(X)
            
            # Train model
            self.model.fit(X_scaled, y)
            self.trained = True
            
            # Calculate accuracy on training set
            accuracy = self.model.score(X_scaled, y)
            
            log.info("ml_classifier_trained", 
                    samples=len(flows),
                    accuracy=round(accuracy, 3))
        except Exception as e:
            log.error("ml_classifier_training_failed", error=str(e), error_type=type(e).__name__)
            self.trained = False
    
    def get_model_info(self) -> Dict[str, Any]:
        """
        Get model information.
        
        Returns:
            Dictionary with model info
        """
        return {
            "trained": self.trained,
            "sklearn_available": SKLEARN_AVAILABLE,
            "feature_count": len(self.feature_names) if SKLEARN_AVAILABLE else 0,
            "features": self.feature_names if SKLEARN_AVAILABLE else []
        }

