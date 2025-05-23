#!/usr/bin/env python3
import os
import pickle
import numpy as np
import pandas as pd
import logging
from typing import Dict, List, Any, Optional, Tuple, Union
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

class MalwareFeatureExtractor:
    """Extract features from files for use in machine learning models."""
    
    def __init__(self):
        """Initialize the feature extractor."""
        pass
    
    def extract_features(self, static_analysis: Dict[str, Any], dynamic_analysis: Dict[str, Any]) -> Dict[str, float]:
        """
        Extract numerical features from static and dynamic analysis results.
        
        Args:
            static_analysis: Results from static analysis
            dynamic_analysis: Results from dynamic analysis
            
        Returns:
            Dictionary of features
        """
        features = {}
        
        # Static features
        # File size
        if 'file_info' in static_analysis and 'size' in static_analysis['file_info']:
            features['file_size'] = float(static_analysis['file_info']['size'])
        else:
            features['file_size'] = 0.0
        
        # Entropy
        features['entropy'] = static_analysis.get('entropy', 0.0)
        
        # PE features
        pe_data = static_analysis.get('pe_data', {})
        
        # Number of sections
        features['num_sections'] = len(pe_data.get('sections', []))
        
        # Average section entropy
        if 'sections' in pe_data and pe_data['sections']:
            section_entropies = [s.get('entropy', 0.0) for s in pe_data['sections']]
            features['avg_section_entropy'] = sum(section_entropies) / len(section_entropies) if section_entropies else 0.0
            features['max_section_entropy'] = max(section_entropies) if section_entropies else 0.0
        else:
            features['avg_section_entropy'] = 0.0
            features['max_section_entropy'] = 0.0
        
        # Number of imports
        import_count = 0
        for dll, imports in pe_data.get('imports', {}).items():
            import_count += len(imports)
        features['import_count'] = import_count
        
        # Number of exports
        features['export_count'] = len(pe_data.get('exports', []))
        
        # Number of DLLs
        features['dll_count'] = len(pe_data.get('dlls', []))
        
        # String features
        features['suspicious_string_count'] = len(static_analysis.get('suspicious_strings', []))
        features['url_count'] = len(static_analysis.get('urls', []))
        features['ip_count'] = len(static_analysis.get('ips', []))
        
        # Dynamic features
        if dynamic_analysis:
            # Network activity
            features['network_connection_count'] = len(dynamic_analysis.get('network_activity', []))
            
            # Process activity
            features['process_count'] = len(dynamic_analysis.get('process_activity', []))
            
            # File operations
            features['file_operation_count'] = len(dynamic_analysis.get('file_operations', []))
            
            # Process execution time
            execution = dynamic_analysis.get('execution', {})
            features['execution_duration'] = execution.get('duration', 0.0)
        else:
            features['network_connection_count'] = 0
            features['process_count'] = 0
            features['file_operation_count'] = 0
            features['execution_duration'] = 0.0
        
        return features

class MalwareDetector:
    """Machine learning-based malware detector."""
    
    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize the malware detector.
        
        Args:
            model_path: Path to a trained model file (.pkl)
        """
        self.model = None
        self.feature_extractor = MalwareFeatureExtractor()
        
        # Default model path if none provided
        if model_path is None:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            parent_dir = os.path.dirname(current_dir)
            model_path = os.path.join(parent_dir, "model", "malware_model.pkl")
        
        self.model_path = model_path
        self._load_model()
    
    def _load_model(self) -> None:
        """Load a trained model from a pickle file."""
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                logging.info(f"Loaded model from {self.model_path}")
            except Exception as e:
                logging.error(f"Failed to load model: {e}")
                self.model = None
        else:
            logging.warning(f"Model not found at {self.model_path}. Creating a new model.")
            self.model = RandomForestClassifier(n_estimators=100, random_state=42)
    
    def _save_model(self) -> None:
        """Save the trained model to a pickle file."""
        try:
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            with open(self.model_path, 'wb') as f:
                pickle.dump(self.model, f)
            logging.info(f"Saved model to {self.model_path}")
        except Exception as e:
            logging.error(f"Failed to save model: {e}")
    
    def predict(self, static_analysis: Dict[str, Any], dynamic_analysis: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Predict whether a file is malicious based on its features.
        
        Args:
            static_analysis: Results from static analysis
            dynamic_analysis: Results from dynamic analysis (optional)
            
        Returns:
            Dictionary with prediction results
        """
        if self.model is None:
            return {
                'error': 'No model loaded',
                'prediction': 'unknown',
                'probability': 0.0
            }
        
        # Extract features
        features = self.feature_extractor.extract_features(static_analysis, dynamic_analysis or {})
        
        # Convert features to a format suitable for the model
        feature_vector = pd.DataFrame([features])
        
        try:
            # Make prediction
            prediction = self.model.predict(feature_vector)[0]
            
            # Get probability if the model supports it
            probability = 0.0
            if hasattr(self.model, 'predict_proba'):
                probabilities = self.model.predict_proba(feature_vector)[0]
                probability = float(probabilities[1])  # Probability of the malicious class
            
            return {
                'prediction': 'malicious' if prediction == 1 else 'benign',
                'probability': probability,
                'features_used': list(features.keys())
            }
        except Exception as e:
            logging.error(f"Error making prediction: {e}")
            return {
                'error': str(e),
                'prediction': 'unknown',
                'probability': 0.0
            }
    
    def train(self, training_data: List[Dict[str, Any]], labels: List[int]) -> Dict[str, Any]:
        """
        Train the model on a dataset.
        
        Args:
            training_data: List of dicts with static and dynamic analysis results
            labels: List of labels (0 for benign, 1 for malicious)
            
        Returns:
            Dictionary with training results
        """
        if len(training_data) != len(labels):
            return {'error': 'Number of samples and labels must match'}
        
        # Extract features from each sample
        features_list = []
        for sample in training_data:
            static = sample.get('static', {})
            dynamic = sample.get('dynamic', {})
            features = self.feature_extractor.extract_features(static, dynamic)
            features_list.append(features)
        
        # Convert to DataFrame
        X = pd.DataFrame(features_list)
        y = np.array(labels)
        
        # Split into train and test sets
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Create a new model
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        
        try:
            # Train the model
            self.model.fit(X_train, y_train)
            
            # Evaluate on test set
            y_pred = self.model.predict(X_test)
            metrics = {
                'accuracy': accuracy_score(y_test, y_pred),
                'precision': precision_score(y_test, y_pred, zero_division=0),
                'recall': recall_score(y_test, y_pred, zero_division=0),
                'f1': f1_score(y_test, y_pred, zero_division=0)
            }
            
            # Save the model
            self._save_model()
            
            return {
                'success': True,
                'metrics': metrics,
                'feature_importance': dict(zip(X.columns, self.model.feature_importances_))
            }
        except Exception as e:
            logging.error(f"Error training model: {e}")
            return {'error': str(e)}
    
    def generate_sample_training_data(self) -> Tuple[List[Dict[str, Any]], List[int]]:
        """
        Generate a small synthetic dataset for demonstration purposes.
        
        Returns:
            Tuple of (training_data, labels)
        """
        training_data = []
        labels = []
        
        # Generate synthetic benign samples
        for _ in range(50):
            static = {
                'file_info': {'size': np.random.randint(10000, 500000)},
                'entropy': np.random.uniform(3.0, 6.0),
                'pe_data': {
                    'sections': [
                        {'entropy': np.random.uniform(3.0, 6.0)} for _ in range(np.random.randint(3, 6))
                    ],
                    'imports': {f'dll{i}': [f'api{j}' for j in range(np.random.randint(5, 20))] 
                                for i in range(np.random.randint(3, 7))},
                    'exports': [f'export{i}' for i in range(np.random.randint(0, 5))],
                    'dlls': [f'dll{i}' for i in range(np.random.randint(3, 7))]
                },
                'suspicious_strings': [f'string{i}' for i in range(np.random.randint(0, 3))],
                'urls': [f'url{i}' for i in range(np.random.randint(0, 2))],
                'ips': [f'ip{i}' for i in range(np.random.randint(0, 1))]
            }
            
            dynamic = {
                'network_activity': [{}] * np.random.randint(0, 3),
                'process_activity': [{}] * np.random.randint(1, 5),
                'file_operations': [{}] * np.random.randint(2, 10),
                'execution': {'duration': np.random.uniform(0.1, 2.0)}
            }
            
            training_data.append({'static': static, 'dynamic': dynamic})
            labels.append(0)  # Benign
        
        # Generate synthetic malicious samples
        for _ in range(50):
            static = {
                'file_info': {'size': np.random.randint(100000, 5000000)},
                'entropy': np.random.uniform(6.0, 8.0),
                'pe_data': {
                    'sections': [
                        {'entropy': np.random.uniform(6.0, 8.0)} for _ in range(np.random.randint(5, 10))
                    ],
                    'imports': {f'dll{i}': [f'api{j}' for j in range(np.random.randint(20, 50))] 
                                for i in range(np.random.randint(7, 15))},
                    'exports': [f'export{i}' for i in range(np.random.randint(0, 3))],
                    'dlls': [f'dll{i}' for i in range(np.random.randint(7, 15))]
                },
                'suspicious_strings': [f'string{i}' for i in range(np.random.randint(5, 15))],
                'urls': [f'url{i}' for i in range(np.random.randint(3, 10))],
                'ips': [f'ip{i}' for i in range(np.random.randint(1, 5))]
            }
            
            dynamic = {
                'network_activity': [{}] * np.random.randint(5, 15),
                'process_activity': [{}] * np.random.randint(5, 15),
                'file_operations': [{}] * np.random.randint(10, 30),
                'execution': {'duration': np.random.uniform(2.0, 10.0)}
            }
            
            training_data.append({'static': static, 'dynamic': dynamic})
            labels.append(1)  # Malicious
        
        return training_data, labels

def create_default_model_file(model_path):
    """
    Create a default ML model if one doesn't exist.
    This trains a simple model on synthetic data.
    """
    if os.path.exists(model_path):
        return
    
    logging.info("Training default model on synthetic data")
    detector = MalwareDetector(model_path)
    training_data, labels = detector.generate_sample_training_data()
    detector.train(training_data, labels)

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    
    # Create default model if it doesn't exist
    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(current_dir)
    default_model_path = os.path.join(parent_dir, "model", "malware_model.pkl")
    
    create_default_model_file(default_model_path)
    
    if len(sys.argv) > 1:
        # For testing, we need some analysis results
        # In a real scenario, these would come from the analyzers
        mock_static_results = {
            'file_info': {'size': 250000},
            'entropy': 7.2,
            'pe_data': {
                'sections': [
                    {'name': '.text', 'entropy': 6.2},
                    {'name': '.data', 'entropy': 7.8}
                ],
                'imports': {
                    'kernel32.dll': ['CreateProcessA', 'ReadFile', 'WriteFile'],
                    'wininet.dll': ['InternetOpenA', 'InternetConnectA'],
                    'advapi32.dll': ['RegOpenKeyExA', 'RegSetValueExA']
                },
                'exports': [],
                'dlls': ['kernel32.dll', 'wininet.dll', 'advapi32.dll']
            },
            'suspicious_strings': ['This is an example malicious string', 'botnet command and control'],
            'urls': ['http://example.com/malware', 'https://badsite.com'],
            'ips': ['192.168.1.1', '10.0.0.1']
        }
        
        mock_dynamic_results = {
            'network_activity': [{} for _ in range(5)],
            'process_activity': [{} for _ in range(3)],
            'file_operations': [{} for _ in range(7)],
            'execution': {'duration': 3.5}
        }
        
        detector = MalwareDetector()
        results = detector.predict(mock_static_results, mock_dynamic_results)
        print(json.dumps(results, indent=4))
    else:
        print("Usage: python ml_detector.py <file_path>")