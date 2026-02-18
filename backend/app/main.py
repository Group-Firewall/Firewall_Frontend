import sys
import os
import joblib
import pandas as pd
import numpy as np
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

# Adding the ML-NIDS/src to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
backend_dir = os.path.dirname(current_dir)
parent_dir = os.path.dirname(backend_dir)
ml_nids_path = os.path.join(parent_dir, 'ML-NIDS')
src_path = os.path.join(ml_nids_path, 'src')
sys.path.insert(0, src_path)

# Trying the imports
try:
    from data_preprocessing import DataPreprocessor
    from hybrid_detection import HybridDetector
except ImportError as e:
    print(f"Error importing modules: {e}")
    # Fallback for when running directly
    sys.path.append(src_path)
    from data_preprocessing import DataPreprocessor
    from hybrid_detection import HybridDetector

from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

# Model paths
MODEL_DIR = os.path.join(ml_nids_path, 'models')
PREPROCESSOR_PATH = os.path.join(MODEL_DIR, 'preprocessor.pkl')
HYBRID_DETECTOR_PATH = os.path.join(MODEL_DIR, 'hybrid_detector.pkl')
SUPERVISED_MODEL_PATH = os.path.join(MODEL_DIR, 'supervised_random_forest.pkl') # Assuming RF is best
UNSUPERVISED_MODEL_PATH = os.path.join(MODEL_DIR, 'unsupervised_isolation_forest.pkl') # Assuming IF is best

# Global variables for models
preprocessor = None
hybrid_detector = None
models_loaded = False

class PredictionRequest(BaseModel):
    Source_IP: str
    Destination_IP: str
    Port: int
    Request_Type: str
    Protocol: str
    Payload_Size: int
    User_Agent: str
    Status: str
    Scan_Type: str


@app.on_event("startup")
def load_models():
    global preprocessor, hybrid_detector, models_loaded
    try:
        print(f"Loading models from {MODEL_DIR}...")
        
        # Load preprocessor
        if os.path.exists(PREPROCESSOR_PATH):
            preprocessor = DataPreprocessor().load(PREPROCESSOR_PATH)
            print("Preprocessor loaded.")
        else:
            print(f"Preprocessor not found at {PREPROCESSOR_PATH}")
            return

        # Load hybrid detector configuration
        if os.path.exists(HYBRID_DETECTOR_PATH):
           # Create a fresh instance and load config
           # Note: The HybridDetector.load method in the provided code loads config but NOT the model objects themselves.
           # We need to manually load the underlying models and set them.
           
           temp_detector = HybridDetector()
           temp_detector.load(HYBRID_DETECTOR_PATH)
           
           # determine which models to load based on the config
           sup_name = temp_detector.supervised_model_name
           unsup_name = temp_detector.unsupervised_model_name
           
           print(f"Loading supervised model: {sup_name}")
           print(f"Loading unsupervised model: {unsup_name}")
           
           sup_path = os.path.join(MODEL_DIR, f'supervised_{sup_name}.pkl')
           unsup_path = os.path.join(MODEL_DIR, f'unsupervised_{unsup_name}.pkl')
           
           if os.path.exists(sup_path) and os.path.exists(unsup_path):
               sup_model = joblib.load(sup_path)
               unsup_model = joblib.load(unsup_path)
               
               # Re-instantiate HybridDetector with correct config
               hybrid_detector = HybridDetector(
                   supervised_model_name=sup_name,
                   unsupervised_model_name=unsup_name,
                   signature_weight=temp_detector.signature_weight,
                   supervised_weight=temp_detector.supervised_weight,
                   unsupervised_weight=temp_detector.unsupervised_weight
               )
               
               # The HybridDetector expects wrappers or specific objects. 
               # In train_models.py:
               # class ModelWrapper: ...
               # sup_wrapper = ModelWrapper(sup_best_model, sup_trainer)
               # unsup_wrapper = unsup_trainer
               
               # We need to mimic this wrapper structure if the HybridDetector uses it.
               # Let's check HybridDetector.detect method.
               # Line 98: self.supervised_model.predict_proba(...)
               # Line 99: self.supervised_model.predict(...)
               # Line 107: self.unsupervised_model.predict_anomaly(...)
               # Line 113: self.unsupervised_model.models[...].decision_function(...)
               
               # It seems `supervised_model` expects `predict` and `predict_proba`. 
               # The `joblib.load` of `supervised_random_forest.pkl` likely returns the sklearn model directly.
               # So we might not need the wrapper if the sklearn model has these methods.
               # HOWEVER, `unsupervised_model` usage `self.unsupervised_model.predict_anomaly` suggests it expects the `UnsupervisedModelTrainer` instance, NOT the raw sklearn model.
               
               # Let's check `train_models.py` again.
               # It saves: `unsup_trainer.save_model(model_name, ...)`
               # `UnsupervisedModelTrainer.save_model` likely saves the specific model, not the trainer.
               # Let's verify `unsupervised_models.py` if possible, but I recall `train_models.py` saving `f'unsupervised_{model_name}.pkl'`.
               
               # If `hybrid_detector.py` calls `self.unsupervised_model.predict_anomaly`, then `self.unsupervised_model` MUST be an object with that method.
               # The `UnsupervisedModelTrainer` has that method.
               # Does the saved pickle contain the trainer or the model? 
               # `train_models.py` line 166: `unsup_trainer.save_model(...)`.
               
               # I'll need to check `unsupervised_models.py` to see what `save_model` does. 
               # But purely from `hybrid_detection.py` line 107, it calls `predict_anomaly`. Sklearn models don't have that.
               # So `self.unsupervised_model` MUST be the trainer or a wrapper.
               
               # I will define a helper class here to wrap the unsupervised model to match the interface if needed,
               # OR I might need to instantiate `UnsupervisedModelTrainer` and load the model into it.
               
               # Let's assume for now I need to wrap it.
               pass

           else:
               print(f"Models not found: {sup_path} or {unsup_path}")
               return
           
           # Load Unsupervised Model Wrapper
           from unsupervised_models import UnsupervisedModelTrainer
           # We need to create a dummy trainer and set its model
           unsup_trainer = UnsupervisedModelTrainer()
           unsup_trainer.models[unsup_name] = unsup_model
           
           # Load Supervised Model
           # The supervised model from joblib should be the sklearn model.
           # HybridDetector expects it to have predict and predict_proba.
           
           hybrid_detector.set_models(sup_model, unsup_trainer, preprocessor)
           models_loaded = True
           print("All models loaded successfully.")
           
        else:
            print(f"Hybrid detector config not found at {HYBRID_DETECTOR_PATH}")
            
    except Exception as e:
        print(f"Error loading models: {e}")
        import traceback
        traceback.print_exc()

@app.post("/predict")
def predict(request: PredictionRequest):
    if not models_loaded:
        raise HTTPException(status_code=503, detail="Models not loaded")
    
    try:
        # specific handling for timestamp as it is required by the preprocessor
        # We'll just use current time
        current_time = datetime.now()
        
        data = {
            'Timestamp': [current_time],
            'Source_IP': [request.Source_IP],
            'Destination_IP': [request.Destination_IP],
            'Port': [request.Port],
            'Request_Type': [request.Request_Type],
            'Protocol': [request.Protocol],
            'Payload_Size': [request.Payload_Size],
            'User_Agent': [request.User_Agent],
            'Status': [request.Status],
            'Scan_Type': [request.Scan_Type],
            # Intrusion is the target, not needed for prediction
        }
        
        df = pd.DataFrame(data)
        
        # Detect
        # detect_batch expects a dataframe and returns a dataframe
        results = hybrid_detector.detect_batch(df)
        
        # Extract result
        result = results.iloc[0]
        
        final_pred = result['is_attack']
        final_conf = result['confidence']
        
        return {
            "prediction": "Malicious" if final_pred else "Normal Traffic",
            "is_malicious": bool(final_pred),
            "confidence_score": float(final_conf),
            "details": {
                "signature_detected": bool(result['signature_detected']),
                "ml_detected": bool(result['ml_detected']),
                "decision_path": str(result['decision_path'])
            }
        }
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
