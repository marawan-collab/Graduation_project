import cv2
import numpy as np
from tensorflow.keras.models import load_model
import os

_model = None

def _get_model():
    """Lazy load the model to avoid import errors if model file doesn't exist"""
    global _model
    if _model is None:
        # Get the absolute path to the model file
        # This file is in the root, so model/ is relative to this file's directory
        current_dir = os.path.dirname(os.path.abspath(__file__))
        model_path = os.path.join(current_dir, 'model', 'mri_brain_tumor.h5')
        
        if not os.path.exists(model_path):
            raise FileNotFoundError(
                f"Model file not found: {model_path}\n"
                f"Please ensure the MRI brain tumor detection model is placed in: {os.path.dirname(model_path)}\n"
                f"Expected file: mri_brain_tumor.h5"
            )
        _model = load_model(model_path)
    return _model

def analyze_mri_image(image_path):
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Image file not found: {image_path}")
    
    img = cv2.imread(image_path)
    if img is None:
        raise ValueError(f"Could not read image from: {image_path}")
    
    model = _get_model()
    img = cv2.resize(img, (224, 224))
    img = img / 255.0
    img = np.expand_dims(img, axis=0)

    preds = model.predict(img, verbose=0)[0]
    # Support both binary (single logit/prob) and multi-class outputs
    if np.ndim(preds) == 0 or (hasattr(preds, 'shape') and preds.shape == ()):  # scalar
        prob = float(preds)
        label = "Tumor" if prob > 0.5 else "No Tumor"
        confidence = round(prob if prob > 0.5 else 1 - prob, 3)
        # Normalize naming for UI
        result = "No Tumor" if label == "No Tumor" else "Tumor"
        return result, confidence

    # Multi-class: assume order [Glioma, Meningioma, Pituitary, No Tumor]
    preds = np.array(preds, dtype=float)
    # If model outputs logits, apply softmax
    if preds.min() < 0 or preds.max() > 1:
        exp = np.exp(preds - np.max(preds))
        preds = exp / np.sum(exp)
    idx = int(np.argmax(preds))
    labels = ["Glioma", "Meningioma", "Pituitary", "No Tumor"]
    result = labels[idx] if idx < len(labels) else "No Tumor"
    confidence = round(float(preds[idx]), 3)
    return result, confidence
