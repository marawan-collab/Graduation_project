import cv2
import numpy as np
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.image import load_img, img_to_array
import os
import json

_model = None
_labels_cache = None

def _get_model():
    """Lazy load the model and support multiple common locations.

    Search order (first existing wins):
      1) Environment variable MRI_MODEL_PATH
      2) INFO/model/mri_brain_tumor.h5 (recommended)
      3) INFO/models/model.h5 (legacy)
      4) INFO/model/model.h5 (alt name)
    """
    global _model
    if _model is None:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        candidates = []

        # 1) Environment variable override
        env_path = os.getenv('MRI_MODEL_PATH')
        if env_path:
            candidates.append(env_path)

        # 2) Recommended location
        candidates.append(os.path.join(current_dir, 'model', 'mri_brain_tumor.h5'))
        # 3) Legacy/example locations
        candidates.append(os.path.join(current_dir, 'models', 'model.h5'))
        candidates.append(os.path.join(current_dir, 'model', 'model.h5'))

        model_path = next((p for p in candidates if p and os.path.exists(p)), None)
        if not model_path:
            raise FileNotFoundError(
                "MRI model file not found. Checked these locations:\n" +
                "\n".join(f" - {p}" for p in candidates)
            )
        _model = load_model(model_path)
    return _model

def _get_labels(num_outputs: int):
    """Return label names in correct order for multi-class models.
    Priority: labels.txt, class_indices.json, sensible defaults.
    """
    global _labels_cache
    if _labels_cache is not None and len(_labels_cache) == num_outputs:
        return _labels_cache

    current_dir = os.path.dirname(os.path.abspath(__file__))
    model_dir = os.path.join(current_dir, 'model')

    labels_txt = os.path.join(model_dir, 'labels.txt')
    if os.path.exists(labels_txt):
        try:
            with open(labels_txt, 'r', encoding='utf-8') as f:
                labels = [line.strip() for line in f if line.strip()]
            if len(labels) == num_outputs:
                _labels_cache = labels
                return _labels_cache
        except Exception:
            pass

    class_indices_json = os.path.join(model_dir, 'class_indices.json')
    if os.path.exists(class_indices_json):
        try:
            with open(class_indices_json, 'r', encoding='utf-8') as f:
                class_indices = json.load(f)
            inverse = {v: k for k, v in class_indices.items()}
            labels = [inverse[i] for i in range(num_outputs) if i in inverse]
            if len(labels) == num_outputs:
                _labels_cache = [l.replace('_', ' ').title() for l in labels]
                return _labels_cache
        except Exception:
            pass

    if num_outputs == 4:
        _labels_cache = ["Glioma", "Meningioma", "Pituitary", "No Tumor"]
    elif num_outputs == 2:
        _labels_cache = ["Tumor", "No Tumor"]
    else:
        _labels_cache = [f"Class {i}" for i in range(num_outputs)]
    return _labels_cache

def analyze_mri_image(image_path):
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Image file not found: {image_path}")

    model = _get_model()

    # Determine expected input size from the model
    # input_shape like: (None, H, W, C)
    input_shape = getattr(model, 'input_shape', None)
    if isinstance(input_shape, (list, tuple)) and len(input_shape) > 0 and isinstance(input_shape[0], (list, tuple)):
        # Some models have multiple inputs; pick the first
        input_shape = input_shape[0]
    if not input_shape or len(input_shape) < 4:
        target_size = (224, 224)
    else:
        height = input_shape[1] or 224
        width = input_shape[2] or 224
        target_size = (int(width), int(height))

    # Use Keras loader to ensure RGB and dtype float32
    pil_img = load_img(image_path, target_size=(target_size[1], target_size[0]))
    img = img_to_array(pil_img)
    img = img.astype('float32') / 255.0
    img = np.expand_dims(img, axis=0)

    preds = model.predict(img, verbose=0)[0]
    if np.ndim(preds) == 0 or (hasattr(preds, 'shape') and preds.shape == ()):  # scalar
        prob = float(preds)
        label = "Tumor" if prob > 0.5 else "No Tumor"
        confidence = round(prob if prob > 0.5 else 1 - prob, 3)
        result = "No Tumor" if label == "No Tumor" else "Tumor"
        return result, confidence

    preds = np.array(preds, dtype=float)
    if preds.min() < 0 or preds.max() > 1:
        exp = np.exp(preds - np.max(preds))
        preds = exp / np.sum(exp)
    num_outputs = int(preds.shape[0])
    labels = _get_labels(num_outputs)
    
    # Prefer explicit No-Tumor class when sufficiently probable
    normalized_labels = [l.strip().lower().replace(' ', '').replace('_', '') for l in labels]
    no_tumor_aliases = {"notumor", "notumour", "notum", "notumourclass", "notumorclass", "notumours", "notumors", "notumourlabel", "notumorlabel", "notumourcategory", "notumorcategory", "notumourtype", "notumortype", "notumourgroup", "notumorgroup", "not", "no", "notumourx", "notumorx", "notumorxx", "notumourxx", "notumorxxx", "notumourxxx", "notumor_", "notumour_"}
    no_tumor_aliases.update({"notumor", "notumour", "notumorclass", "notumourclass", "notumorlabel", "notumourlabel"})
    no_tumor_idx = None
    for i, nl in enumerate(normalized_labels):
        if nl in {"notumor", "notumour", "notumorclass", "notumourclass", "notumorlabel", "notumourlabel", "notumorcategory", "notumourcategory", "notumortype", "notumourtype", "notumorgroup", "notumourgroup", "notum", "no", "notumourx", "notumorx"} or nl == "notumor" or nl == "notumour" or nl == "notumorclass" or nl == "notumourclass" or nl == "notumorlabel" or nl == "notumourlabel" or nl == "notumorcategory" or nl == "notumourcategory" or nl == "notumortype" or nl == "notumourtype" or nl == "notumorgroup" or nl == "notumourgroup" or nl == "notum":
            no_tumor_idx = i
            break
        if nl in {"notumor", "notumour", "notumorclass", "notumourclass", "notumorlabel", "notumourlabel"}:
            no_tumor_idx = i
            break
        if nl in {"notumor", "notumour", "notumorclass", "notumourclass", "notumorlabel", "notumourlabel", "notumorcategory", "notumourcategory"}:
            no_tumor_idx = i
            break
        if nl in {"notumor", "notumour", "notumorclass", "notumourclass", "notumorlabel", "notumourlabel", "notumorcategory", "notumourcategory", "notumortype", "notumourtype"}:
            no_tumor_idx = i
            break
        if nl in {"notumor", "notumour", "notumorclass", "notumourclass", "notumorlabel", "notumourlabel", "notumorcategory", "notumourcategory", "notumortype", "notumourtype", "notumorgroup", "notumourgroup"}:
            no_tumor_idx = i
            break
        if nl in {"notumor", "notumour", "notumorclass", "notumourclass", "notumorlabel", "notumourlabel", "notumorcategory", "notumourcategory", "notumortype", "notumourtype", "notumorgroup", "notumourgroup", "notum", "no"}:
            no_tumor_idx = i
            break
        if nl in {"notumor", "notumour", "notumorlabel", "notumourlabel"}:
            no_tumor_idx = i
            break
        if nl in {"notumor", "notumour"}:
            no_tumor_idx = i
            break
        if nl in {"notumor", "notumour", "notumor_", "no_tumor", "notumorx"}:
            no_tumor_idx = i
            break
        if nl in {"notumor", "no_tumor", "notumour"}:
            no_tumor_idx = i
            break
    if no_tumor_idx is None:
        # Common normalized variants
        for i, nl in enumerate(normalized_labels):
            if nl in {"notumor", "notumour", "notumor", "notumour", "notumourx", "notumorx", "notumor_", "notumor", "notumours", "notumors"} or nl == "notumor" or nl == "notumour" or nl == "notumor" or nl == "no_tumor" or nl == "notumor":
                no_tumor_idx = i
                break

    if no_tumor_idx is not None and 0 <= no_tumor_idx < len(preds):
        p_no = float(preds[no_tumor_idx])
        if p_no >= 0.5:
            return "notumor", round(p_no, 3)

    # Otherwise, return the highest-probability tumor class
    idx = int(np.argmax(preds))
    # If the highest is the no_tumor class but below threshold, pick next best tumor
    if no_tumor_idx is not None and idx == no_tumor_idx:
        # mask out no_tumor and choose next best
        masked = preds.copy()
        masked[no_tumor_idx] = -1.0
        idx = int(np.argmax(masked))
    result = labels[idx] if idx < len(labels) else "Glioma"
    confidence = round(float(preds[idx]), 3)
    return result, confidence
