"""
Test script to check if MRI model is available and working
"""
import os
from mri_analysis import analyze_mri_image

def test_model():
    model_path = os.path.join('model', 'mri_brain_tumor.h5')
    
    print("=" * 60)
    print("MRI Model Test Script")
    print("=" * 60)
    print()
    
    if not os.path.exists(model_path):
        print(f"❌ Model file NOT FOUND: {model_path}")
        print()
        print("To fix this issue:")
        print("1. Obtain a trained brain tumor detection model (.h5 file)")
        print("2. Place it in the 'model' directory")
        print("3. Name it 'mri_brain_tumor.h5'")
        print()
        print("Expected location:")
        print(f"   {os.path.abspath(model_path)}")
        print()
        print("You can find pre-trained models from:")
        print("  - Kaggle datasets on brain tumor detection")
        print("  - Medical imaging AI repositories on GitHub")
        print("  - Research papers with code repositories")
        return False
    else:
        print(f"✅ Model file FOUND: {model_path}")
        print(f"   File size: {os.path.getsize(model_path) / (1024*1024):.2f} MB")
        print()
        print("Model is ready to use!")
        print("You can now upload MRI images through the web interface.")
        return True

if __name__ == "__main__":
    test_model()

