import subprocess
import sys
import openai
import os

try:
    from transformers import pipeline
except ImportError as e:
    if 'Keras 3' in str(e):
        subprocess.check_call([sys.executable, "-m", "pip", "install", "tf-keras"])
        # Remove the line that references `tf`
        # sys.modules['keras'] = tf.keras
        from transformers import pipeline
    else:
        raise e

# Remove PyTorch import and configuration
# import torch
# assert torch.__version__ >= "1.0.0", "PyTorch version must be at least 1.0.0"

# Configure PyTorch to use CPU only if no GPU is available
# if not torch.cuda.is_available():
#     torch.set_default_tensor_type(torch.FloatTensor)

chatbot_pipeline = pipeline('text-generation', model='microsoft/DialoGPT-medium')

def get_available_models():
    """Return a list of available models."""
    try:
        # List available models for the user
        available_models = ["gpt-3.5-turbo", "gpt-4"]
        if os.getenv('CUSTOM_MODEL'):
            available_models.append(os.getenv('CUSTOM_MODEL'))
        return available_models
    except Exception as e:
        print(f"Error fetching models: {e}")
        return ["gpt-3.5-turbo"]  # Default fallback

def get_response(prompt, model="gpt-3.5-turbo"):
    """
    Get a response from the chatbot.
    
    Args:
        prompt: The user's input
        model: The model to use (defaults to gpt-3.5-turbo)
        
    Returns:
        str: The chatbot's response
    """
    try:
        # If the model is default-model or not specified, use gpt-3.5-turbo
        if not model or model == 'default-model':
            model = "gpt-3.5-turbo"
        
        # Check if the model is available
        available_models = get_available_models()
        if model not in available_models:
            model = available_models[0]  # Use the first available model
        
        # For newer chat models (gpt-3.5-turbo, gpt-4)
        if model.startswith("gpt-"):
            response = openai.ChatCompletion.create(
                model=model,
                messages=[
                    {"role": "system", "content": "You are a helpful assistant."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=1000,
                n=1,
                temperature=0.7,
            )
            return response.choices[0].message.content.strip()
        else:
            # For older completion models (if needed)
            response = openai.Completion.create(
                model=model,
                prompt=prompt,
                max_tokens=1000,
                n=1,
                temperature=0.7,
            )
            return response.choices[0].text.strip()
    except Exception as e:
        return f"Error: {str(e)}. Please try again later or select a different model."