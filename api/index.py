import sys
import os

# Add the parent directory to the path so we can import app
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Load environment variables if .env exists (for local testing)
from dotenv import load_dotenv
load_dotenv()

# Import the Flask app
from app import app

