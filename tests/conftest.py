import sys
from pathlib import Path

# Add repository root directory to sys.path for pytest module imports
sys.path.insert(0, str(Path(__file__).parent.parent.resolve()))
