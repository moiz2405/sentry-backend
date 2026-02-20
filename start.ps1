# Activate the virtual environment
winenv\Scripts\Activate.ps1

# Run the FastAPI app on port 8001
python -m uvicorn app.main:app --port 8001
