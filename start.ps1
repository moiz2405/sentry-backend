# Activate the virtual environment
winenv\Scripts\Activate.ps1

# Run the FastAPI app on port 9000
python -m uvicorn app.main:app --port 9000
