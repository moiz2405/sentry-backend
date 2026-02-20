#!/bin/bash
source venv/bin/activate
uvicorn app.main:app --reload --port 9000
