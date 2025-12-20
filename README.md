# RestaurantApp (Minimal Flask Example)

This is a minimal restaurant ordering & reservation system built with Flask and SQLite for learning purposes.

## Features
- User registration & login (simple session-based auth)
- Browse menu (categorized) with images (placeholder)
- Add to cart, update/remove, place order (Cash on Delivery)
- Make table reservations
- View order & reservation history
- Admin login to add / edit / delete menu items and view orders

This project is for learning and demo only (no production-level security or email).

## Requirements
Install dependencies:
```
pip install -r requirements.txt
```

## Run locally (Linux/Mac/Windows)
1. create virtualenv (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate   # Windows: venv\Scripts\activate
   ```
2. install:
   ```bash
   pip install -r requirements.txt
   ```
3. initialize database and run:
   ```bash
   export FLASK_APP=app.py       # Windows PowerShell: $env:FLASK_APP = "app.py"
   flask run
   ```
4. Open http://127.0.0.1:5000

## Notes
- Admin default credentials: username=`admin`, password=`adminpass` (created automatically on first run)
- Images are placeholders; you can replace `static/img` files.




flask --version
flask run

python app.py
