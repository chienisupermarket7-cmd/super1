from fastapi import FastAPI, Form, File, UploadFile, HTTPException, Request, Header, Depends
from fastapi.responses import JSONResponse, FileResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import json
import pymysql
import os
from dotenv import load_dotenv
import shutil
import zipfile
import io
import requests
import base64
from jose import jwt, JWTError, ExpiredSignatureError   # ✅ fixed import
import cloudinary
import hashlib
import cloudinary.uploader
from pathlib import Path
from pydantic import BaseModel
from urllib.parse import quote
from cloudinary.utils import cloudinary_url
from datetime import datetime, timedelta
from functools import partial
import asyncio
import smtplib
from email.message import EmailMessage


app = FastAPI()

ALGORITHM = "HS256"
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # ⚠️ Change "*" to a specific domain in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

load_dotenv()

SMTP_SERVER = os.getenv('SMTP_SERVER')   # Replace with your SMTP server
SMTP_PORT = os.getenv('SMTP_PORT')       # Use 465 for SSL, 587 for TLS
SMTP_USER = os.getenv('SMTP_USER')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')
SECRET_KEY = os.getenv('SECRET_KEY')

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

cloudinary.config(
    cloud_name=os.getenv('CLOUD_NAME'),
    api_key=os.getenv('API_KEY'),
    api_secret=os.getenv('API_SECRET')
)

def get_db_connection():
    return pymysql.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME"),
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True
    )

class User(BaseModel):
    email: str
    password: str

class Userregis(BaseModel):
    email: str
    name: str
    phonenumber: int
    password: str



@app.post("/login")
async def login(creds: User):
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Fetch user by email
    sql = "SELECT * FROM chieniusers WHERE email=%s"
    cursor.execute(sql, (creds.email,))
    user = cursor.fetchone()

    if not user:
        cursor.close()
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # 2. Hash incoming password and compare with stored hash
    hashed_input_password = hashlib.sha256(creds.password.encode()).hexdigest()
    if hashed_input_password != user["password"]:
        cursor.close()
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # 3. Generate JWT payload like /register
    payload = {
        "sub": user["name"],        # use name as subject
        "email": user["email"],
        "phone": user["phonenumber"],
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(days=1)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    # 4. Save token in DB
    update_sql = "UPDATE users SET token=%s WHERE email=%s"
    cursor.execute(update_sql, (token, user["email"]))
    conn.commit()

    cursor.close()
    conn.close()

    # 5. Return safe response
    user.pop("password", None)
    user["token"] = token

    return {"status": "Login successful", "user": user}

def verify_token(authorization: str = Header(...)):
    try:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer":
            raise HTTPException(status_code=403, detail="Invalid authentication scheme")

        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload

    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")

    except JWTError:
        raise HTTPException(status_code=403, detail="Invalid token")


def generate_signed_url(public_id: str) -> str:
    url, _ = cloudinary_url(
        public_id,
        type="authenticated",
        resource_type="image",
        sign_url=True,
        secure=True,
        expires_at=(datetime.utcnow() + timedelta(hours=1)).timestamp()
    )
    return url

ALGORITHM = "HS256"

@app.post("/register")
async def register(creds: Userregis):
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Check if user exists
    sql = "SELECT * FROM chieniusers WHERE email=%s"
    cursor.execute(sql, (creds.email,))
    user = cursor.fetchone()
    if user:
        cursor.close()
        conn.close()
        raise HTTPException(status_code=400, detail="This user already exists")

    # 2. Hash password
    hashed_password = hashlib.sha256(creds.password.encode()).hexdigest()

    # 3. Create JWT payload for the new user
    payload = {
        "sub": creds.name,
        "email": creds.email,
        "phone": creds.phonenumber
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    # 4. Insert new user into users table
    insert_sql = """
        INSERT INTO chieniusers (email, name, phonenumber, password, token)
        VALUES (%s, %s, %s, %s, %s)
    """
    cursor.execute(insert_sql, (creds.email, creds.name, creds.phonenumber, hashed_password, token))
    conn.commit()

    cursor.close()
    conn.close()

    # 5. Return success with token
    return {
        "status": "Registered successfully",
        "token": token
    }
@app.api_route("/offers", methods=["GET", "POST"])
async def offers(request: Request):
    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == "POST":
        data = await request.json()

        product_id = data.get("product_id")
        new_price = data.get("new_price")
        offer_label = data.get("offer_label")
        start_date = data.get("start_date")   # must be provided manually
        end_date = data.get("end_date")       # must be provided manually

        if not product_id or not new_price:
            raise HTTPException(status_code=400, detail="product_id and new_price are required")

        # 🔥 fetch old price from products table
        cursor.execute("SELECT UnitPrice FROM SupermarketProducts WHERE ProductID=%s", (product_id,))
        product = cursor.fetchone()
        if not product:
            cursor.close()
            conn.close()
            raise HTTPException(status_code=404, detail="Product not found")

        old_price = product["UnitPrice"]

        sql = """
        INSERT INTO offers (product_id, old_price, new_price, offer_label, start_date, end_date)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            old_price = VALUES(old_price),
            new_price = VALUES(new_price),
            offer_label = VALUES(offer_label),
            start_date = VALUES(start_date),
            end_date = VALUES(end_date)
        """
        cursor.execute(sql, (product_id, old_price, new_price, offer_label, start_date, end_date))
        conn.commit()

        cursor.close()
        conn.close()
        return {"status": "Offer saved successfully"}

    # -------- GET: Customers fetch active offers --------
    elif request.method == "GET":
        sql = """
        SELECT p.ProductID, p.ProductName, p.Description,
               o.old_price, o.new_price, o.offer_label, o.start_date, o.end_date,
               p.image_filename
        FROM offers o
        JOIN SupermarketProducts p ON o.product_id = p.ProductID
        WHERE (o.end_date IS NULL OR o.end_date >= CURDATE())
        """
        cursor.execute(sql)
        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        offers = []
        for row in rows:
            offers.append({
                "ProductID": row["ProductID"],
                "ProductName": row["ProductName"],
                "Description": row["Description"],
                "old_price": row["old_price"],
                "new_price": row["new_price"],
                "offer_label": row["offer_label"],
                "start_date": row["start_date"],
                "end_date": row["end_date"],
                "image_url": generate_signed_url(row["image_filename"]) if row["image_filename"] else None
            })

        return {"status": "OK", "data": offers}


@app.post("/upload")
async def upload_file(
    ProductName: str = Form(...),
    Category: str = Form(...),
    Brand: str = Form(...),
    UnitPrice: float = Form(...),
    QuantityInStock: int = Form(...),
    ExpiryDate: str = Form(...),
    Description: str = Form(...),
    image: UploadFile = File(...)
):
    try:
        # 1️⃣ Read file and check size
        file_bytes = await image.read(MAX_FILE_SIZE + 1)
        if len(file_bytes) > MAX_FILE_SIZE:
            raise HTTPException(status_code=400, detail="File too large. Max 5MB.")

        # 2️⃣ Upload to Cloudinary
        upload_func = partial(
            cloudinary.uploader.upload,
            file_bytes,
            folder="products",
            type="authenticated"
        )
        upload_result = await asyncio.to_thread(upload_func)
        public_id = upload_result.get("public_id")
        if not public_id:
            raise HTTPException(status_code=500, detail="Image upload failed.")

        # 3️⃣ Save product in DB
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO SupermarketProducts
            (ProductName, Category, Brand, UnitPrice, QuantityInStock, ExpiryDate, Description, image_filename)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            ProductName,
            Category,
            Brand,
            UnitPrice,
            QuantityInStock,
            ExpiryDate,
            Description,
            public_id
        ))
        conn.commit()
        cursor.close()
        conn.close()

        signed_url = generate_signed_url(public_id)

        return {
            "status": "OK",
            "message": "Product uploaded successfully.",
            "image_url": signed_url
        }

    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")


@app.get("/viewchieni")
async def view_memos(request: Request):
    # Check if the request is from a browser expecting HTML
    accept_header = request.headers.get("accept", "")
    if "text/html" in accept_header:
        return RedirectResponse(url="https://chienisupermarket7-cmd.github.io/super")

    # Otherwise, return JSON (API response)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM SupermarketProducts")
    rows = cursor.fetchall()
    conn.close()

    products = []
    for row in rows:
        image_url = generate_signed_url(row['image_filename'])
        product_data = {
            'id': row['ProductID'],
            'productName': row.get('ProductName', ''),
            'category': row['Category'],
            'brand': row['Brand'],
            'unitprice': row['UnitPrice'],
            'quantity': row['QuantityInStock'],
            'expirydate': row['ExpiryDate'],
            'description': row['Description'],
            'image_url': image_url
        }
        products.append(product_data)

    return JSONResponse(content={"status": "OK", "data": products})
