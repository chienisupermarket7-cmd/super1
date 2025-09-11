from fastapi import FastAPI, Form, File, UploadFile, HTTPException, Request, Header
from fastapi.responses import JSONResponse, FileResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import pymysql
import os
from dotenv import load_dotenv
import cloudinary
import hashlib
import cloudinary.uploader
from pathlib import Path
from pydantic import BaseModel
from cloudinary.utils import cloudinary_url
from datetime import datetime, timedelta
from functools import partial
import asyncio

app = FastAPI()

ALGORITHM = "HS256"
INDEX_PAGE = "https://chienisupermarket7-cmd.github.io/super/index.html"

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # ⚠️ In production, specify your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

load_dotenv()

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

ALLOWED_REFERRERS = ["https://chienisupermarket7-cmd.github.io/super"]

# ✅ Check if request is from allowed frontend
def verify_referrer(request: Request):
    referer = request.headers.get("referer", "")
    origin = request.headers.get("origin", "")
    return any(allowed in referer or allowed in origin for allowed in ALLOWED_REFERRERS)

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

@app.api_route("/offers", methods=["GET", "POST"])
async def offers(request: Request):
    # ✅ Block direct attacker requests
    if not verify_referrer(request):
        return RedirectResponse(url=INDEX_PAGE, status_code=302)

    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == "POST":
        data = await request.json()
        product_id = data.get("product_id")
        new_price = data.get("new_price")
        offer_label = data.get("offer_label")
        start_date = data.get("start_date")
        end_date = data.get("end_date")

        if not product_id or not new_price:
            raise HTTPException(status_code=400, detail="product_id and new_price are required")

        cursor.execute("SELECT UnitPrice FROM SupermarketProducts WHERE ProductID=%s", (product_id,))
        product = cursor.fetchone()
        if not product:
            cursor.close()
            conn.close()
            raise HTTPException(status_code=404, detail="Product not found")

        old_price = product["UnitPrice"]

        cursor.execute("""
            INSERT INTO offers (product_id, old_price, new_price, offer_label, start_date, end_date)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                old_price = VALUES(old_price),
                new_price = VALUES(new_price),
                offer_label = VALUES(offer_label),
                start_date = VALUES(start_date),
                end_date = VALUES(end_date)
        """, (product_id, old_price, new_price, offer_label, start_date, end_date))
        conn.commit()
        cursor.close()
        conn.close()
        return {"status": "Offer saved successfully"}

    elif request.method == "GET":
        # ✅ Clean up expired offers
        cursor.execute("SELECT product_id, old_price FROM offers WHERE end_date IS NOT NULL AND end_date < CURDATE()")
        expired_offers = cursor.fetchall()

        for offer in expired_offers:
            cursor.execute("UPDATE SupermarketProducts SET UnitPrice=%s WHERE ProductID=%s",
                           (offer["old_price"], offer["product_id"]))
            cursor.execute("DELETE FROM offers WHERE product_id=%s", (offer["product_id"],))
        if expired_offers:
            conn.commit()

        cursor.execute("""
            SELECT p.ProductID, p.ProductName, p.Description,
                   o.old_price, o.new_price, o.offer_label, o.start_date, o.end_date,
                   p.image_filename
            FROM offers o
            JOIN SupermarketProducts p ON o.product_id = p.ProductID
            WHERE (o.end_date IS NULL OR o.end_date >= CURDATE())
        """)
        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        return {"status": "OK", "data": [
            {
                "ProductID": row["ProductID"],
                "ProductName": row["ProductName"],
                "Description": row["Description"],
                "old_price": row["old_price"],
                "new_price": row["new_price"],
                "offer_label": row["offer_label"],
                "start_date": row["start_date"],
                "end_date": row["end_date"],
                "image_url": generate_signed_url(row["image_filename"]) if row["image_filename"] else None
            }
            for row in rows
        ]}

@app.get("/viewchieni")
async def view_memos(request: Request):
    # ✅ Block direct attacker requests
    if not verify_referrer(request):
        return RedirectResponse(url=INDEX_PAGE, status_code=302)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM SupermarketProducts")
    rows = cursor.fetchall()
    conn.close()

    return {"status": "OK", "data": [
        {
            'id': row['ProductID'],
            'productName': row.get('ProductName', ''),
            'category': row['Category'],
            'brand': row['Brand'],
            'unitprice': row['UnitPrice'],
            'quantity': row['QuantityInStock'],
            'expirydate': row['ExpiryDate'],
            'description': row['Description'],
            'image_url': generate_signed_url(row['image_filename'])
        } for row in rows
    ]}

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
        file_bytes = await image.read(MAX_FILE_SIZE + 1)
        if len(file_bytes) > MAX_FILE_SIZE:
            raise HTTPException(status_code=400, detail="File too large. Max 5MB.")

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

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO SupermarketProducts
            (ProductName, Category, Brand, UnitPrice, QuantityInStock, ExpiryDate, Description, image_filename)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (ProductName, Category, Brand, UnitPrice, QuantityInStock, ExpiryDate, Description, public_id))
        conn.commit()
        cursor.close()
        conn.close()

        return {"status": "OK", "message": "Product uploaded successfully.", "image_url": generate_signed_url(public_id)}

    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")
