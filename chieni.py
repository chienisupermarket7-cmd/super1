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
from typing import Optional
import io
import requests
import base64
from jose import jwt, JWTError, ExpiredSignatureError
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

# ✅ Restrict CORS to your frontend
FRONTEND_DOMAIN = "https://chienisupermarket7-cmd.github.io"
REDIRECT_URL = f"{FRONTEND_DOMAIN}/super"

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

load_dotenv()

SMTP_SERVER = os.getenv('SMTP_SERVER')
SMTP_PORT = os.getenv('SMTP_PORT')
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
class OfferUpdate(BaseModel):
    new_price: float | None = None
    offer_label: str | None = None
    start_date: str | None = None
    end_date: str | None = None

# ✅ Function to verify request origin
def verify_referrer(request: Request) -> bool:
    referer = request.headers.get("referer", "")
    origin = request.headers.get("origin", "")
    return referer.startswith(FRONTEND_DOMAIN) or origin.startswith(FRONTEND_DOMAIN)
@app.get("/")
async def home():
    return RedirectResponse(url=REDIRECT_URL, status_code=302)
@app.post("/login")
async def login(creds: User):
    conn = get_db_connection()
    cursor = conn.cursor()

    sql = "SELECT * FROM chieniusers WHERE email=%s"
    cursor.execute(sql, (creds.email,))
    user = cursor.fetchone()

    if not user:
        cursor.close()
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid email or password")

    hashed_input_password = hashlib.sha256(creds.password.encode()).hexdigest()
    if hashed_input_password != user["password"]:
        cursor.close()
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid email or password")

    payload = {
        "sub": user["name"],
        "email": user["email"],
        "phone": user["phonenumber"],
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(days=1)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    update_sql = "UPDATE users SET token=%s WHERE email=%s"
    cursor.execute(update_sql, (token, user["email"]))
    conn.commit()

    cursor.close()
    conn.close()

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

@app.post("/register")
async def register(creds: Userregis):
    conn = get_db_connection()
    cursor = conn.cursor()

    sql = "SELECT * FROM chieniusers WHERE email=%s"
    cursor.execute(sql, (creds.email,))
    user = cursor.fetchone()
    if user:
        cursor.close()
        conn.close()
        raise HTTPException(status_code=400, detail="This user already exists")

    hashed_password = hashlib.sha256(creds.password.encode()).hexdigest()

    payload = {
        "sub": creds.name,
        "email": creds.email,
        "phone": creds.phonenumber
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    insert_sql = """
        INSERT INTO chieniusers (email, name, phonenumber, password, token)
        VALUES (%s, %s, %s, %s, %s)
    """
    cursor.execute(insert_sql, (creds.email, creds.name, creds.phonenumber, hashed_password, token))
    conn.commit()

    cursor.close()
    conn.close()

    return {"status": "Registered successfully", "token": token}

@app.api_route("/offers", methods=["GET", "POST"])
async def offers(request: Request):
    # ✅ Redirect if coming from another site
    if not verify_referrer(request):
        return RedirectResponse(url=REDIRECT_URL, status_code=302)

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

    elif request.method == "GET":
        cursor.execute("SELECT product_id, old_price FROM offers WHERE end_date IS NOT NULL AND end_date < CURDATE()")
        expired_offers = cursor.fetchall()

        for offer in expired_offers:
            cursor.execute(
                "UPDATE SupermarketProducts SET UnitPrice=%s WHERE ProductID=%s",
                (offer["old_price"], offer["product_id"])
            )
            cursor.execute("DELETE FROM offers WHERE product_id=%s", (offer["product_id"],))

        if expired_offers:
            conn.commit()

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

        return {"status": "OK", "message": "Product uploaded successfully.", "image_url": signed_url}

    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")

@app.get("/viewchieni")
async def view_memos(request: Request):
    # ✅ Redirect if coming from another site
    if not verify_referrer(request):
        return RedirectResponse(url=REDIRECT_URL, status_code=302)

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

    return {"status": "OK", "data": products}
# ✅ Get all categories
@app.get("/supermarket/categories")
async def get_categories():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT Category FROM SupermarketProducts")
    rows = cursor.fetchall()
    conn.close()

    categories = [row["Category"] for row in rows]
    return {"status": "OK", "categories": categories}

# ✅ Get products by category (category in the URL)
@app.get("/products/by-category/{category}")
async def get_products_by_category(category: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM SupermarketProducts WHERE Category = %s", (category,))
    rows = cursor.fetchall()
    conn.close()

    products = []
    for row in rows:
        image_url = generate_signed_url(row["image_filename"])
        product_data = {
            "ProductID": row["ProductID"],
            "productName": row.get("ProductName", ""),
            "category": row["Category"],
            "Brand": row["Brand"],
            "UnitPrice": row["UnitPrice"],
            "QuantityInStock": row["QuantityInStock"],
            "expirydate": row["ExpiryDate"],
            "Description": row["Description"],
            "image_url": image_url,
        }
        products.append(product_data)

    return {"status": "OK", "products": products}
@app.put("/offers/update/{product_id}")
async def update_offer(product_id: int, data: OfferUpdate):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM offers WHERE product_id=%s", (product_id,))
    offer = cursor.fetchone()
    if not offer:
        cursor.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Offer not found for this product_id")

    fields, values = [], []
    if data.new_price is not None:
        fields.append("new_price=%s")
        values.append(data.new_price)
    if data.offer_label is not None:
        fields.append("offer_label=%s")
        values.append(data.offer_label)
    if data.start_date is not None:
        fields.append("start_date=%s")
        values.append(data.start_date)
    if data.end_date is not None:
        fields.append("end_date=%s")
        values.append(data.end_date)

    if not fields:
        raise HTTPException(status_code=400, detail="No fields to update provided")

    sql = f"UPDATE offers SET {', '.join(fields)} WHERE product_id=%s"
    values.append(product_id)
    cursor.execute(sql, tuple(values))
    conn.commit()

    cursor.close()
    conn.close()

    return {"status": "OK", "message": "Offer updated successfully"}
@app.delete("/offers/delete/{product_id}")
async def delete_offer(product_id: int):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # ✅ correct table name
        cursor.execute("DELETE FROM offers WHERE product_id = %s", (product_id,))
        conn.commit()

        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Offer not found")

        cursor.close()
        conn.close()
        return {"status": "Offer deleted successfully", "product_id": product_id}

    except pymysql.MySQLError as e:  # ✅ catch MySQL errors properly
        raise HTTPException(status_code=500, detail=f"MySQL error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")
@app.put("/products/update/{product_id}")
async def update_product(
    product_id: int,
    ProductName: Optional[str] = Form(None),
    Category: Optional[str] = Form(None),
    Brand: Optional[str] = Form(None),
    UnitPrice: Optional[float] = Form(None),
    QuantityInStock: Optional[int] = Form(None),
    ExpiryDate: Optional[str] = Form(None),
    Description: Optional[str] = Form(None),
    image: Optional[UploadFile] = File(None)
):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        fields = []
        values = []

        if ProductName is not None:
            fields.append("ProductName = %s")
            values.append(ProductName)

        if Category is not None:
            fields.append("Category = %s")
            values.append(Category)

        if Brand is not None:
            fields.append("Brand = %s")
            values.append(Brand)

        if UnitPrice is not None:
            fields.append("UnitPrice = %s")
            values.append(UnitPrice)

        if QuantityInStock is not None:
            fields.append("QuantityInStock = %s")
            values.append(QuantityInStock)

        if ExpiryDate is not None:
            fields.append("ExpiryDate = %s")
            values.append(ExpiryDate)

        if Description is not None:
            fields.append("Description = %s")
            values.append(Description)

        # 🔥 Handle new image upload
        if image is not None:
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

            fields.append("image_filename = %s")
            values.append(public_id)

        if not fields:
            raise HTTPException(status_code=400, detail="No fields provided to update")

        # ✅ Perform update
        sql = f"""
            UPDATE SupermarketProducts
            SET {", ".join(fields)}
            WHERE ProductID = %s
        """
        values.append(product_id)
        cursor.execute(sql, tuple(values))
        conn.commit()

        # ✅ Fetch the full updated product
        cursor.execute("SELECT * FROM SupermarketProducts WHERE ProductID = %s", (product_id,))
        updated = cursor.fetchone()

        if not updated:
            raise HTTPException(status_code=404, detail="Product not found after update")

        # ✅ Generate signed image URL
        image_url = None
        if updated.get("image_filename"):
            image_url = generate_signed_url(updated["image_filename"])

        updated_product = {
            "ProductID": updated["ProductID"],
            "ProductName": updated["ProductName"],
            "Category": updated["Category"],
            "Brand": updated["Brand"],
            "UnitPrice": updated["UnitPrice"],
            "QuantityInStock": updated["QuantityInStock"],
            "ExpiryDate": updated["ExpiryDate"],
            "Description": updated["Description"],
            "image_url": image_url
        }

        return {
            "status": "OK",
            "message": "✅ Product updated successfully",
            "product": updated_product
        }

    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail=str(e))

    finally:
        cursor.close()
        conn.close()
# ✅ Delete Product
@app.delete("/products/{product_id}")
async def delete_product(product_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()

    # check if product exists
    cursor.execute("SELECT * FROM SupermarketProducts WHERE ProductID=%s", (product_id,))
    product = cursor.fetchone()
    if not product:
        cursor.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Product not found")

    # delete related offers first
    cursor.execute("DELETE FROM offers WHERE product_id=%s", (product_id,))

    # then delete the product itself
    cursor.execute("DELETE FROM SupermarketProducts WHERE ProductID=%s", (product_id,))
    conn.commit()
    cursor.close()
    conn.close()

    return {"status": "OK", "message": "Product and related offers deleted successfully"}






