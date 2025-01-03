import streamlit as st
from streamlit_option_menu import option_menu
import mysql.connector
import time  # Untuk mengatur delay

import re
import streamlit as st
import hashlib
import mysql.connector
import fitz  # PyMuPDF
from PIL import Image
from pytesseract import image_to_string, image_to_osd
import tempfile
import os
from pyzbar.pyzbar import decode
import qrcode
from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
from Crypto.Util.number import bytes_to_long, GCD

import random
import math
import qrcode
from io import BytesIO
import json

import cv2
import numpy as np

# Fungsi untuk menghubungkan ke database
def connect_to_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="skripsi"
    )

# Menggunakan koneksi
conn = connect_to_db()
cursor = conn.cursor()

# Fungsi untuk memeriksa kredensial pengguna di database
def check_credentials(username, password):
    conn = connect_to_db()
    cursor = conn.cursor()
    try:
        query = "SELECT * FROM users WHERE username = %s AND password = %s"
        cursor.execute(query, (username, password))
        result = cursor.fetchone()
        return result is not None
    finally:
        cursor.fetchall()  # Membersihkan hasil yang belum dibaca
        cursor.close()
        conn.close()

# Streamlit session states
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if 'page' not in st.session_state:
    st.session_state['page'] = "Login" # Default ke halaman login

# Navbar
selected = option_menu(
    menu_title=None,  # No title for navbar
    options=["Verification" if not st.session_state.logged_in else "Signing", "Login" if not st.session_state.logged_in else "Logout"],
    icons=["check2-circle" if not st.session_state.logged_in else "file-earmark-plus", "person"],
    menu_icon="menu-app",  # Icon for menu
    default_index=0,
    orientation="horizontal",
)

# 2. Hash file with MD5
def calculate_md5(file_path):
    """
    Menghitung hash MD5 dari file.
    """
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):  # Membaca file dalam blok
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def detect_and_correct_orientation(img):
    """
    Deteksi orientasi teks pada gambar dan perbaiki jika perlu.
    """
    osd_data = image_to_osd(img)  # Optical Script Detection dari Tesseract
    rotation_angle = int(osd_data.split("Rotate:")[1].split("\n")[0])  # Ambil nilai rotasi
    st.info(f"Rotasi terdeteksi: {rotation_angle}°")
    
    # Putar gambar ke orientasi yang benar
    if rotation_angle != 0:
        img = img.rotate(-rotation_angle, expand=True)  # Rotasi ke arah yang benar
    return img

def extract_text_from_scanned_pdf(pdf_path):
    """
    Ekstraksi teks dari file PDF hasil scan menggunakan PyMuPDF untuk mengambil gambar,
    mendeteksi orientasi, dan melakukan OCR.
    """
    extracted_text = ""
    pdf_document = fitz.open(pdf_path)

    for page_number in range(len(pdf_document)):
        # Render halaman menjadi gambar
        page = pdf_document[page_number]
        pix = page.get_pixmap(dpi=300)
        img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)

        # Deteksi dan koreksi orientasi
        img_corrected = detect_and_correct_orientation(img)

        # OCR untuk gambar dengan orientasi yang sudah benar
        page_text = image_to_string(img_corrected, lang="eng")  # Bisa ganti 'eng' dengan 'ind'
        extracted_text += f"\n=== Halaman {page_number + 1} ===\n" + page_text

    pdf_document.close()
    return extracted_text

def extract_specific_data(text):
    """
    Ekstraksi data spesifik seperti Nomor Seri Ijazah, Nama, NIM, Gelar, dan NIK.
    """
    data = {
        "Nomor Seri Ijazah": None,
        "Nama": None,
        "NIM": None,
        "Gelar": None,
        "NIK": None
    }

    # Pisahkan teks menjadi baris
    lines = text.split("\n")

    # Cari nomor seri ijazah (angka pertama di teks)
    nomor_ijazah_pattern = r"(Nomor|Nomer)[\s\w]*[:|;\s]+(\d+)"
    nomor_ijazah_match = re.search(nomor_ijazah_pattern, text, re.IGNORECASE)
    if nomor_ijazah_match:
        data["Nomor Seri Ijazah"] = nomor_ijazah_match.group(2)
    else:
        # Jika tidak ada kata kunci, cari angka berderet pertama
        angka_pertama_match = re.search(r"\d+", text)
        if angka_pertama_match:
            data["Nomor Seri Ijazah"] = angka_pertama_match.group(0)

    # Cari NIM dan nama
    for i, line in enumerate(lines):
        nim_pattern = r"(NIM[:\s]+([\w\d]+))"
        nim_match = re.search(nim_pattern, line, re.IGNORECASE)
        if nim_match:
            data["NIM"] = nim_match.group(2)

            # Cek nama di baris sebelum NIM, ulangi jika baris kosong
            for j in range(i - 1, -1, -1):
                if lines[j].strip():  # Jika baris tidak kosong
                    data["Nama"] = lines[j].strip()
                    break
            break

    # Cari gelar (tepat setelah kata "Gelar")
    gelar_pattern = r"Gelar[:\s]+([\w\.\,\-\s]+)"
    gelar_match = re.search(gelar_pattern, text, re.IGNORECASE)
    if gelar_match:
        data["Gelar"] = gelar_match.group(1).strip()

    # Cari NIK (16 digit angka)
    nik_pattern = r"\b(\d{16})\b"
    nik_match = re.search(nik_pattern, text)
    if nik_match:
        data["NIK"] = nik_match.group(1)

    return data

# 3. ElGamal signing
def mod_exp(base, exp, mod):
    """Perhitungan modular exponentiation."""
    result = 1
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp //= 2
    return result

def generate_keys(passphrase):
    """Membentuk kunci ElGamal dari passphrase."""
    p = 7919  # Bilangan prima besar untuk modulus
    g = 2     # Generator

    # Hash passphrase menjadi kunci privat
    hashed = int(hashlib.sha256(passphrase.encode()).hexdigest(), 16)
    x = hashed % (p - 1)  # Kunci privat
    y = mod_exp(g, x, p)  # Kunci publik

    return {"p": p, "g": g, "x": x, "y": y}

def sign_message(message, private_key, p, g):
    """Proses penandatanganan menggunakan kunci privat."""
    m = int(hashlib.sha256(message.encode()).hexdigest(), 16) % p
    k = random.randint(1, p - 2)  # Kunci sementara
    while math.gcd(k, p - 1) != 1:  # k harus coprime dengan p-1
        k = random.randint(1, p - 2)
    r = mod_exp(g, k, p)
    s = ((m - private_key * r) * pow(k, -1, p - 1)) % (p - 1)

    return {"r": r, "s": s}

def verify_signature(message, signature, public_key, p, g):
    """Proses verifikasi tanda tangan."""
    m = int(hashlib.sha256(message.encode()).hexdigest(), 16) % p
    r, s = signature["r"], signature["s"]

    if r <= 0 or r >= p:  # Validasi nilai r
        return False

    left = mod_exp(public_key, r, p) * mod_exp(r, s, p) % p
    right = mod_exp(g, m, p)

    return left == right

# Tambahkan fungsi untuk menyisipkan QR Code ke dalam PDF
def insert_qr_into_pdf(pdf_path, qr_image, output_path):
    """
    Menyisipkan gambar QR Code ke dalam file PDF pada halaman pertama.
    
    Parameters:
    - pdf_path: Path ke file PDF asli.
    - qr_image: Objek gambar QR Code (Pillow Image).
    - output_path: Path untuk menyimpan file PDF yang dimodifikasi.
    """
    pdf_document = fitz.open(pdf_path)
    page = pdf_document[0]  # Ambil halaman pertama

    # Konversi gambar QR ke format bytes
    qr_bytes = BytesIO()
    qr_image.save(qr_bytes, format="PNG")
    qr_bytes.seek(0)

    # Masukkan QR Code sebagai gambar
    rect = fitz.Rect(320, 450, 410, 540)  # Koordinat tempat QR Code akan disisipkan
    page.insert_image(rect, stream=qr_bytes.read(), keep_proportion=True)

    # Simpan PDF baru
    pdf_document.save(output_path)
    pdf_document.close()

def preprocess_image(image_path):
    """
    Melakukan preprocessing pada gambar untuk meningkatkan deteksi QR Code.
    """
    # Membuka gambar menggunakan OpenCV
    img = cv2.imread(image_path)

    # Ubah ke grayscale
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

    # Perbaiki kontras menggunakan adaptive histogram equalization
    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
    enhanced_img = clahe.apply(gray)

    # Lakukan thresholding untuk meningkatkan perbedaan warna
    _, thresh = cv2.threshold(enhanced_img, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)

    return thresh

# Page Routing
if selected == "Login":
    st.title("Login Page")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if check_credentials(username, password):
            st.success("Login berhasil!")
            time.sleep(1)  # Perpanjang durasi tampilan pesan (1 detik)
            st.session_state.logged_in = True
            st.rerun()
        else:
            st.error("Username atau Password salah")
elif selected == "Logout":
    st.session_state.logged_in = False
    st.success("Anda telah logout.")
    time.sleep(1)  # Perpanjang durasi tampilan pesan (1 detik)
    st.rerun()  # Langsung kembali ke halaman login
elif selected == "Verification":
    st.header("Verification via Camera or Photo")
    uploaded_file = st.file_uploader("Upload Photo or Capture QR Code:", type=["png", "jpg", "jpeg", "pdf"])

    if uploaded_file:
        if uploaded_file.type == "application/pdf":
            # Proses file PDF
            pdf_document = fitz.open(stream=uploaded_file.read(), filetype="pdf")
            qr_data = None

            for page_number in range(len(pdf_document)):
                page = pdf_document[page_number]
                pix = page.get_pixmap(dpi=300)
                img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)

                # Mencoba mendekode QR Code dari gambar halaman
                decoded_qr = decode(img)
                if decoded_qr:
                    qr_data = decoded_qr[0].data.decode("utf-8")
                    break  # Berhenti jika QR Code ditemukan

            pdf_document.close()
        else:
            # Simpan gambar sementara
            with tempfile.NamedTemporaryFile(delete=False, suffix=".jpg") as temp_img:
                temp_img.write(uploaded_file.read())
                temp_img_path = temp_img.name

            # Preprocess image for better QR detection
            preprocessed_image = preprocess_image(temp_img_path)
            cv2.imwrite("preprocessed_image.jpg", preprocessed_image)  # Debugging (opsional)

            # Deteksi QR Code setelah preprocessing
            decoded_qr = decode(Image.open("preprocessed_image.jpg"))
            qr_data = decoded_qr[0].data.decode("utf-8")

        if qr_data:
            try:
                # Parsing data dari QR Code
                data = json.loads(qr_data)

                signature = data["signature"]
                public_key = data["public_key"]

                # Ambil semua hash dari database
                cursor.execute("SELECT * FROM data_mahasiswa")
                all_data = cursor.fetchall()

                # Variabel untuk menyimpan hasil validasi
                is_valid = False
                verified_data = None

                # Bandingkan hash satu per satu dari database
                for row in all_data:
                    db_hash = row[5]  # Kolom hash
                    # Verifikasi tanda tangan dengan hash dari database
                    is_valid = verify_signature(
                        db_hash,
                        signature,
                        public_key["y"],
                        public_key["p"],
                        public_key["g"]
                    )
                    if is_valid:
                        verified_data = row
                        break  # Keluar dari loop jika valid

                if is_valid and verified_data:
                    st.success("Signature is valid!")
                    st.write("### Verified Document Data")
                    st.write(f"**Nama**: {verified_data[1]}")
                    st.write(f"**NIK**: {verified_data[3]}")
                    st.write(f"**Gelar**: {verified_data[4]}")
                else:
                    st.error("Signature is invalid or no matching hash found in the database.")

            except json.JSONDecodeError:
                st.error("Invalid QR Code data!")
        else:
            st.error("No QR Code detected!")

elif selected == "Signing":
    st.header("Signing Documen Ijazah")
    # Page 1: Upload and Process PDF
    uploaded_file = st.file_uploader("Unggah file PDF ijazah hasil scan atau ijazah akan cetak", type="pdf")

    if uploaded_file:
        # Simpan file sementara
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as temp_pdf:
            temp_pdf.write(uploaded_file.read())
            temp_pdf_path = temp_pdf.name

        # Hitung hash MD5 dari file
        file_hash = calculate_md5(temp_pdf_path)

        st.success("File berhasil diunggah. Memulai proses OCR...")

        # Ekstraksi teks dari PDF hasil scan
        extracted_text = extract_text_from_scanned_pdf(temp_pdf_path)

        # Ekstrak data spesifik dari teks
        extracted_data = extract_specific_data(extracted_text)

        # Tampilkan data spesifik
        st.subheader("Data Spesifik yang Diekstraksi")
        for key, value in extracted_data.items():
            st.write(f"**{key}**: {value if value else 'Tidak ditemukan'}")

        # Hash the file
        st.write(f"File Hash (MD5): {file_hash}")
        
        # Generate ElGamal keys and sign
        passphrase = st.text_input("Masukkan passphrase untuk Generate Kunci ElGamal")
        if st.button("Generate dan Tanda Tangani"):
            keys = generate_keys(passphrase)
            st.write("### Generated Keys")
            st.json({"Public Key": {"p": keys["p"], "g": keys["g"], "y": keys["y"]}})

            message = file_hash
            if message:
                signature = sign_message(message, keys["x"], keys["p"], keys["g"])
                st.write("### Digital Signature")
                st.json(signature)

                # Membuat QR Code
                data = {
                    "signature": signature,
                    "public_key": {"p": keys["p"], "g": keys["g"], "y": keys["y"]}
                }
                qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_H)
                qr.add_data(json.dumps(data))
                qr.make(fit=True)

                qr_img = qr.make_image(fill_color="black", back_color="white").convert("RGBA")
                buf = BytesIO()
                qr_img.save(buf, format="PNG")
                buf.seek(0)
                
                # Inputan ke dalam database dengan validasi
                no_ijazah = extracted_data['Nomor Seri Ijazah']
                nama = extracted_data['Nama']
                nim = extracted_data['NIM']
                gelar = extracted_data['Gelar']
                nik = extracted_data['NIK']

                if no_ijazah:
                    # Cek apakah nomor ijazah sudah ada di database
                    cursor.execute("SELECT COUNT(*) FROM data_mahasiswa WHERE no_ijazah = %s", (no_ijazah,))
                    result = cursor.fetchone()[0]

                    if result > 0:
                        st.warning("Data dengan Nomor Seri Ijazah ini sudah ada di database.")

                        # Mengubah latar belakang putih menjadi transparan
                        qr_pixels = qr_img.load()
                        for y in range(qr_img.size[1]):
                            for x in range(qr_img.size[0]):
                                if qr_pixels[x, y] == (255, 255, 255, 255):  # Jika putih
                                    qr_pixels[x, y] = (255, 255, 255, 0)  # Ubah menjadi transparan

                        # QR Code sekarang memiliki latar belakang transparan

                        # Menyisipkan QR Code ke PDF
                        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as temp_output_pdf:
                            output_pdf_path = temp_output_pdf.name

                        insert_qr_into_pdf(temp_pdf_path, qr_img, output_pdf_path)

                        st.success("QR Code berhasil disisipkan ke dalam PDF.")

                        # Tampilkan dan unduh PDF hasil
                        with open(output_pdf_path, "rb") as pdf_file:
                            st.download_button(
                                "Download PDF dengan QR Code",
                                pdf_file,
                                file_name= f"signed_document_{no_ijazah}.pdf",
                                mime="application/pdf"
                            )
                    else:
                        # Jika belum ada, lakukan insert
                        st.image(buf, caption="QR Code for Digital Signature")
                        st.download_button("Download QR Code", buf, file_name= f"signature_qr_{no_ijazah}.png", mime="image/png")
                
                        cursor.execute(
                            "INSERT INTO data_mahasiswa (no_ijazah, nama, nim, gelar, nik, hash) VALUES (%s, %s, %s, %s, %s, %s)",
                            (no_ijazah, nama, nim, gelar, nik, file_hash)
                        )
                        conn.commit()
                        st.success("Data berhasil ditambahkan ke database!")
                else:
                    st.error("Nomor Seri Ijazah tidak ditemukan dalam dokumen.")

        # Hapus file sementara setelah selesai
        if os.path.exists(temp_pdf_path):
            os.unlink(temp_pdf_path)
    
# Halaman tidak ditemukan
else:
    st.warning("Halaman tidak ditemukan!")
