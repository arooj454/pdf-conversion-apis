import os
import io
import shutil
import uuid
import subprocess
from concurrent.futures import ThreadPoolExecutor
from typing import Tuple

from fastapi import FastAPI, UploadFile, File, Form, BackgroundTasks, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

import pyzipper               # for password-protected zip fallback
from PyPDF2 import PdfReader, PdfWriter
import msoffcrypto            # for decrypting office files (if internally encrypted)

# ---------------------------
# Configuration (change via env)
# ---------------------------
UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "/tmp/uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
MAX_FILE_SIZE = int(os.environ.get("MAX_FILE_SIZE_BYTES", 30 * 1024 * 1024))  # 30 MB default
ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "")  # comma-separated, e.g. https://example.com

# Thread pool for blocking tasks
executor = ThreadPoolExecutor(max_workers=4)

# FastAPI init
app = FastAPI(title="Cross-platform File Locker & Converter")

# CORS config
if ALLOWED_ORIGINS:
    origins = [o.strip() for o in ALLOWED_ORIGINS.split(",") if o.strip()]
else:
    origins = []
# Do not allow "*" in production; if empty, no CORS allowed
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins or [],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------
# Helpers
# ---------------------------
def safe_filename(name: str) -> str:
    # keep simple unique filename
    return f"{uuid.uuid4().hex}_{os.path.basename(name)}"

def write_temp_file(upload: UploadFile) -> str:
    contents = upload.file.read()
    if len(contents) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="File too large")
    temp_name = safe_filename(upload.filename)
    path = os.path.join(UPLOAD_FOLDER, temp_name)
    with open(path, "wb") as f:
        f.write(contents)
    return path

def cleanup(path: str):
    try:
        if os.path.isdir(path):
            shutil.rmtree(path)
        elif os.path.exists(path):
            os.remove(path)
    except Exception:
        pass

def run_soffice_convert(input_path: str, out_dir: str) -> Tuple[bool, str]:
    """
    Run LibreOffice headless conversion.
    Returns (success, output_path_or_error_message)
    """
    try:
        # --headless and --convert-to auto-detect output, output placed in out_dir
        proc = subprocess.run(
            ["soffice", "--headless", "--convert-to", "docx:writer8" , "--outdir", out_dir, input_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, text=True
        )
        # We try to locate the converted file: same basename but with .docx
        base = os.path.splitext(os.path.basename(input_path))[0]
        candidate = os.path.join(out_dir, base + ".docx")
        if os.path.exists(candidate):
            return True, candidate
        else:
            # return stdout/stderr for debugging
            msg = f"soffice exit={proc.returncode}, stdout={proc.stdout}, stderr={proc.stderr}"
            return False, msg
    except FileNotFoundError:
        return False, "soffice (LibreOffice) not installed or not on PATH"
    except Exception as e:
        return False, str(e)

def run_soffice_convert_to_pdf(input_path: str, out_dir: str) -> Tuple[bool, str]:
    try:
        proc = subprocess.run(
            ["soffice", "--headless", "--convert-to", "pdf", "--outdir", out_dir, input_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, text=True
        )
        base = os.path.splitext(os.path.basename(input_path))[0]
        candidate = os.path.join(out_dir, base + ".pdf")
        if os.path.exists(candidate):
            return True, candidate
        else:
            msg = f"soffice exit={proc.returncode}, stdout={proc.stdout}, stderr={proc.stderr}"
            return False, msg
    except FileNotFoundError:
        return False, "soffice (LibreOffice) not installed or not on PATH"
    except Exception as e:
        return False, str(e)

# ---------------------------
# PDF lock/unlock (PyPDF2)
# ---------------------------
def lock_pdf_bytes(file_bytes: bytes, password: str) -> bytes:
    reader = PdfReader(io.BytesIO(file_bytes))
    writer = PdfWriter()
    for p in reader.pages:
        writer.add_page(p)
    writer.encrypt(user_password=password, owner_password=None, use_128bit=True)
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()

def unlock_pdf_bytes(file_bytes: bytes, password: str) -> bytes:
    reader = PdfReader(io.BytesIO(file_bytes))
    try:
        reader.decrypt(password)
    except Exception as e:
        raise HTTPException(status_code=400, detail="Wrong PDF password or decryption failed")
    writer = PdfWriter()
    for p in reader.pages:
        writer.add_page(p)
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()

# ---------------------------
# Office decrypt (msoffcrypto)
# ---------------------------
def try_decrypt_office_file(input_path: str, password: str, out_path: str) -> bool:
    """
    Attempt to decrypt an internally-encrypted Office file using msoffcrypto.
    Returns True on success (writes out_path), False if not encrypted or failed.
    """
    try:
        with open(input_path, "rb") as f:
            office = msoffcrypto.OfficeFile(f)
            if not office.is_encrypted():
                return False
            office.load_key(password=password)
            with open(out_path, "wb") as out_f:
                office.decrypt(out_f)
            return True
    except msoffcrypto.exceptions.InvalidKeyError:
        raise HTTPException(status_code=400, detail="Wrong Office password")
    except Exception:
        # If something else fails, return False (caller can handle)
        return False

# ---------------------------
# ZIP protect as fallback for Office lock
# ---------------------------
def make_password_zip(file_path: str, password: str) -> str:
    locked_zip = file_path + "_locked.zip"
    with pyzipper.AESZipFile(locked_zip, 'w', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(password.encode())
        # set strong encryption
        zf.writestr(os.path.basename(file_path), open(file_path, "rb").read())
    return locked_zip

def extract_password_zip(zip_path: str, password: str, out_dir: str) -> str:
    with pyzipper.AESZipFile(zip_path, 'r') as zf:
        try:
            zf.setpassword(password.encode())
            names = zf.namelist()
            if not names:
                raise HTTPException(status_code=400, detail="Empty zip")
            # extract first entry
            member = names[0]
            out_path = os.path.join(out_dir, member)
            with open(out_path, "wb") as f:
                f.write(zf.read(member))
            return out_path
        except RuntimeError:
            raise HTTPException(status_code=400, detail="Wrong zip password")

# ---------------------------
# Routes
# ---------------------------

@app.get("/")
def root():
    return {"message": "Cross-platform File Locker & Converter (LibreOffice + ZIP fallback)"}

# ---------------------------
# LOCK endpoint
# ---------------------------
@app.post("/lock")
async def lock_file(background_tasks: BackgroundTasks, file: UploadFile = File(...), password: str = Form(...)):
    # Save temp
    tmp_in = write_temp_file(file)
    name_lower = file.filename.lower()

    try:
        # PDF: do true internal PDF encryption
        if name_lower.endswith(".pdf"):
            raw = open(tmp_in, "rb").read()
            out_bytes = await executor.submit(lock_pdf_bytes, raw, password)
            out_path = os.path.join(UPLOAD_FOLDER, f"{os.path.splitext(file.filename)[0]}_locked.pdf")
            with open(out_path, "wb") as f:
                f.write(out_bytes)
            # cleanup after response
            background_tasks.add_task(cleanup, out_path)
            return FileResponse(out_path, filename=os.path.basename(out_path), media_type="application/pdf")

        # Office files: create password-protected ZIP fallback (cross-platform)
        elif name_lower.endswith((".docx", ".xlsx", ".pptx")):
            # We could try UNO to set internal password in future.
            out_zip = await executor.submit(make_password_zip, tmp_in, password)
            background_tasks.add_task(cleanup, out_zip)
            return FileResponse(out_zip, filename=os.path.basename(out_zip), media_type="application/zip")

        else:
            raise HTTPException(status_code=400, detail="Unsupported file type for lock")

    finally:
        background_tasks.add_task(cleanup, tmp_in)

# ---------------------------
# UNLOCK endpoint
# ---------------------------
@app.post("/unlock")
async def unlock_file(background_tasks: BackgroundTasks, file: UploadFile = File(...), password: str = Form(...)):
    tmp_in = write_temp_file(file)
    name_lower = file.filename.lower()

    try:
        # PDF: remove encryption
        if name_lower.endswith(".pdf"):
            raw = open(tmp_in, "rb").read()
            out_bytes = await executor.submit(unlock_pdf_bytes, raw, password)
            out_path = os.path.join(UPLOAD_FOLDER, f"{os.path.splitext(file.filename)[0]}_unlocked.pdf")
            with open(out_path, "wb") as f:
                f.write(out_bytes)
            background_tasks.add_task(cleanup, out_path)
            return FileResponse(out_path, filename=os.path.basename(out_path), media_type="application/pdf")

        # Office files:
        elif name_lower.endswith((".docx", ".xlsx", ".pptx")):
            # First, try if the file is an internally-encrypted Office file (msoffcrypto)
            candidate_out = os.path.join(UPLOAD_FOLDER, f"{os.path.splitext(file.filename)[0]}_decrypted{os.path.splitext(file.filename)[1]}")
            tried = await executor.submit(try_decrypt_office_file, tmp_in, password, candidate_out)
            if tried:
                background_tasks.add_task(cleanup, candidate_out)
                return FileResponse(candidate_out, filename=os.path.basename(candidate_out))
            # Else, try if the uploaded file is a password-protected zip (our fallback)
            if tmp_in.lower().endswith("_locked.zip") or tmp_in.lower().endswith(".zip"):
                try:
                    extracted = await executor.submit(extract_password_zip, tmp_in, password, UPLOAD_FOLDER)
                    background_tasks.add_task(cleanup, extracted)
                    return FileResponse(extracted, filename=os.path.basename(extracted))
                except HTTPException as e:
                    raise e
            # Not encrypted or unsupported
            raise HTTPException(status_code=400, detail="File is not an internally-encrypted Office file or password-protected zip, or password wrong")

        else:
            raise HTTPException(status_code=400, detail="Unsupported file type for unlock")

    finally:
        background_tasks.add_task(cleanup, tmp_in)

# ---------------------------
# PDF -> Word (LibreOffice)
# ---------------------------
@app.post("/pdf-to-word")
async def pdf_to_word(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    tmp_in = write_temp_file(file)
    out_dir = UPLOAD_FOLDER
    try:
        success, result = await executor.submit(run_soffice_convert, tmp_in, out_dir)
        if not success:
            raise HTTPException(status_code=500, detail=f"Conversion failed: {result}")
        background_tasks.add_task(cleanup, tmp_in)
        background_tasks.add_task(cleanup, result)
        return FileResponse(result, filename=os.path.basename(result))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ---------------------------
# Word -> PDF (LibreOffice)
# ---------------------------
@app.post("/word-to-pdf")
async def word_to_pdf(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    tmp_in = write_temp_file(file)
    out_dir = UPLOAD_FOLDER
    try:
        success, result = await executor.submit(run_soffice_convert_to_pdf, tmp_in, out_dir)
        if not success:
            raise HTTPException(status_code=500, detail=f"Conversion failed: {result}")
        background_tasks.add_task(cleanup, tmp_in)
        background_tasks.add_task(cleanup, result)
        return FileResponse(result, filename=os.path.basename(result), media_type="application/pdf")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
