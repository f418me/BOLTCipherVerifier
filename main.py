# --- START OF FILE main.py (Decryption Application) ---

import binascii
import logging
from base64 import b64decode
import os
import uvicorn
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
# Import ChaCha20 instead of AES
from Crypto.Cipher import ChaCha20
from starlette.staticfiles import StaticFiles

# Basic Logging setup
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)
log = logging.getLogger(__name__)

app = FastAPI()
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/", response_class=HTMLResponse)
async def read_form(request: Request):
    # Display the initial form
    return templates.TemplateResponse("form.html", {"request": request})


# Empfangen und Antworten mit den übermittelten Formulardaten
@app.post("/", response_class=HTMLResponse)
async def handle_form(request: Request,
                      preimage: str = Form(...),        # Key (hex)
                      nonce_hex: str = Form(...),       # Nonce (hex) - NEU
                      content_encrypted: str = Form(...) # Encrypted Content (Base64)
                     ):
    try:
        # Preimage ist der Key für ChaCha20 (muss 32 Bytes sein)
        key = binascii.unhexlify(preimage)
        if len(key) != 32:
            log.error(f"Invalid key length: {len(key)} bytes. Expected 32.")
            # Return an error message or raise an exception
            return templates.TemplateResponse("form.html", {
                "request": request,
                "error_message": "Fehler: Ungültige Preimage-Länge (muss 64 Hex-Zeichen / 32 Bytes sein)."
            })

        # Nonce (muss 12 Bytes sein, basierend auf dem Encryption-Skript)
        nonce = binascii.unhexlify(nonce_hex)
        if len(nonce) != 12:
            log.error(f"Invalid nonce length: {len(nonce)} bytes. Expected 12.")
            # Return an error message or raise an exception
            return templates.TemplateResponse("form.html", {
                "request": request,
                "error_message": "Fehler: Ungültige Nonce-Länge (muss 24 Hex-Zeichen / 12 Bytes sein)."
            })

        # Encrypted content is Base64 encoded
        encrypted_data = b64decode(content_encrypted)

        log.info(f"Received Key (Hex): {preimage}")
        log.info(f"Received Nonce (Hex): {nonce_hex}")
        # log.debug(f"Received Encrypted Data (Bytes): {encrypted_data}") # Optional: nur bei Bedarf loggen

        # Initialize ChaCha20 cipher
        cipher = ChaCha20.new(key=key, nonce=nonce)

        # Decrypt the content
        content_decrypted_bytes = cipher.decrypt(encrypted_data)

        # Decode from bytes to string (assuming UTF-8)
        content_decrypted = content_decrypted_bytes.decode('utf-8')

        log.info("Decryption successful.")
        # log.debug(f"Decrypted content: {content_decrypted}") # Optional

        # Return the response page with the decrypted content
        return templates.TemplateResponse("response.html", { # Verwende response.html für die Antwort
            "request": request,
            "preimage": preimage, # Optional: Zum Anzeigen
            "nonce_hex": nonce_hex,   # Optional: Zum Anzeigen
            "content_decrypted": content_decrypted
        })

    except binascii.Error as e:
        log.error(f"Hex decoding error: {e}")
        return templates.TemplateResponse("form.html", {
            "request": request,
            "error_message": f"Fehler beim Dekodieren von Hex-Werten: {e}"
        })
    except ValueError as e:
         log.error(f"Base64 decoding error: {e}")
         return templates.TemplateResponse("form.html", {
             "request": request,
             "error_message": f"Fehler beim Dekodieren von Base64: {e}"
         })
    except UnicodeDecodeError as e:
        log.error(f"UTF-8 decoding error after decryption: {e}")
        return templates.TemplateResponse("form.html", {
            "request": request,
            "error_message": "Fehler: Entschlüsselte Daten konnten nicht als UTF-8 Text dekodiert werden."
        })
    except Exception as e:
        log.exception("An unexpected error occurred during decryption.") # Loggt den Stack Trace
        return templates.TemplateResponse("form.html", {
            "request": request,
            "error_message": f"Ein unerwarteter Fehler ist aufgetreten: {e}"
        })


# Route für Testzwecke bleibt bestehen (optional)
@app.get("/test-response", response_class=HTMLResponse)
async def read_form_test(request: Request):
    content_decrypted = "Test Response: Dies ist ein Test einer Antwort."
    # Simuliere Werte für die Anzeige in response.html
    preimage_test = "a" * 64 # Beispiel Preimage
    nonce_test = "b" * 24    # Beispiel Nonce
    return templates.TemplateResponse("response.html", {
        "request": request,
        "preimage": preimage_test,
        "nonce_hex": nonce_test,
        "content_decrypted": content_decrypted
    })


if __name__ == "__main__":
    app_host = os.getenv("APP_HOST", "127.0.0.1")
    app_port = int(os.getenv("APP_PORT", "8000"))

    uvicorn.run(app, host=app_host, port=app_port)