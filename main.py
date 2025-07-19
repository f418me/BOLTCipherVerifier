import binascii
import logging
from base64 import b64decode
import os
import uvicorn
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from Crypto.Cipher import ChaCha20
from starlette.staticfiles import StaticFiles

logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)
log = logging.getLogger(__name__)

app = FastAPI(root_path=os.getenv("FASTAPI_ROOT_PATH", ""))
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/", response_class=HTMLResponse)
async def read_form(request: Request):
    # Display the initial form
    return templates.TemplateResponse("form.html", {"request": request})


@app.post("/", response_class=HTMLResponse)
async def handle_form(request: Request,
                      preimage: str = Form(...),
                      nonce_hex: str = Form(...),
                      content_encrypted: str = Form(...)
                     ):
    try:
        # Preimage is the key for ChaCha20 (32 Bytes)
        key = binascii.unhexlify(preimage)
        if len(key) != 32:
            log.error(f"Invalid key length: {len(key)} bytes. Expected 32.")
            # Return an error message or raise an exception
            return templates.TemplateResponse("form.html", {
                "request": request,
                "error_message": "Fehler: Ungültige Preimage-Länge (muss 64 Hex-Zeichen / 32 Bytes sein)."
            })

        # Nonce (12 Bytes)
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
        log.debug(f"Decrypted content: {content_decrypted}") # Optional

        # Return the response page with the decrypted content
        return templates.TemplateResponse("response.html", {
            "request": request,
            "preimage": preimage,
            "nonce_hex": nonce_hex,
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
        log.exception("An unexpected error occurred during decryption.")
        return templates.TemplateResponse("form.html", {
            "request": request,
            "error_message": f"Ein unerwarteter Fehler ist aufgetreten: {e}"
        })


@app.get("/test-response", response_class=HTMLResponse)
async def read_form_test(request: Request):
    content_decrypted = "Test Response: Dies ist ein Test einer Antwort."
    # synthetic data
    preimage_test = "a" * 64
    nonce_test = "b" * 24
    return templates.TemplateResponse("response.html", {
        "request": request,
        "preimage": preimage_test,
        "nonce_hex": nonce_test,
        "content_decrypted": content_decrypted
    })


if __name__ == "__main__":
    app_host = os.getenv("APP_HOST", "127.0.0.1")
    app_port = int(os.getenv("APP_PORT", "8000"))

    proxy_headers_env = os.getenv("PROXY_HEADERS", "False")
    proxy_headers = proxy_headers_env.lower() in ("1", "true", "yes", "on")
    forwarded_allow_ips = os.getenv("FORWARDED_ALLOW_IPS", "127.0.0.1")

    uvicorn.run(
        app,
        host=app_host,
        port=app_port,
        proxy_headers=proxy_headers,
        forwarded_allow_ips=forwarded_allow_ips,
    )
