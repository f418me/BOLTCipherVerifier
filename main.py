
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from base64 import b64decode
from Crypto.Cipher import AES
import binascii

from starlette.staticfiles import StaticFiles

app = FastAPI()
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")


# Erstellen eines HTML-Formulars
@app.get("/", response_class=HTMLResponse)
async def read_form(request: Request):
    return templates.TemplateResponse("form.html", {"request": request})

# Empfangen und Antworten mit den übermittelten Formulardaten
@app.post("/", response_class=HTMLResponse)
async def handle_form(request: Request, preimage: str = Form(...), initialize_vector: str = Form(...), content_encrypted: str = Form(...)):
    hex_key = preimage
    key = binascii.unhexlify(hex_key)
    iv = binascii.unhexlify(initialize_vector)
    encrypted_text = b64decode(content_encrypted)

    # Entschlüssele den verschlüsselten Text im CFB-Modus
    cipher = AES.new(key, AES.MODE_CFB, iv)
    content_decrypted = cipher.decrypt(encrypted_text).decode()

    return templates.TemplateResponse("response.html", {
        "request": request, "preimage": preimage, "content_decrypted": content_decrypted
    })




# Erstellen eines HTML-Formulars
@app.get("/test-response", response_class=HTMLResponse)
async def read_form_test(request: Request):
    content_decrypted = "Test Response dies ist ein Test einer Antwort auf einen verschlüsselten Text.Test Response dies ist ein Test einer Antwort auf einen verschlüsselten TextTest Response dies ist ein Test einer Antwort auf einen verschlüsselten TextTest Response dies ist ein Test einer Antwort auf einen verschlüsselten TextTest Response dies ist ein Test einer Antwort auf einen verschlüsselten TextTest Response dies ist ein Test einer Antwort auf einen verschlüsselten Text"
    return templates.TemplateResponse("response.html", {
        "request": request, "content_decrypted": content_decrypted
    })



if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
