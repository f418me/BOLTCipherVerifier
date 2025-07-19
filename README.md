# ChaCha20 Decryption Web UI

This project provides a simple web interface built with FastAPI to decrypt messages encrypted with the ChaCha20 stream cipher. Users can input the encryption key (Bitcoin Lightning hex preimage), the nonce (hex), and the Base64 encoded ciphertext to receive the decrypted plaintext.

## Overview

The application utilizes the `pycryptodome` library for the underlying ChaCha20 decryption process. It expects:

1.  **Preimage (Key Hex):** A 32-byte (64 hexadecimal characters) encryption key.
2.  **Nonce (Hex):** A 12-byte (24 hexadecimal characters) nonce, unique for each message encrypted with the same key.
3.  **Encrypted Message (Base64):** The ciphertext encoded in Base64 format.

Upon submission, the application attempts decryption and displays either the resulting plaintext (assuming UTF-8 encoding) or a specific error message if any step fails (e.g., invalid input format, incorrect key/nonce length, decoding errors).


## Prerequisites

*   Python 3.11+
*   `pip` (Python package installer)
*   `git` (for cloning the repository, optional)

## Installation

1.  **Clone the repository (optional):**
    ```bash
    git clone <your-repository-url>
    cd <repository-directory>
    ```

2.  **Create and activate a virtual environment (recommended):**
    ```bash
    python -m venv venv
    # On Windows
    .\venv\Scripts\activate
    # On macOS/Linux
    source venv/bin/activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Running the Application

You can run the application using the Uvicorn ASGI server.

```bash
uvicorn main:app --reload
```

## Docker/Podman

Alternatively you can run the application inside a container. A `Dockerfile` is
provided and works with both Docker and Podman.

### Build the image

```bash
docker build -t boltcipherverifier .
# or using podman
podman build -t boltcipherverifier .
```

### Run the container

```bash
docker run --rm -p 8000:8000 boltcipherverifier
# or using podman
podman run --rm -p 8000:8000 boltcipherverifier
```

The application will be available at `http://localhost:8000`.
