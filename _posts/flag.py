import hashlib
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE = bytes.fromhex("6372696d65776174636821")
CIPHERTEXT = bytes.fromhex("cdbfdb28bb51036b488c7f0565868b404116aa941538b3b6b27c7133799192ce239c630ec9e267a8671a9f7578")
TAG = bytes.fromhex("51dfb4e13c0206af0cc875e9b04ecb0e")

HELP = '''Crimewatch

Answer the case questions, then pass the answers to this script.

1. Which TeleChat account or chat appears to be supplying the courier with vape stock?
2. What car plate number connected to the supplier's import method is recoverable from deleted image/cache evidence?
3. Which TeleChat contact appears to be the most recent buyer awaiting a delivery?
4. What coordinates identify the pickup point?

Answer format:
- TeleChat handles include the leading @
- Plate numbers are uppercase with no spaces
- Buyer must be lowercase plain text
- Coordinates use decimal latitude,longitude rounded to 2 decimal places

usage: flag.py <supplier> <plate> <buyer> <coordinates>
'''

def normalise(values):
    supplier, plate, buyer, coordinates = [v.strip() for v in values]
    if buyer != buyer.lower():
        raise ValueError("buyer must be lowercase")
    return [
        supplier.lower(),
        plate.replace(" ", "").upper(),
        buyer,
        coordinates.replace(" ", ""),
    ]

if len(sys.argv) != 5:
    print(HELP)
    sys.exit(1)

try:
    candidate = "|".join(normalise(sys.argv[1:]))
except ValueError:
    print("[-] Wrong case reconstruction")
    sys.exit(1)

key = hashlib.sha256(candidate.encode()).digest()
try:
    plaintext = AESGCM(key).decrypt(NONCE, CIPHERTEXT + TAG, None)
except Exception:
    print("[-] Wrong case reconstruction")
    sys.exit(1)

print("[+] " + plaintext.decode())