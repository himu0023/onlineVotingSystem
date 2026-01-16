from fastapi import FastAPI, HTTPException
from server.board import BulletinBoard
from server.auth import TokenAuthority, hash_token
from server.token_store import TokenRegistry
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey



app = FastAPI()
board = BulletinBoard()

auth = TokenAuthority()
token_registry = TokenRegistry()

PUBLIC_KEY_BYTES = bytes.fromhex(auth.export_public_key())
PUBLIC_KEY = Ed25519PublicKey.from_public_bytes(PUBLIC_KEY_BYTES)

@app.post("/submit")
def submit_ballot(payload:dict):
    """
    Payload must contain:
    - ballot 
    - token 
    - signature
    """
    ballot = payload['ballot']
    token_hex = payload['token']
    signature_hex = payload['signature']

    token_bytes = bytes.fromhex(token_hex)
    signature_bytes = bytes.fromhex(signature_hex)

    # 1. Verify authority sigature 
    try:
        PUBLIC_KEY.verify(signature_bytes, token_bytes)
    except Exception:
        return {"error": "Invalid token signature"}
    
    # 2. Compute token hash
    token_hash = hash_token(token_hex)

    # 3. Check double voting 
    if token_registry.is_used(token_hash):
        return {"error":"Token already used"}
    
    # 4. Accept ballot
    token_registry.mark_used(token_hash)

    ballot["token_hash"] = token_hash
    board.post_ballot(ballot)

    return{
        "status":"accepted",
        "merkle_root":board.get_merkle_root()
    }


@app.get("/proof/{index}")
def fetch_inclusion_proof(index:int):
    """
    Return Merkle inclusion proof for a ballot.
    """

    try: 
        return board.get_inclusion_proof(index)
    except IndexError:
        raise HTTPException(status_code=404, detail="Ballot not found")
    
@app.get("/issue-token")
def issue_token():
    """
    Simulates voter registration authority.
    """
    token, signature = auth.issue_token()

    return{
        "token": token,
        "signature": signature
    }