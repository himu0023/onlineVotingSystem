from fastapi import FastAPI, HTTPException
from server.board import BulletinBoard

app = FastAPI()
board = BulletinBoard()

@app.post("/submit")
def submit_ballot(ballot:dict):
    """
    Accept encrypted ballot.

    Server performs NO cryptographic validation.
    """
    board.post_ballot(ballot)
    return {
        "status": "accepted",
        "current_merkle_root": board.get_merkle_root()
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