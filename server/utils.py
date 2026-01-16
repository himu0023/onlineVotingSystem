import json

def canonical_json(obj: dict)-> bytes:
    """
    Deterministic serialization for cryptographic hashing.
    """

    return json.dumps(
        obj, 
        sort_keys=True,
        separators=(",",":")
    ).encode()