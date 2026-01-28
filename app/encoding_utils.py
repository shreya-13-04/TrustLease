import base64

def encode_token(data: str) -> str:
    return base64.urlsafe_b64encode(data.encode()).decode()

def decode_token(token: str) -> str:
    return base64.urlsafe_b64decode(token.encode()).decode()
