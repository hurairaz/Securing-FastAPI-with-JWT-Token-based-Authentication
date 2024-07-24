from fastapi import Request, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import datetime, timedelta, timezone
import jwt
import schemas

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


class JWTBearer(HTTPBearer):
    """
    JWTBearer is a security class for FastAPI that implements the Bearer token authentication scheme.
    """

    def __init__(self, auto_error: bool = True):
        """
        Initializes JWTBearer with optional auto_error flag.

        param auto_error: If True, will automatically raise HTTP 401 errors if credentials are invalid.
        """
        super(JWTBearer, self).__init__(auto_error=auto_error)

    async def __call__(self, request: Request):
        """
        Validates the JWT token from the Authorization header.

        param request: The HTTP request object.
        return: The email from the decoded JWT payload if valid.
        raises HTTPException: If the token is invalid or missing.

        The `credentials` parameter is an instance of `HTTPAuthorizationCredentials` that contains:
        - scheme: The authentication scheme, should be "Bearer".
        - credentials: The token string.
        """
        credentials: HTTPAuthorizationCredentials = await super(
            JWTBearer, self
        ).__call__(request)
        if credentials:
            if credentials.scheme != "Bearer":
                raise HTTPException(
                    status_code=403, detail="Invalid authentication scheme."
                )
            try:
                payload = decode_jwt_token(credentials.credentials)
                # Token is valid, you can use payload if needed
                return payload.get("email")
            except HTTPException as e:
                raise e  # Re-raise the exception from decode_jwt_token
        else:
            raise HTTPException(status_code=403, detail="Invalid authorization code.")


def create_jwt_token(data: dict):
    """
    Creates a JWT token with an expiration time.

    param data: The payload data to include in the token.
    return: A dictionary containing the JWT token.
    """
    payload = data.copy()
    access_token_expires = datetime.now(timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )
    payload.update({"exp": access_token_expires})
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return {"jwt_token": token}


def decode_jwt_token(token: str):
    """
    Decodes a JWT token and verifies its validity.

    param token: The JWT token to decode.
    return: The decoded token payload.
    raises HTTPException: If the token is expired or invalid.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        # payload = {'email': 'username@gmail.com', 'exp': 1721675711}
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
