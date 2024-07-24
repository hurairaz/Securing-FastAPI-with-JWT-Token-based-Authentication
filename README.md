# Securing FastAPI with JWT Token-based Authentication

This guide outlines the process for implementing JWT (JSON Web Token) authentication in a FastAPI application. JWT is widely used to secure APIs by encoding information into tokens that can be validated and decoded by the server. This document provides a comprehensive overview of setting up JWT authentication, including the complete code and detailed explanations.

## Project Structure

The project structure for this implementation is as follows:

```
FastAPIApplication/
│
├── api.py
└── auth_handler.py
```

### `/auth_handler.py`

This file contains the logic for handling JWT token creation, decoding, and validation.

**Complete Code:**

```python
from fastapi import Request, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import datetime, timedelta, timezone
import jwt

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class JWTBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super(JWTBearer, self).__init__(auto_error=auto_error)

    async def __call__(self, request: Request):
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
    payload = data.copy()
    access_token_expires = datetime.now(timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )
    payload.update({"exp": access_token_expires})
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return {
        "jwt_token": token
    }

def decode_jwt_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        # payload = {'email': 'username@gmail.com', 'exp': 1721675711}
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
```

### `Explanation`

1. **Importing Libraries**

   ```python
   from fastapi import Request, HTTPException
   from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
   from datetime import datetime, timedelta, timezone
   import jwt
   ```

   In this section, essential libraries are imported. `Request` and `HTTPException` are imported from FastAPI to handle incoming requests and raise HTTP exceptions. `HTTPBearer` and `HTTPAuthorizationCredentials` are used for managing Bearer tokens, which are the standard method for transmitting JWTs. The `datetime`, `timedelta`, and `timezone` modules are utilized to handle time-based operations such as token expiration. The `jwt` library is used for encoding and decoding JSON Web Tokens.

2. **Configuration Constants**

   ```python
   SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
   ALGORITHM = "HS256"
   ACCESS_TOKEN_EXPIRE_MINUTES = 30
   ```

   Here, `SECRET_KEY` is a confidential string used to sign the JWTs, ensuring that they cannot be tampered with. `ALGORITHM` specifies the encryption algorithm used for encoding the JWT (HS256 in this case). `ACCESS_TOKEN_EXPIRE_MINUTES` defines the token's validity period in minutes, after which the token will expire and need to be refreshed.

3. **Creating JWT Token**

   ```python
   def create_jwt_token(data: dict):
       payload = data.copy()
       access_token_expires = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
       payload.update({"exp": access_token_expires})
       token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
       return {
           "jwt_token": token
       }
   ```

   The `create_jwt_token` function generates a new JWT token. It accepts a `data` dictionary, which typically includes user information such as `{"email": "user@example.com"}`. The function creates a copy of this data for the `payload` and sets an expiration time for the token by adding `ACCESS_TOKEN_EXPIRE_MINUTES` to the current UTC time. This expiration time is included in the payload. The `jwt.encode` function then creates the JWT using the `SECRET_KEY` and specified `ALGORITHM`. The generated token is returned in a dictionary with the key `"jwt_token"`.

4. **Decoding JWT Token**

   ```python
   def decode_jwt_token(token: str):
       try:
           payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
           return payload
       except jwt.ExpiredSignatureError:
           raise HTTPException(status_code=401, detail="Token has expired")
       except jwt.InvalidTokenError:
           raise HTTPException(status_code=401, detail="Invalid token")
   ```

   The `decode_jwt_token` function is responsible for decoding the JWT token. It uses the `SECRET_KEY` and `ALGORITHM` to decode the token and extract the payload. If the token is valid, the function returns the payload, which contains the information originally encoded. If the token has expired or is otherwise invalid, the function raises an `HTTPException` with a status code of 401 and an appropriate error message. This ensures that only valid tokens can be processed.

5. **JWTBearer Class**

   ```python
   class JWTBearer(HTTPBearer):
       def __init__(self, auto_error: bool = True):
           super(JWTBearer, self).__init__(auto_error=auto_error)

       async def __call__(self, request: Request):
           credentials: HTTPAuthorizationCredentials = await super(JWTBearer, self).__call__(request)
           if credentials:
               if credentials.scheme != "Bearer":
                   raise HTTPException(
                       status_code=403, detail="Invalid authentication scheme."
                   )
               try:
                   payload = decode_jwt_token(credentials.credentials)
                   return payload.get("email")
               except HTTPException as e:
                   raise e
           else:
               raise HTTPException(status_code=403, detail="Invalid authorization code.")
   ```

   The `JWTBearer` class extends the `HTTPBearer` class from FastAPI's security module to implement custom JWT authentication logic. In the `__init__` method, the class is initialized with an optional `auto_error` parameter. When set to `True`, authentication errors are automatically handled; when `False`, you must manage these errors manually. The method calls the parent class's constructor to set up the base class with the `auto_error` parameter.

   The `__call__` method processes and validates the JWT found in the `Authorization` header of an incoming request. It first calls the superclass's `__call__` method to extract the header of type HTTPAuthorizationCredentials in credentials variable, containing the scheme and credentials(token). If the credentials are present, it checks if the scheme is "Bearer". If not, it raises a 403 Forbidden error. If the scheme is correct, the method tries to decode the JWT using the `decode_jwt_token` function. If successful, it extracts and returns the email from the payload. If decoding fails, it raises an HTTPException with the relevant error details.

### `/api.py`

This file contains the FastAPI route handlers that use the `JWTBearer` class to secure endpoints.

1. **Signup Endpoint**

   ```python
   @app.post("/user/signup")
   async def create_user(user: UserSchema):
       new_user = create_new_user(user)
       jwt_token = auth_handler.create_jwt_token({"email": new_user.email})
       return jwt_token
   ```

   The `/user/signup` endpoint allows new users to sign up and generates a JWT token for them. The `create_user` function handles user creation and is typically implemented in the `crud` module. After creating the new user, the `create_jwt_token` function is called with the user's email to generate a JWT token. This token is then returned in the response, allowing the user to authenticate in subsequent requests.

2. **User Details Endpoint**

   ```python
   @app.post("/user/details")
   async def get_user_details(email: str = Depends(auth_handler.JWTBearer())):
       return user_details(email)
   ```

   The `/user/details` endpoint is protected by the `JWTBearer` dependency. This ensures that only requests with a valid JWT token can access the endpoint. The `Depends(auth_handler.JWTBearer())` dependency validates the JWT token provided in the `Authorization` header. If the token is valid, the `get_user_details` function retrieves and returns the user's details based on the provided email.

---
