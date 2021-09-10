# -*- coding: utf-8 -*-
"""
Created on Fri Jun 11 08:39:03 2021

@author: Ajit.Jadhav
"""

import requests
import jwt as j
import json
from jwt import PyJWKClient
from jose import jwt, jwk
from jose.utils import base64url_decode

class JWTAuth():    
    def __init__(self, token = None):
        if not token:
            raise Exception("Initialization: No OAuth token found")
        self.token= token
        self.openid_uri = "https://sts.windows.net/your-active-directory-tenant-id/.well-known/openid-configuration"
    
    def get_token_headers(self):
        if not self.token:
            raise Exception("Headers: No OAuth token found")
        try:
            headers = jwt.get_unverified_header(token)
            if headers:
                return headers
            else:
                raise Exception("Headers: Error while decoding headers")
        except Exception as error:
            print(f"Headers: {error}")
            return None
    
    def get_signing_key(self, kid):
        try:
            jwks_uri = requests.get(self.openid_uri).json()["jwks_uri"]
            if not jwks_uri:
                raise Exception("Signing Key: No JWKS URI found")
            res = requests.get(jwks_uri).json()
            if "keys" not in res:
                raise Exception("Signing Key: No keys found")
            if len(res["keys"]) == 0:
                raise Exception("Singing Key: Null Keys")
            
            keys = res["keys"]
            for key in keys:
                if key["kid"] == kid:
                    sign_key = key
                    break
            if not sign_key:
                raise Exception("Signing Keys: No matching kid found")
            if "alg" not in sign_key:
                sign_key["alg"] = "RS256"
            return sign_key
        except Exception as error:
            print(str(error))
            return None
    
    def verify(self):
        try:
            if not self.token:
                raise Exception("Verify: No token found")
            token_headers = self.get_token_headers()
            if not token_headers:
                raise Exception("Verify: No headers")
            kid = token_headers["kid"]
            sign_key = self.get_signing_key(kid)
            if "alg" not in sign_key:
                sign_key["alg"] = "RS256"
            public_key = jwk.construct(sign_key)
            message, encoded_signature = str(self.token).rsplit(".", 1)
            decoded_signature = base64url_decode(encoded_signature.encode("utf-8"))
            if not public_key.verify(message.encode("utf-8"), decoded_signature):
                raise Exception("Verify: Invalid Signature")
            self.verify_status = True
            return True
        except Exception as error:
            self.verify_status = False
            print("--------------------------------------")
            print(str(error))
            print("--------------------------------------")
            return False
    
    def decode(self):
        try:
            if not self.verify_status:
                raise Exception("Decode: Invalid Signature")
            decoded = j.decode(self.token, options={"verify_signature": False})
            if decoded:
                return decoded
            else:
                raise Exception("Decode: Error while decoding token")
        except Exception as error:
            print(str(error))
            return None
        

def main(token):
    user = JWTAuth(token)
    is_verified = user.verify()
    if is_verified:
        return user.decode()

if __name__ == "__main__":
    token = "<jwt-token-without-Bearer>"
    decoded = main(token)
