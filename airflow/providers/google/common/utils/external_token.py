from google.auth.transport import Request
from google.auth.identity_pool import SubjectTokenSupplier
from google.auth.external_account import SupplierContext

import requests

class KeyCloakTokenSupplier(SubjectTokenSupplier):

    def __init__(
        self,
        idp_link: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
    ) -> None:
        super().__init__()
        self.idp_link = idp_link
        self.client_id = client_id
        self.client_secret = client_secret
        self._cached_token = None
        self._token_expiry = None

    def get_subject_token(self, context: SupplierContext, request: Request):

        r = requests.post(self.idp_link, data={
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "client_credentials"
        })
        r.raise_for_status()

        token_response = r.json()
        access_token = token_response['access_token']

        return access_token
    
