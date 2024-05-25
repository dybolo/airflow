# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
from __future__ import annotations

from typing import TYPE_CHECKING

import requests
from google.auth.identity_pool import SubjectTokenSupplier

if TYPE_CHECKING:
    from google.auth.external_account import SupplierContext
    from google.auth.transport import Request


class KeyCloakTokenSupplier(SubjectTokenSupplier):
    """
        This class provides support for getting access tokens from Keycloak using Client Credentials Grant flow.

    :param idp_link: Keycloak link to request the token.
    :param client_id: Keycloak client id.
    :param client_secret: Keycloak client_secret.
    """

    def __init__(
        self,
        idp_link: str,
        client_id: str,
        client_secret: str,
    ) -> None:
        super().__init__()
        self.idp_link = idp_link
        self.client_id = client_id
        self.client_secret = client_secret
        self._cached_token = None
        self._token_expiry = None

    def get_subject_token(self, context: SupplierContext, request: Request):
        r = requests.post(
            self.idp_link,
            data={
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "grant_type": "client_credentials",
            },
        )
        r.raise_for_status()

        token_response = r.json()
        access_token = token_response["access_token"]

        return access_token
