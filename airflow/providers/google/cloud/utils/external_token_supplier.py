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

import time
from functools import wraps
from typing import TYPE_CHECKING, Any

import requests
from google.auth.exceptions import RefreshError
from google.auth.identity_pool import SubjectTokenSupplier

if TYPE_CHECKING:
    from google.auth.external_account import SupplierContext
    from google.auth.transport import Request

from airflow.utils.log.logging_mixin import LoggingMixin


def cache_token_decorator(get_subject_token_method):
    """Cache calls to ``SubjectTokenSupplier`` instances' ``get_token_supplier`` methods.

    :param get_subject_token_method: A method that returns both a token and an integer specifying
        the time in seconds until the token expires

    See also:
        https://googleapis.dev/python/google-auth/latest/reference/google.auth.identity_pool.html#google.auth.identity_pool.SubjectTokenSupplier.get_subject_token
    """
    token: str | None = None
    expiration_time: float = 0

    @wraps(get_subject_token_method)
    def wrapper(supplier_instance: SubjectTokenSupplier, context: SupplierContext, request: Request) -> str:
        """Obeys the interface set by ``SubjectTokenSupplier`` for ``get_subject_token`` methods.

        :param supplier_instance: the SubjectTokenSupplier whose get_subject_token method is being decorated
        :param context: The context object containing information about the requested audience and subject token type
        :param request: The object used to make HTTP requests
        :return: The token string
        """
        nonlocal token, expiration_time

        if token is None or expiration_time < time.monotonic():
            supplier_instance.log.info("OIDC token missing or expired")
            try:
                token, expires_in = get_subject_token_method(supplier_instance, context, request)
                if not isinstance(expires_in, int) or not isinstance(token, str):
                    raise RefreshError  # assume error if strange values are provided

            except RefreshError:
                supplier_instance.log.error("Failed retrieving new OIDC Token from IdP")
                raise

            expiration_time = time.monotonic() + float(expires_in)

            supplier_instance.log.info("New OIDC token retrieved, expires in %s", expires_in)

        return token

    return wrapper


class ClientCredentialsGrantFlowTokenSupplier(LoggingMixin, SubjectTokenSupplier):
    """
    Class that retrieves an OIDC token from an external IdP using OAuth2.0 Client Credentials Grant flow.

    This class implements the ``SubjectTokenSupplier`` interface class used by ``google.auth.identity_pool.Credentials``

    :params oidc_issuer_url: URL of the IdP that performs OAuth2.0 Client Credentials Grant flow and returns an OIDC token.
    :params client_id: Client ID of the application requesting the token
    :params client_secret: Client secret of the application requesting the token
    :params extra_params_kwargs: Extra parameters to be passed in the payload of the POST request to the `oidc_issuer_url`

    See also:
        https://googleapis.dev/python/google-auth/latest/reference/google.auth.identity_pool.html#google.auth.identity_pool.SubjectTokenSupplier
    """

    def __init__(
        self,
        oidc_issuer_url: str,
        client_id: str,
        client_secret: str,
        **extra_params_kwargs: Any,
    ) -> None:
        super().__init__()
        self.oidc_issuer_url = oidc_issuer_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.extra_params_kwargs = extra_params_kwargs

    @cache_token_decorator
    def get_subject_token(self, context: SupplierContext, request: Request):
        """Perform Client Credentials Grant flow with IdP and retrieves an OIDC token and expiration time."""
        self.log.info("Requesting new OIDC token from Keycloak IdP")
        response = requests.post(
            self.oidc_issuer_url,
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                **self.extra_params_kwargs,
            },
        )

        try:
            response.raise_for_status()
        except requests.HTTPError as e:
            raise RefreshError(str(e))

        try:
            response_dict = response.json()
        except requests.JSONDecodeError:
            raise RefreshError(f"Didn't get a json response from {self.oidc_issuer_url}")

        # These fields are required
        if {"access_token", "expires_in"} - set(response_dict.keys()):
            # TODO more information about the error can be provided in the exception by inspecting the response
            raise RefreshError(f"No access token returned from {self.oidc_issuer_url}")

        return response_dict["access_token"], response_dict["expires_in"]
