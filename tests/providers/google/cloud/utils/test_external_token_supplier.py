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

import logging
from unittest.mock import ANY

import pytest

from airflow.providers.google.cloud.utils.external_token_supplier import (
    ClientCredentialsGrantFlowTokenSupplier,
)

ISSUER_URL = "https://testidpissuerurl.com"
CLIENT_ID = "clientid"
CLIENT_SECRET = "clientsecret"

TOKEN1 = "token1"
TOKEN2 = "token2"
EXPIRES_IN = 60
EXPIRED = -1
SUPPLIER_LOGGER_NAME = (
    "airflow.providers.google.cloud.utils.external_token_supplier.ClientCredentialsGrantFlowTokenSupplier"
)


class TestClientCredentialsGrantFlowTokenSupplier:
    @pytest.fixture
    def token_supplier(self):
        return ClientCredentialsGrantFlowTokenSupplier(ISSUER_URL, CLIENT_ID, CLIENT_SECRET)

    def test_get_subject_token_first_time(self, requests_mock, token_supplier):
        requests_mock.post(ISSUER_URL, json={"access_token": TOKEN1, "expires_in": EXPIRES_IN})
        assert token_supplier.get_subject_token(context=ANY, request=ANY) == TOKEN1

    def test_get_subject_token_has_valid_token(self, requests_mock, token_supplier):
        requests_mock.post(ISSUER_URL, json={"access_token": TOKEN1, "expires_in": EXPIRES_IN})
        assert token_supplier.get_subject_token(context=ANY, request=ANY) == TOKEN1
        requests_mock.post(ISSUER_URL, json={"access_token": TOKEN2, "expires_in": EXPIRES_IN})
        assert token_supplier.get_subject_token(context=ANY, request=ANY) == TOKEN1

    def test_get_subject_token_expired(self, requests_mock, token_supplier, caplog):
        requests_mock.post(ISSUER_URL, json={"access_token": TOKEN1, "expires_in": EXPIRED})
        token_supplier.get_subject_token(context=ANY, request=ANY)
        with caplog.at_level(level=logging.INFO, logger=SUPPLIER_LOGGER_NAME):
            caplog.clear()
            token_supplier.get_subject_token(context=ANY, request=ANY)
        assert "OIDC token missing or expired" in caplog.messages
