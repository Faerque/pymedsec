# SPDX-License-Identifier: Apache-2.0

"""Integration-style tests for Hyperledger adapter logic."""

import json

import pytest

import pymedsec.blockchain.hyperledger as hyperledger_module


class _FakeHyperledgerClient:
    """Minimal fake Fabric client for adapter integration path."""

    def __init__(self, net_profile):
        self.net_profile = net_profile

    def get_organization(self, org_name):
        return {"org": org_name}

    def get_user(self, org_name, user_name):
        return {"org": org_name, "user": user_name}

    def get_peer(self, peer_name):
        return {"peer": peer_name}

    def new_channel(self, channel_name):
        return {"channel": channel_name}

    def chaincode_invoke(self, **kwargs):
        return {"tx_id": "hlf_tx_123"}

    def chaincode_query(self, **kwargs):
        return json.dumps(
            {
                "verified": True,
                "status": "verified",
                "block_number": 7,
                "confirmations": 2,
                "message": "Verified",
            }
        )

    def query_transaction(self, **kwargs):
        return {
            "found": True,
            "status": "confirmed",
            "block_number": 7,
            "confirmations": 2,
            "message": "Confirmed",
        }


@pytest.mark.integration
def test_hyperledger_adapter_contract_with_fake_client(monkeypatch):
    """Hyperledger adapter should return normalized contracts."""
    monkeypatch.setattr(hyperledger_module, "HFC_AVAILABLE", True)
    monkeypatch.setattr(
        hyperledger_module,
        "Hyperledger_Fabric_Client",
        _FakeHyperledgerClient,
    )

    adapter = hyperledger_module.HyperledgerBlockchainAdapter(
        {
            "network_profile": "fake-network.json",
            "channel_name": "mychannel",
            "chaincode_name": "audit_chaincode",
            "org_name": "Org1MSP",
            "peer_name": "peer0.org1.example.com",
            "user_name": "Admin",
        }
    )

    digest = "b" * 64
    submit_result = adapter.submit_digest(digest, {"operation": "integration-test"})
    assert submit_result["backend"] == "hyperledger"
    assert submit_result["status"] == "submitted"

    verify_result = adapter.verify_digest(digest, submit_result["tx_hash"])
    assert verify_result["backend"] == "hyperledger"
    assert verify_result["status"] == "verified"
    assert verify_result["verified"] is True

    tx_status = adapter.get_transaction_status(submit_result["tx_hash"])
    assert tx_status["backend"] == "hyperledger"
    assert tx_status["status"] == "confirmed"
    assert tx_status["found"] is True
