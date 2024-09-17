EXCHANGE_SYMMETRIC_KEY_ENDPOINT = "exchange-symmetric-key"
PUBLIC_ENCRYPTION_KEY_ENDPOINT = "public-encryption-key"

SYMMETRIC_KEY_UUID = "symmetric-key-uuid"
SS58_ADDRESS = "hotkey-ss58-address"
NEURON_INFO_LITE = "NeuronInfoLite"

# Used in HMAC tickets
HMAC_TICKET_SIGNATURE = "fiber-hmac-ticket-signature"
HMAC_TICKET_UUID = "fiber-hmac-ticket-uuid"
HMAC_TICKET_SEQUENCE = "fiber-hmac-ticket-sequence"

FINNEY_NETWORK = "finney"
FINNEY_TEST_NETWORK = "test"
FINNEY_SUBTENSOR_ADDRESS = "wss://entrypoint-finney.opentensor.ai:443"
FINNEY_TEST_SUBTENSOR_ADDRESS = "wss://test.finney.opentensor.ai:443/"

SUBTENSOR_NETWORK_TO_SUBTENSOR_ADDRESS = {
    FINNEY_NETWORK: FINNEY_SUBTENSOR_ADDRESS,
    FINNEY_TEST_NETWORK: FINNEY_TEST_SUBTENSOR_ADDRESS,
}


NONCE = "nonce"

SAVE_NODES_FILEPATH = "nodes.json"

SS58_FORMAT = 42
U16_MAX = 65535
