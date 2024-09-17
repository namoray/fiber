from pydantic import BaseModel

class TicketKey(BaseModel):
    """
    Represents the symmetric key shared between a miner and a validator for HMAC operations.

    Attributes:
        uuid (str): Unique identifier for the HMAC key.
        secret (bytes): The symmetric key used for generating HMAC signatures.
        validator_ss58_address (str): Validator's SS58 address.
        miner_ss58_address (str): Miner's SS58 address.
    """
    uuid: str
    secret: bytes
    validator_ss58_address: str
    miner_ss58_address: str

class TicketState(BaseModel):
    """
    Tracks the current HMAC operation state between a validator and a miner.

    Attributes:
        key (TicketKey): The Ticket in use.
        sequence (int): The current sequence number for ensuring unique message signatures.
    """
    key: TicketKey
    sequence: int

class Ticket(BaseModel):
    """
    Holds the details of an HMAC ticket used for validating messages.

    Attributes:
        key_uuid (str): UUID of the HMAC key used.
        signature (str): The HMAC signature for verification.
        sequence (int): The sequence number tied to this ticket.
    """
    key_uuid: str
    signature: str
    sequence: int

class TicketInfo(BaseModel):
    sequence: int
    ttl: float