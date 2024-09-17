import base64
import json
from typing import Any
from cryptography.hazmat.primitives import hashes, hmac
from fiber.security.tickets.models import TicketState, Ticket, TicketKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from fiber import constants as bcst

def create_key(uuid: str, secret: bytes, validator_ss58_address: str, miner_ss58_address: str) -> TicketKey:
    """
    Creates a TicketKey instance with the provided parameters.

    Args:
        uuid (str): Unique identifier for the HMAC key.
        secret (bytes): The symmetric key used for generating HMAC signatures.
        validator_ss58_address (str): Validator's SS58 address.
        miner_ss58_address (str): Miner's SS58 address.

    Returns:
        TicketKey: A new instance of the TicketKey class.
    """
    return TicketKey(
        uuid=uuid,
        secret=secret,
        validator_ss58_address=validator_ss58_address,
        miner_ss58_address=miner_ss58_address
    )

def create_state(key: TicketKey) -> TicketState:
  """
  Creates and initializes an HMAC state object for managing HMAC sequences.

  This function initializes an TicketState object with a sequence number set to 0
  and a symmetric key provided as input. The sequence number is used to track the 
  number of HMAC operations, ensuring each operation can be tied to a specific 
  order or session state. The symmetric key is used for generating the HMACs 
  when the state is used in future cryptographic operations.

  Args:
      key (TicketKey): The symmetric key used for HMAC operations.
  
  Returns:
      TicketState: An initialized HMAC state with the sequence set to 0 and 
      the provided symmetric key.
  """
  return TicketState(
    sequence=0,
    key=key
  )

def _sign(key: TicketKey, message: str):
  """
  Signs a given message using HMAC (SHA-256) and returns the signature encoded in Base64.

  Args:
      key (TicketKey): The secret key used to create the HMAC signature.
      message (str): The message or data that needs to be signed.

  Returns:
      str: The generated HMAC signature, encoded in Base64 format.
  """
  h = hmac.HMAC(key.secret, hashes.SHA256())
  h.update(message.encode())
  signature = h.finalize()
  return base64.b64encode(signature).decode()

def _verify(key: TicketKey, message: str, signature: str) -> bool:
  """
  Verifies that a given HMAC signature is valid for a message using the provided key.

  Args:
      key (TicketKey): The secret key used to verify the HMAC signature.
      message (str): The original message that was signed.
      signature (str): The HMAC signature to verify, encoded in Base64.

  Returns:
      bool: True if the signature is valid, False otherwise.
  """
  try: 
    h = hmac.HMAC(key.secret, hashes.SHA256())
    h.update(message.encode())    
    h.verify(base64.b64decode(signature.encode()))
    return True
  except:
    return False

def _body_hash(body: dict[str, Any]) -> str:
  """
  Generates a SHA-256 hash for the given body (in JSON format).

  Args:
      body (dict[str, Any]): The body of the HTTP request or any data represented as a dictionary.
  
  Returns:
      str: The hexadecimal representation of the SHA-256 hash of the JSON-encoded body.
  """
  body_json = json.dumps(body)
  body_json_digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
  body_json_digest.update(body_json.encode())
  return body_json_digest.finalize().hex()

def create_basic_ticket(state: TicketState) -> Ticket:
  """
  Creates an HMAC-based ticket using the current sequence number

  Args:
      state (TicketState): The HMAC state containing the sequence and key.
      message (bytes): The message to sign (e.g., request payload).

  Returns:
      bytes: The HMAC ticket to be used in the API call.
  """

  # Creates the HMAC signature for the ticket
  current_sequence = state.sequence
  message = f"{state.key.uuid}.{current_sequence}"
  state.sequence += 1

  # Creates a ticket holder
  return Ticket(
    key_uuid=state.key.uuid,
    signature=_sign(state.key, message),
    sequence=current_sequence
  )


def create_advanced_ticket(state: TicketState, body: dict[str, Any]) -> Ticket:
  """
  Creates an HMAC-based ticket using the current sequence number

  Args:
      state (TicketState): The HMAC state containing the sequence and key.
      message (bytes): The message to sign (e.g., request payload).

  Returns:
      bytes: The HMAC ticket to be used in the API call.
  """

  # Creates the HMAC signature for the ticket
  current_sequence = state.sequence
  message = f"{state.key.uuid}.{current_sequence}.{_body_hash(body)}"
  state.sequence += 1

  # Creates a ticket holder
  return Ticket(
    key_uuid=state.key.uuid,
    signature=_sign(state.key, message),
    sequence=current_sequence
  )

def verify_basic_ticket(state: TicketState, ticket: Ticket) -> bool:
  """
  Verifies a basic HMAC ticket by checking the signature against the combination 
  of the key UUID and the sequence number.

  Args:
      state (TicketState): The current HMAC state, which contains the key and sequence information.
      ticket (Ticket): The ticket to verify, which includes the sequence and the signature.

  Returns:
      bool: True if the ticket's signature is valid, False otherwise.
  """
  message = f"{state.key.uuid}.{ticket.sequence}"
  return _verify(key=state.key, message=message, signature=ticket.signature)


def verify_advanced_ticket(state: TicketState, ticket: Ticket, body: dict[str, Any]) -> bool:
  """
  Verifies an advanced HMAC ticket by checking the signature against the combination 
  of the key UUID, sequence number, and the SHA-256 hash of the HTTP body.

  Args:
      state (TicketState): The current HMAC state, which contains the key and sequence information.
      ticket (Ticket): The ticket to verify, which includes the sequence and the signature.
      body (dict[str, Any]): The HTTP body (or payload) that should be hashed and included in the verification.

  Returns:
      bool: True if the ticket's signature is valid, False otherwise.
  """
  message = f"{state.key.uuid}.{ticket.sequence}.{_body_hash(body)}"
  return _verify(key=state.key, message=message, signature=ticket.signature)

def ticket_to_headers(ticket: Ticket, current_headers: dict[str, Any] = {}) -> dict[str, Any]:
    """
    Adds the HMAC ticket information to the HTTP headers for API requests.

    This function takes an existing dictionary of HTTP headers and adds new headers
    related to the HMAC ticket, including the sequence number and signature.
    If no headers are provided, a new dictionary is created.

    Args:
        ticket (Ticket): The HMAC ticket containing the sequence and signature.
        current_headers (dict[str, Any], optional): The existing headers to update. Defaults to an empty dictionary.

    Returns:
        dict[str, Any]: A dictionary containing the updated headers with HMAC ticket information.
    """
    # Adjust current headers accordingly
    current_headers[bcst.HMAC_TICKET_UUID] = ticket.key_uuid
    current_headers[bcst.HMAC_TICKET_SEQUENCE] = str(ticket.sequence)
    current_headers[bcst.HMAC_TICKET_SIGNATURE] = ticket.signature
    return current_headers
  
def headers_to_ticket(headers: dict[str, Any]) -> Ticket:
    """
    Converts HTTP headers containing HMAC-related information into an Ticket object.

    This function extracts the HMAC sequence and signature from the headers and 
    creates an `Ticket` object that can be used for further verification or processing.

    Args:
        headers (dict[str, Any]): A dictionary containing HTTP headers, including 
                                  "X-HMAC-Sequence" and "X-HMAC-Signature".

    Returns:
        Ticket: An object containing the sequence number and signature extracted from the headers.
    """
    # Extract the ticket from header
    sequence = int(headers.get(bcst.HMAC_TICKET_SEQUENCE, 0))
    signature = headers.get(bcst.HMAC_TICKET_SIGNATURE, '')
    key_uuid = headers.get(bcst.HMAC_TICKET_UUID, '')
    return Ticket(key_uuid=key_uuid, sequence=sequence, signature=signature)