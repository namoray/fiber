import base64
import json
from typing import Type, TypeVar

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import Depends, Header, HTTPException, Request
from pydantic import BaseModel

from fiber.logging_utils import get_logger
from fiber.miner.core.models.config import Config
from fiber.miner.core.models.encryption import SymmetricKeyExchange
from fiber.miner.dependencies import get_config

logger = get_logger(__name__)

T = TypeVar("T", bound=BaseModel)


async def get_body(request: Request) -> bytes:
    return await request.body()


def get_symmetric_key_b64_from_payload(payload: SymmetricKeyExchange, private_key: rsa.RSAPrivateKey) -> str:
    encrypted_symmetric_key = base64.b64decode(payload.encrypted_symmetric_key)
    try:
        decrypted_symmetric_key = private_key.decrypt(
            encrypted_symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except ValueError:
        raise HTTPException(status_code=401, detail="Oi, I can't decrypt that symmetric key, sorry")
    base64_symmetric_key = base64.urlsafe_b64encode(decrypted_symmetric_key).decode()
    return base64_symmetric_key


async def decrypt_symmetric_key_exchange_payload(
    config: Config = Depends(get_config), encrypted_payload: bytes = Depends(get_body)
):
    decrypted_data = config.encryption_keys_handler.private_key.decrypt(
        encrypted_payload,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    data_dict = json.loads(decrypted_data.decode())
    return SymmetricKeyExchange(**data_dict)


def decrypt_general_payload(
    model: Type[T],
    check_nonce: bool = True,
    encrypted_payload: bytes = Depends(get_body),
    symmetric_key_uuid: str = Header(...),
    hotkey_ss58_address: str = Header(...),
    config: Config = Depends(get_config),
) -> T:
    symmetric_key_info = config.encryption_keys_handler.get_symmetric_key(hotkey_ss58_address, symmetric_key_uuid)
    if not symmetric_key_info:
        raise HTTPException(status_code=400, detail="No symmetric key found for that hotkey and uuid")

    decrypted_data = symmetric_key_info.fernet.decrypt(encrypted_payload)

    data_dict: dict = json.loads(decrypted_data.decode())
    if check_nonce:
        nonce: str = data_dict.get("nonce", "")
        if config.encryption_keys_handler.nonce_manager.nonce_is_valid(nonce):
            raise HTTPException(
                status_code=401,
                detail="Oi, I've seen that nonce before. Don't send me the nonce more than once",
            )
    return model(**data_dict)
