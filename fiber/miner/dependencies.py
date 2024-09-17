from fiber.miner.core import configuration
from fiber.miner.core.models.config import Config
from fastapi import Depends, Request, HTTPException
from fiber.logging_utils import get_logger
from fiber.miner.security import signatures
from fiber.security.tickets.operations import headers_to_ticket


logger = get_logger(__name__)


def get_config() -> Config:
    return configuration.factory_config()


async def verify_signature(request: Request, config: Config = Depends(get_config)):
    hotkey = request.headers.get("hotkey")
    if not hotkey:
        logger.debug("Hotkey header missing")
        raise HTTPException(status_code=400, detail="Hotkey header missing")

    signature = request.headers.get("signature")
    if not signature:
        logger.debug("Signature header missing")
        raise HTTPException(status_code=400, detail="Signature header missing")

    if not signatures.verify_signature(
        message=signatures.construct_message_from_payload(await request.body()),
        ss58_address=hotkey,
        signature=signature,
    ):
        raise HTTPException(
            status_code=401,
            detail="Oi, invalid signature, you're not who you said you were!",
        )


async def blacklist_low_stake(request: Request, config: Config = Depends(get_config)):
    metagraph = config.metagraph

    hotkey = request.headers.get("hotkey")
    if not hotkey:
        raise HTTPException(status_code=400, detail="Hotkey header missing")

    node = metagraph.nodes.get(hotkey)
    if not node:
        raise HTTPException(status_code=403, detail="Hotkey not found in metagraph")

    if node.stake <= config.min_stake_threshold:
        raise HTTPException(status_code=403, detail="Insufficient stake")


async def verify_nonce(request: Request, config: Config = Depends(get_config)):
    nonce = (await request.json()).get("nonce")
    if not nonce:
        raise HTTPException(status_code=400, detail="Nonce missing from body")

    if not config.encryption_keys_handler.nonce_manager.nonce_is_valid(nonce):
        raise HTTPException(status_code=401, detail="Oi, invalid nonce!!")


async def verify_ticket(request: Request, config: Config = Depends(get_config)):
    ticket = headers_to_ticket(dict(request.headers))
    if not config.ticket_manager.verify_ticket(ticket):
        raise HTTPException(status_code=401, detail="Oi, invalid ticket!!")
