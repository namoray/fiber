from dataclasses import dataclass
from fiber.chain_interactions.metagraph import Metagraph
from fiber.miner.security import key_management
from substrateinterface import Keypair
import httpx
import aiohttp


@dataclass
class Config:
    encryption_keys_handler: key_management.EncryptionKeysHandler
    keypair: Keypair
    metagraph: Metagraph
    min_stake_threshold: float
    httpx_client: httpx.AsyncClient
    aiohttp_client: aiohttp.ClientSession
