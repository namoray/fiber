"""
THIS IS AN EXAMPLE FILE OF A SUBNET ENDPOINT!

PLEASE IMPLEMENT YOUR OWN :)
"""

from functools import partial
from fastapi import Depends
from pydantic import BaseModel
from fiber.miner.dependencies import blacklist_low_stake, verify_nonce
from fiber.miner.security.encryption import decrypt_general_payload
from fastapi.routing import APIRouter


class ExampleSubnetRequest(BaseModel):
    pass


async def example_subnet_request(
    decrypted_payload: ExampleSubnetRequest = Depends(
        partial(decrypt_general_payload, ExampleSubnetRequest),
    ),
):
    return {"status": "Example request received"}


def factory_router() -> APIRouter:
    router = APIRouter()
    router.add_api_route(
        "/example-subnet-request",
        example_subnet_request,
        tags=["Example"],
        dependencies=[
            Depends(blacklist_low_stake),
            Depends(verify_nonce),
        ],
        methods=["POST"],
    )
    return router
