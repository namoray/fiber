import json
from typing import Any
import httpx
from fiber.chain_interactions.models import Node
from fiber.logging_utils import get_logger
from typing import AsyncGenerator

from fiber.security.tickets.operations import create_basic_ticket, ticket_to_headers
from fiber.security.tickets.models import TicketState

logger = get_logger(__name__)

def construct_server_address(
    node: Node,
    replace_with_docker_localhost: bool = False,
    replace_with_localhost: bool = False,
) -> str:
    """
    Currently just supports http4.
    """
    if node.ip == "0.0.0.1":
        # CHAIN DOES NOT ALLOW 127.0.0.1 TO BE POSTED. IS THIS
        # A REASONABLE WORKAROUND FOR LOCAL DEV?
        if replace_with_docker_localhost:
            return f"http://host.docker.internal:{node.port}"
        elif replace_with_localhost:
            return f"http://localhost:{node.port}"
    return f"http://{node.ip}:{node.port}"


async def make_non_streamed_get(
    httpx_client: httpx.AsyncClient,
    server_address: str,
    endpoint: str,
    state: TicketState,
    headers: dict[str, Any] = {},
    timeout: float = 10,
):
    # Create new ticket
    ticket = create_basic_ticket(state) # TODO: you could also make an advanced ticket

    # Convert ticket to headers
    headers = ticket_to_headers(ticket, headers)
    logger.debug(f"headers: {headers}")
    response = await httpx_client.get(
        timeout=timeout,
        headers=headers,
        url=server_address + endpoint,
    )
    return response


async def make_non_streamed_post(
    httpx_client: httpx.AsyncClient,
    server_address: str,
    endpoint: str,
    payload: dict[str, Any],
    state: TicketState,
    headers: dict[str, Any] = {},
    timeout: float = 10,
) -> httpx.Response:
    # Create new ticket
    ticket = create_basic_ticket(state) # TODO: you could also make an advanced ticket

    # Convert ticket to headers
    headers = ticket_to_headers(ticket, headers)

    # Send request    
    response = await httpx_client.post(
        content=json.dumps(payload).encode(),
        timeout=timeout,
        headers=headers,
        url=server_address + endpoint,
    )
    return response


async def make_streamed_post(
    httpx_client: httpx.AsyncClient,
    server_address: str,
    endpoint: str,
    payload: dict[str, Any],
    state: TicketState,
    headers: dict[str, Any] = {},
    timeout: float = 10,
) -> AsyncGenerator[bytes, None]:
    # Create new ticket
    ticket = create_basic_ticket(state) # TODO: you could also make an advanced ticket

    # Convert ticket to headers
    headers = ticket_to_headers(ticket, headers)

    # Create generator
    async with httpx_client.stream(
        method="POST",
        url=server_address + endpoint,
        content=json.dumps(payload).encode(),
        headers=headers,
        timeout=timeout,
    ) as response:
        try:
            response.raise_for_status()
            async for line in response.aiter_raw():
                yield line
        except httpx.HTTPStatusError as e:
            await response.aread()
            logger.error(f"HTTP Error {e.response.status_code}: {e.response.text}")
            raise
        except Exception:
            # logger.error(f"Unexpected error: {str(e)}")
            # logger.exception("Full traceback:")
            raise
