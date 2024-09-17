import time
from typing import Dict
from fiber.miner.core import miner_constants as mcst
from fiber.logging_utils import get_logger
from fiber.security.tickets.errors import TicketKeyAlreadyUsedError, TicketKeyExpiredError, TicketSequenceUsedError, TicketUUIDNotFoundError
from fiber.security.tickets.models import TicketInfo, Ticket, TicketKey

logger = get_logger(__name__)

class TicketManager:
    """
    Manages HMAC tickets and their sequences, ensuring each ticket is valid, unique,
    and within its time-to-live (TTL) period.
    
    Attributes:
        tickets (Dict[str, TicketTicketInfo]): A dictionary mapping ticket UUIDs to their TicketTicketInfo.
    """

    def __init__(self):
        self.tickets: Dict[str, TicketInfo] = {}

    def add_ticket_key(self, key: TicketKey, ttl: float):
        """
        Adds a new ticket key to the manager and initializes its sequence to 0.

        This method registers a new ticket key in the ticket manager and assigns a Time-to-Live (TTL) 
        for the key, after which it expires. The key is identified by its UUID, and if the UUID already 
        exists in the manager, an error is raised to prevent duplicate keys. The sequence is initialized 
        to 0 upon addition.

        Args:
            key (TicketKey): The key to be added, containing its UUID.
            ttl (float): The Time-to-Live (in seconds) for this key, representing how long the key is valid.
        
        Raises:
            TicketKeyAlreadyUsedError: If the key's UUID already exists in the manager.
        """
        current_time = time.time()
        expiration_time = current_time + ttl
        
        # Check if the UUID is already in the ticket manager
        if key.uuid in self.tickets:
            raise TicketKeyAlreadyUsedError(key.uuid)

        # Add or update the ticket with a new sequence and TTL
        self.tickets[key.uuid] = TicketInfo(sequence=0, ttl=expiration_time)

    def verify_ticket(self, ticket: Ticket) -> bool:
        """
        Verifies if a ticket is valid and its sequence hasn't been used already.

        Args:
            ticket (HMACTicket): The ticket to verify.
        
        Returns:
            bool: True if the ticket is valid, False otherwise.
        
        Raises:
            TicketUUIDNotFoundError: If the ticket's UUID is not known.
            TicketSequenceUsedError: If the ticket's sequence number has already been used.
            TicketKeyExpiredError: If the ticket key TTL has expired.
        """
        # Check if the UUID exists in the manager
        if ticket.key_uuid not in self.tickets:
            raise TicketUUIDNotFoundError(ticket.key_uuid)

        # Ensure the sequence number hasn't been reused
        existing_info = self.tickets[ticket.key_uuid]
        if ticket.sequence <= existing_info.sequence:
            raise TicketSequenceUsedError(ticket.key_uuid, ticket.sequence)


        # Check TTL (Time-to-Live)
        current_time = time.time()
        if current_time > existing_info.ttl:
            raise TicketKeyExpiredError(f"Ticket UUID {ticket.key_uuid} has expired.")

        # Update that sequence cannot be used again
        existing_info.sequence = ticket.sequence

        # Valid
        return True

    def cleanup(self):
        """
        Removes expired key uuids from the manager based on their TTL.
        """
        current_time = time.time()
        expired_tickets = [uuid for uuid, info in self.tickets.items() if info.ttl < current_time]
        
        # Remove tickets whose TTL has expired
        for uuid in expired_tickets:
            del self.tickets[uuid]

    def remove_expired_key_uuids(self, uuid: str):
        """
        Removes a specific key uuids if it has expired.
        
        Args:
            uuid (str): The UUID of the key to remove.
        """
        if uuid in self.tickets and self.tickets[uuid].ttl < time.time():
            del self.tickets[uuid]
            