class TicketError(Exception):
    """Base class for ticket-related exceptions."""
    pass

class TicketUUIDNotFoundError(TicketError):
    """Raised when a ticket's UUID is not found in the ticket manager."""
    
    def __init__(self, uuid: str):
        self.uuid = uuid
        super().__init__(f"Ticket UUID {uuid} not found.")

class TicketSequenceUsedError(TicketError):
    """Raised when a ticket's sequence number has already been used."""
    
    def __init__(self, uuid: str, sequence: int):
        self.uuid = uuid
        self.sequence = sequence
        super().__init__(f"Ticket sequence {sequence} has already been used for UUID {uuid}.")

class TicketKeyAlreadyUsedError(Exception):
    """Raised when a ticket's key has already been used."""
    
    def __init__(self, uuid: str):
        self.uuid = uuid
        super().__init__(f"TicketKey has already been used for UUID {uuid}.")

class TicketKeyExpiredError(Exception):
    """Raised when a ticket's TTL has expired."""
    def __init__(self, message: str):
        super().__init__(message)