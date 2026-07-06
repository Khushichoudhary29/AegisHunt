import abc
import logging
from state.models import IncidentState

class AegisAgent(abc.ABC):
    """
    Abstract base class for all security agents in the AegisHunt framework.
    """
    def __init__(self, name: str):
        self.name = name
        self.logger = logging.getLogger(self.name)
        # Configure logging if not already configured
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "[%(asctime)s - %(name)s] %(levelname)s: %(message)s"
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    @abc.abstractmethod
    async def process(self, state: IncidentState) -> IncidentState:
        """
        Executes the agent logic, modifying the state in-place or returning a new state.
        """
        pass
