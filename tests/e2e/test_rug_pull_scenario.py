import pytest
import asyncio
from sandbox.traffic.attacks.rug_pull import simulate_rug_pull

def test_e2e_rug_pull():
    asyncio.run(simulate_rug_pull())
