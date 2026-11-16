from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any

import pytest

from sigaudit.demo_server import DemoReceiver, ReceiverConfig

SECRET = "whsec_test_secret"

ReceiverFactory = Callable[..., DemoReceiver]


@pytest.fixture
def make_receiver() -> Iterator[ReceiverFactory]:
    """Start local receivers on random ports; all are stopped after the test."""
    started: list[DemoReceiver] = []

    def factory(**kwargs: Any) -> DemoReceiver:
        kwargs.setdefault("secret", SECRET)
        receiver = DemoReceiver(ReceiverConfig(**kwargs)).start()
        started.append(receiver)
        return receiver

    yield factory
    for receiver in started:
        receiver.stop()
