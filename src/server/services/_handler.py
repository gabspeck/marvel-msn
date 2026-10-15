"""Base class for pipe service handlers."""


class ServiceHandler:
    """Hooks the connection calls on every handler. Each is a no-op unless the
    service overrides it."""

    def bind_connection(self, connection):
        """Called once after the pipe opens, before discovery. Services that
        push outside a request keep `connection` to reach the client."""

    def handle_iterator_cancel(self, msg_class, selector, request_id):
        """An MPCCL iterator-cancel arrived for a stream this pipe opened. The
        connection sends the ack."""

    def flush_pending_events(self):
        """Called after each request, outside the connection's send lock."""

    def close(self):
        """The pipe or the connection closed."""
