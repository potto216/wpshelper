import socket
import threading


class MockAutomationSimulator:
    def __init__(self, responses=None, connect_responses=None):
        self._responses = list(responses or [])
        self._connect_responses = list(connect_responses or [])
        self.received = []
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind(("127.0.0.1", 0))
        self.address = self._server.getsockname()
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._clients = []
        self._conn = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc, exc_tb):
        self.stop()

    def start(self):
        self._server.listen(1)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._conn is not None:
            try:
                self._conn.close()
            except OSError:
                pass
        for client in self._clients:
            try:
                client.close()
            except OSError:
                pass
        try:
            self._server.close()
        except OSError:
            pass
        if self._thread.is_alive():
            self._thread.join(timeout=1)

    def create_handle(self, *, timeout=0.1, max_to_read=1000):
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(timeout)
        client.connect(self.address)
        self._clients.append(client)
        return {
            "socket": client,
            "max_data_from_automation_server": max_to_read,
            "sleep_time": 0,
            "max_wait_time": 1,
            "log": [],
        }

    def _serve(self):
        try:
            conn, _ = self._server.accept()
        except OSError:
            return
        self._conn = conn
        conn.settimeout(0.1)
        for response in self._connect_responses:
            conn.sendall(response)

        while not self._stop_event.is_set():
            try:
                data = conn.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            if not data:
                break
            self.received.append(data)
            if self._responses:
                response = self._responses.pop(0)
                if response is not None:
                    conn.sendall(response)
        try:
            conn.close()
        except OSError:
            pass
