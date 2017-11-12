import base64
import os
import socket

import six

# for matching in the Codec class
if six.PY3:
    START_CHAR = 37  # 37 == %
    END_CHAR = 36  # 36 == $
else:
    START_CHAR = '%'
    END_CHAR = '$'


class Codec():
    """A very simple codec that bounds messages with a start char of '%' and an
    end char of '$'.  The message itself mustn't contain either of these
    characters, and this is ensured by encoding the message using base64 (which
    doesn't contain either of those characters).

    This is for sending over a unix domain socket which has interesting
    buffering -- this makes sure we can reconstruct entire messages between two
    processes.
    """

    def __init__(self):
        self.found_start = -1
        self.message = None
        self.buffer = b''

    def _add(self, bites):
        """Add some bytes to the buffer: called from receive()

        It looks for the beginning and end of a message, and if found returns
        the encoded buffer without the '%' and '$' markers.

        :param bites: the bytes to add to the buffer and search for a message
        :type bites: bytes
        :returns: Either a b64encoded message, or None
        :rtype: Option[bytes, None]
        """
        # current = len(self.buffer)
        self.buffer += bites
        if self.found_start < 0:
            # skip till we found a '%'
            for i, b in enumerate(self.buffer):
                if b == START_CHAR:
                    self.found_start = i
                    break
        if self.found_start > -1:
            # see if the end of the message is available
            for i, b in enumerate(self.buffer):
                if i > self.found_start + 1 and b == END_CHAR:
                    # found the end
                    start = self.found_start + 1
                    self.message = (base64
                                    .b64decode(self.buffer[start:i])
                                    .decode('UTF-8'))
                    self.buffer = self.buffer[i + 1:]
                    self.found_start = -1
                    return self.message
        return None

    def receive(self, _callable):
        """Continuously calls the param _callable() until it returns None or a
        full message is received.

        If the message is already in the buffer, then it grabs it and doesn't
        call the _callable().

        _callable() should return bytes until it wants receive() to terminate,
        when it should return None.  receive() also returns when a message is
        complete.

        receive() will return a decoded UTF-8 string when a complete message is
        received.

        Any left over bytes are retained in the Codec object, and further calls
        to receive() will consume these first.

        :param _callable: A function that returns None or bytes
        :type _callable: Callable()
        :returns: None or a UTF-8 decoded string
        :rtype: Option[None, str]
        """
        # first see if the message is already in the buffer?
        message = self._add(b'')
        if message:
            return message
        while True:
            # receive the data in chunks
            data = _callable()
            if data:
                message = self._add(data)
                if message:
                    return message
            else:
                break
        return None

    def encode(self, message):
        """Encode a message for sending on a channel with inconsistent
        buffering (e.g. like a unix domain socket.

        Encodes the message by UTF-8, then base64 and finally adds '%' and '$'
        to the start and end of the message.  This is so the message can be
        recovered by searching through a receiving buffer.

        :param message: The string that needs encoding.
        :type message: str
        :returns: the encoded message
        :rtype: bytes
        """
        buffer = base64.b64encode(message.encode('UTF-8'))
        return b"%" + buffer + b"$"


# client and socket classes for the channel
#
# The Client connects to the server, and performs a READY handshake as part of
# the connect().  The server has to respond 'OK'.  Once this is done the client
# and server are synchronised.  Note that it is a one-to-one, synchronised
# connection with client and server exchanging messages.  The theory is that
# the server initiates the Server, to bind to the socket, launches the script
# and then waits for the connection.  There is no race as the client will wait
# until the servers calls wait_for_connection() which can be after the client
# has connected to the socket.
#
# The server then sends a "QUIT" to the client to get it to clean up and exit
# (but this is outside of the protocol in the Client() and Server() classes

class UDSException(Exception):
    """Used to gather up all exceptions and return a single one so that the
    client/server can error out on comms failures.
    """


class UDSClient():
    """Unix Domain Socket Client class.

    Provides a synchronised message/receive client for connecting to the
    equivalent UDSServer() running in a different process.

    The client/server is backwards, as the UDSClient() is expecting to receive
    a message, which its user will then reply with a result.  i.e. the Client
    is implemented in a process that expects to get commands from the server.
    This is so that the server can launch a child script, communicate with it,
    and then terminate it when finished.

    Example use:

        client = Client(server_address)
        client.connect()

        message = client.receive()
        if message == "DONE":
            client.close()
            return
        client.send("OK")
        # etc.
    """

    BUFFER_SIZE = 256

    def __init__(self, socket_path):
        """Initialise the Client.

        :param socket_path: the file to use as a Unix Domain Socket
        :type socket_path: str
        :raises: UDSException on Error
        """
        self.socket_path = socket_path
        try:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        except Exception as e:
            raise UDSException(str(e))
        self.codec = Codec()

    def connect(self):
        """Attempt to connect to the other side.
        When the connection is made, automatically calls _ready() to indicate
        that the client is ready as part of the handshake.  When connect()
        completes the user should call receive() to receive the first message
        from the server.

        :raises: UDSException on Error
        """
        try:
            self.sock.connect(self.socket_path)
            self._ready()
        except Exception as e:
            raise UDSException(str(e))

    def _ready(self):
        """Internal method to provide a handshake to the server"""
        self.sock.sendall(self.codec.encode("READY"))
        message = self.receive()
        if message != "OK":
            raise RuntimeError("Handshake failed")

    def receive(self):
        """Receives a message from the Server() in the other process on the
        other end of the UDS.  Uses the Codec() class to ensure that the
        messages are properly received and sent.

        :returns: the string send by the Server.send() methdod.
        :rtype: str
        :raises: UDSException on Error
        """
        try:
            return self.codec.receive(
                lambda: self.sock.recv(self.BUFFER_SIZE))
        except Exception as e:
            raise UDSException(str(e))

    def send(self, buffer):
        """Send a message to the Server() in the other process.

        :param buffer: the string to send
        :type buffer: str
        :raises: UDSException on Error
        """
        try:
            self.sock.sendall(self.codec.encode(buffer))
        except Exception as e:
            raise UDSException(str(e))

    def close(self):
        """Close the socket -- good housekeeping, so should do it at the end of
        the process.
        :raises: UDSException on Error
        """
        try:
            self.sock.close()
        except Exception as e:
            raise UDSException(str(e))


class UDSServer():
    """The Server (or listening) end of the Unix Domain Socket chat protocol.
    Uses Codec() to encode and decode messages on the channel.

    The Server listens for a connection, performs a handshake, and then is in
    control of the conversation.  The user of Server() should then send a
    message and wait for a reponse.  It's up to the client to disconnect, so an
    protocol level message should be used (e.g. QUIT) that the user of Client()
    will use to close the connection.

    Example use:

        server = Server(server_address)
        input("Press enter to continue ....")
        server.wait_for_connection()
        try:
            # send some data
            server.send(data)
            # and await the reply
            message = server.receive()
        finally:
            # clean up
            server.send("DONE")
            message = server.receive()
            server.close()
    """

    BUFFER_SIZE = 256

    def __init__(self, socket_path):
        """Initialise the listener on the UDS.  This binds to the socket and
        ensures that a client can connect.  The conversation doesn't get
        started until the wait_for_connection() method is called.

        The server can initialse the Server, then ask the client to connect,
        and then at any point later call wait_for_connection() to get the
        conversation going.

        :param socket_path: the filename for the UDS.
        :type socket_path: str
        :raises: UDSException on Error
        """
        self.socket_path = socket_path
        self.sock = None
        # Make sure the socket does not already exist
        try:
            os.unlink(socket_path)
        except OSError:
            if os.path.exists(socket_path):
                raise
        try:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            # ensure the socket is created with 600 permissions
            _mask = os.umask(0o177)
            self.sock.bind(socket_path)
            os.umask(_mask)
            self.sock.listen(1)
        except Exception as e:
            raise UDSException(str(e))
        self.codec = Codec()

    def wait_for_connection(self):
        """Blocking method to wait for a connection from the client.

        Performs the handshake to ensure that both ends are in sync.
        :raises: UDSException on Error
        """
        try:
            self.connection, self.client_address = self.sock.accept()
            self._handshake()
        except Exception as e:
            raise UDSException(str(e))

    def _handshake(self):
        """Internal method to sync up the client and server"""
        while True:
            message = self.receive()
            if message == 'READY':
                self.send('OK')
                break

    def receive(self):
        """Receives a message from the Client() in the other process on the
        other end of the UDS.  Uses the Codec() class to ensure that the
        messages are properly received and sent.

        :returns: the string send by the Client.send() methdod.
        :rtype: str
        :raises: UDSException on Error
        """
        try:
            return self.codec.receive(
                lambda: self.connection.recv(self.BUFFER_SIZE))
        except Exception as e:
            raise UDSException(str(e))

    def send(self, buffer):
        """Send a message to the Client() in the other process.

        :param buffer: the string to send
        :type buffer: str
        :raises: UDSException on Error
        """
        try:
            self.connection.sendall(self.codec.encode(buffer))
        except Exception as e:
            raise UDSException(str(e))

    def close(self):
        """Close the socket -- good housekeeping, so should do it at the end of
        the process.
        :raises: UDSException on Error
        """
        try:
            self.connection.close()
        except Exception as e:
            raise UDSException(str(e))
