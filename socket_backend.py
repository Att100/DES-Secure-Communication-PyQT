import socket
import os
import struct
import json
from typing import Tuple
import threading
import traceback
import time


def getTime() -> str:
    """
    METHOD: getTime

    description: get current time
    """
    _time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    return "[{}] ".format(_time)


class InnerClientSocket:
    """
    CLASS: InnerClientSocket

    description: support all the basic socket functions such as the sending, 
                 receiving of file and message.
    """
    def __init__(self, client_socket: socket.socket, client_addr: Tuple) -> None:
        """
        METHOD: __init__

        description: constructor
        """
        self.client_init_status: bool = False
        self.username = ""
        self.client_address: str = str(client_addr[0]) if client_addr[0] is not None else client_addr[0]
        self.client_port: int = int(client_addr[1]) if client_addr[1] is not None else client_addr[1]
        self.client_socket: socket.socket = client_socket

    def sock(self) -> socket.socket:
        """
        METHOD: sock

        description: return the socket
        """
        return self.client_socket

    def send(self, msg: bytes, head: bool=True):
        """
        METHOD: send

        description: send message 
        """
        if not head:
            # transmit message without protocol
            self.client_socket.sendall(msg)
        else:
            headers = {'msg_size': len(msg)}
            head_json = json.dumps(headers)
            head_json_bytes = bytes(head_json, encoding='utf-8')
            self.client_socket.send(struct.pack('i',len(head_json_bytes)))
            self.client_socket.send(head_json_bytes)
            self.client_socket.sendall(msg)

    def send_file(self, path: str, _filename: str = None):
        """
        METHOD: send_file

        description: send a file (NOT USED IN SERVER IMPLEMENTATION)
        """
        if _filename is not None:
            filename = _filename
        else:
            # if _filename is None, use the original file name
            filename = os.path.basename(path)
        filesize = os.path.getsize(path)
    
        head = {"filename": filename, "size": filesize}
        head_info = json.dumps(head)
        head_info_len = struct.pack('i', len(head_info))

        self.client_socket.send(head_info_len)
        self.client_socket.send(head_info.encode('utf-8'))

        # read file and send 
        with open(path, 'rb') as f:
            data = f.read()
            self.client_socket.sendall(data)
    

    def recv_file(self, path: str, name: str = None) -> str:
        """
        METHOD: recv_file

        description: recieve a file and return the filename (NOT USED IN SERVER IMPLEMENTATION)
        """
        head_len = struct.unpack('i', self.client_socket.recv(4))[0]
        head = json.loads(self.client_socket.recv(head_len).decode("utf-8"))

        filename = head["filename"]
        filesize = head["size"]

        recv_len = 0
        recv_mesg = b''
        if name is None:
            # if name is None, use the recieved file name
            f = open(os.path.join(path, filename), 'wb')
        else:
            f = open(os.path.join(path, name), 'wb')

        # start to recieve file
        while recv_len < filesize:
            if filesize - recv_len > 1024:
                recv_mesg = self.client_socket.recv(1024)
                f.write(recv_mesg)
                recv_len += len(recv_mesg)
            else:
                recv_mesg = self.client_socket.recv(filesize - recv_len)
                recv_len += len(recv_mesg)
                f.write(recv_mesg)
        f.close()
        return filename

    def recv(self, buffer_size: int=1024, head: bool=True) -> bytes:
        """
        METHOD: recv

        description: receive message and return the bytes
        """
        if not head:
            # receive message without protocol
            return self.client_socket.recv(buffer_size)
        else:
            try:
                head_len = struct.unpack('i', self.client_socket.recv(4))[0]
                head_json = json.loads(self.client_socket.recv(head_len).decode('utf-8'))
                data_len = head_json['msg_size']

                # start to receive message
                recv_size=0
                recv_data=b''
                while recv_size < data_len:
                    if data_len - recv_size >= 1024:
                        re_data = self.client_socket.recv(buffer_size)
                    else:
                        re_data = self.client_socket.recv(data_len - recv_size)
                    recv_data += re_data
                    recv_size += len(re_data)
                return recv_data
            except:
                return None


class Server(object):
    """
    CLASS: Server

    description: the Server class, implentation of all the functions of main server
    """
    def __init__(self, address: str, port: int, max_n_client: int = 100) -> None:
        """
        METHOD: __init__

        description: constructor
        """
        super().__init__()

        self.client_socket_pool = {}  # {"username": <InnerClientSocket>}
        self.server_address: str = address
        self.server_port: int = port
        self.max_n_client = max_n_client
        self.server_socket: socket.socket = None

        self.log_callback = None

    def set_callback(self, log_callback):
        self.log_callback = log_callback

    def start(self):
        """
        METHOD: start

        description: start P2P main server
        """
        self.server_socket = socket.socket()               
        self.server_socket.bind((self.server_address, self.server_port))
        self.server_socket.listen(self.max_n_client)
        self.log_callback("server start", 0)

        while True:
            c, addr = self.server_socket.accept()
            client_obj = InnerClientSocket(c, addr)
            t = threading.Thread(target=self.clientThread, args=(client_obj,))
            t.start()

    def clientThread(self, _client_sock: InnerClientSocket):
        """
        METHOD: clientThread

        description: handle the communication between a peer and main server
        """
        client_sock = _client_sock
        while True:
            try:
                # wait for the message from peer
                recv_data = client_sock.recv()
                if not recv_data:
                    self.close_client_connection(client_sock)
                    break
                msg_data = json.loads(recv_data.decode("UTF-8"))
                if msg_data["code"] == 0:
                    client_sock.username = msg_data["username"]
                    self.client_socket_pool[msg_data["username"]] = client_sock
                    self.log_callback("{} connected".format(msg_data["username"]), 0)
                elif msg_data["code"] == 1:
                    for key, client in self.client_socket_pool.items():
                        client.send(recv_data)
                elif msg_data["code"] == 2:
                    file_name = client_sock.recv_file("./cache", "cache_server_recv.des")
                    for key, client in self.client_socket_pool.items():
                        client.send(recv_data)
                        client.send_file("./cache/cache_server_recv.des")
            except:
                traceback.print_exc()
                self.close_client_connection(client_sock)

    def close_client_connection(self, client_sock: InnerClientSocket):
        """
        METHOD: close_client_connection

        description: close the connetion with peer
        """
        client_sock.sock().close()
        self.log_callback("user {} is offline".format(client_sock.username), 0)
        response = self.client_socket_pool.pop(str(client_sock.username), None)

    def close_all(self):
        self.server_socket.close()


class Client(object):
    """
    CLASS: Client

    description: the backend of Client, the collection of all the main functions which
                 contains communication with main server and communication
    """
    def __init__(self, server_address: str, server_port: int, username: str) -> None:
        """
        METHOD: __init__

        description: constructor
        """

        super().__init__()

        self.server_address: str = server_address
        self.server_port: int = server_port
        self.username = username
        self.client_socket: InnerClientSocket = None

        self.log_callback = None
        self.table_callback = None

    def set_callbacks(self, log_callback, table_callback):
        self.log_callback = log_callback
        self.table_callback = table_callback

    def connect_server(self):
        """
        METHOD: connect_server

        description: connect the main server
        """
        try:
            self.client_socket = InnerClientSocket(socket.socket(), (None, None))
            self.client_socket.client_socket.connect((self.server_address, self.server_port))
            self.client_socket.send(json.dumps({"code": 0, "username": self.username}).encode("UTF-8"))
            self.log_callback("server connected", 0)
        except:
            traceback.print_exc()
            self.log_callback("network or server is down", -1)

    def listen_server(self, callback):
        """
        METHOD: listen_server

        description: monitored the message from main server
        """
        while True:
            try:
                recv_data = self.client_socket.recv()
                if not recv_data:
                    self.client_socket.sock().close()
                    break
                recv_msg = json.loads(recv_data.decode("UTF-8"))
                if recv_msg["code"] == 0:
                    pass
                elif recv_msg["code"] == 1:
                    callback(recv_msg)
                elif recv_msg["code"] == 2:
                    filename = self.client_socket.recv_file("./cache", recv_msg["name"]+".des")
                    callback(recv_msg)
            except: 
                traceback.print_exc()
                break

    def send_msg(self, msg: str):
        self.client_socket.send(json.dumps(
            {"code": 1, "msg": msg, "username": self.username, "type": "text"}).encode("UTF-8"))

    def close_all(self):
        """
        METHOD: close_all

        description: close the connection
        """
        self.client_socket.sock().close()
