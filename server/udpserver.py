import logging

import abc
import asyncio, struct
import queue
from typing import List
import threading

import datetime
import random
import time
from colorama import Fore

FLAG_DATA = 1
FLAG_ACK = 2
FLAG_SYN = 4
FLAG_SYNACK = 8
FLAG_RST = 16
FLAG_PING = 32

MAX_PACKET_SIZE = 1200
SEND_TIMEOUT = 5000 / 1000
TIME_WAIT_FOR_ACK = 200 / 1000
TIME_MIDDLE_PACKET = 20 / 1000

ERROR_OK = 0
ERROR_TIMEOUT = -1
ERROR_NOSPACE = -2
ERROR_CONNECTION_LOST = -3

MAX_ID = 0xffff
HALF_ID = MAX_ID / 2


def uint8diff(a, b):
    if a >= b:
        return a - b
    else:
        return 256 - b + a


def uint16diff(a, b):
    if a >= b:
        return a - b
    else:
        return 256 * 256 - b + a


def get_date_str():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")


class Header:
    FMT = "<HHB"

    sessId = 0  # type; int
    id = 0  # type: int
    lastReceived = 0  # type: int
    flags = 0  # type: int

    def __str__(self):
        flags_str = []
        if self.flags & FLAG_DATA: flags_str.append("DATA")
        if self.flags & FLAG_ACK: flags_str.append("ACK")
        if self.flags & FLAG_SYN: flags_str.append("SYN")
        if self.flags & FLAG_SYNACK: flags_str.append("SYNACK")
        if self.flags & FLAG_RST: flags_str.append("RST")
        if self.flags & FLAG_PING: flags_str.append("PING")
        return "Header sessId: {0} id: {1}, flags: {2}".format(self.sessId, self.id, ' '.join(flags_str))

    def to_binary(self):
        return struct.pack(Header.FMT, self.sessId, self.id, self.flags)

    @staticmethod
    def get_len():
        return struct.calcsize(Header.FMT)

    @staticmethod
    def from_binary(data: bytes, offset: int) -> 'Header':
        h = Header()
        (h.sessId, h.id, h.flags) = struct.unpack_from(Header.FMT, data, offset)
        return h


class UdpConnClient:
    ip = None  # type: str
    port = None  # type: int
    srv = None  # type: UdpConnServer
    to_delete = False  # type: bool

    access_mutex = None  # type: threading.Lock

    sess_id = None  # type: int
    disconnection_event = False  # type: bool

    # sending
    last_send_id = 0  # type: int
    last_send_acked = None  # type: int
    send_cond_var = None  # type: threading.Condition

    # receiving
    last_received_id = None  # type: int
    last_received_time = None  # type: int

    def log(self, x):
        logging.info("[{}] {}[client {}:{}]{} {}".format(get_date_str(), Fore.LIGHTMAGENTA_EX, self.ip, self.port, Fore.RESET, x))

    def __init__(self, srv: 'UdpConnServer', ip: str, port: int) -> None:
        self.srv = srv
        self.ip = ip
        self.port = port
        self.access_mutex = threading.Lock()
        self.send_cond_var = threading.Condition(self.access_mutex)
        # self.last_received_id = 0
        self.sess_id = 0

    @abc.abstractmethod
    def on_connected(self):
        pass

    @abc.abstractmethod
    def on_disconnected(self):
        pass

    @abc.abstractmethod
    def on_new_packet(self, payload):
        pass

    def get_next_send_id(self, reset=False):
        with self.access_mutex:
            if reset:
                self.last_send_id = random.randint(0, MAX_ID)
            else:
                if self.last_send_id == MAX_ID:
                    self.last_send_id = 0
                else:
                    self.last_send_id += 1
            return self.last_send_id

    def mark_disconnection(self, send_rst=True):
        if send_rst:
            self._send_rst()
        self.on_disconnected()
        self.sess_id = 0
        self.to_delete = True
        with self.access_mutex:
            self.disconnection_event = True
            self.send_cond_var.notify()

    def process_packet(self, packet: bytes) -> None:  # in main thread
        hl = Header.get_len()
        h = Header.from_binary(packet, 0)
        payload = packet[hl:]

        self.log("received: [{0}] len: {1}".format(h, len(payload)))

        if h.flags & FLAG_SYN:
            if self.sess_id != 0:
                self.log("connection already established")
                self.mark_disconnection(send_rst=False)
                return

            self.sess_id = random.randint(1, 2 ** 16 - 1)
            self.last_send_acked = None
            self.last_received_id = h.id
            self.last_received_time = time.time()
            self.log("creating new connection with sessId: {0}".format(self.sess_id))
            send_id = self.get_next_send_id(reset=True)
            self._send_packet(self.sess_id, send_id, FLAG_SYNACK)
            self.on_connected()
            return

        if self.sess_id == 0:
            self.log("connection not established but got packet other than SYN")
            self._send_rst()
            self.to_delete = True
            return

        # client is connected

        if h.sessId != self.sess_id:
            self.log("invalid sessId")
            self.mark_disconnection()
            return

        if h.flags & FLAG_PING:
            self.log("answering to PING")
            self._send_packet(self.sess_id, 0, FLAG_PING)
            self.last_received_time = time.time()
            return

        if h.flags & FLAG_DATA:
            if uint16diff(h.id, self.last_received_id) == 1:
                self.last_received_id = h.id
                if len(payload) > 0:
                    self.on_new_packet(payload)
            else:
                self.log("skipping packet got {0} last {1}".format(h.id, self.last_received_id))
            self.last_received_time = time.time()
            self._send_ack()
            return

        if h.flags & FLAG_ACK:
            self.last_received_time = time.time()
            with self.access_mutex:
                if self.last_send_acked is None or uint16diff(h.id, self.last_send_acked) == 1:
                    self.last_send_acked = h.id
                    self.send_cond_var.notify()
                    self.log("received ACK for {0}".format(self.last_send_acked))
                else:
                    diff = uint16diff(h.id, self.last_send_acked)
                    if diff < HALF_ID:  # skipped lot of packets
                        self.log("invalid ACK for {0} last {1}".format(h.id, self.last_send_acked))
                        self.mark_disconnection()
                    else:  # duplicated ACK (already recevied)
                        self.log("duplicated ACK for {0} last {1}".format(h.id, self.last_send_acked))

            return

    def _send_ack(self) -> None:
        self.log("sending ACK ({0})".format(self.last_received_id))
        self._send_packet(self.sess_id, self.last_received_id, FLAG_ACK)

    def _send_rst(self) -> None:
        self._send_packet(0, 0, FLAG_RST)

    def _send_packet(self, sess_id: int, id: int, flags: int):
        h = Header()
        h.sessId = sess_id
        h.id = id
        h.flags = flags
        self._send(h.to_binary())

    def _send(self, data: bytes) -> None:
        self.srv.send(data, self.ip, self.port)

    def send(self, packets_payload: List[bytes]):  # in any thread context

        if self.sess_id == 0:
            return ERROR_CONNECTION_LOST

        packets = []
        for payload in packets_payload:
            h = Header()
            h.sessId = self.sess_id
            send_id = self.get_next_send_id()
            h.id = send_id
            h.flags = FLAG_DATA

            out_data = h.to_binary() + payload

            packets.append((h, out_data))

        start_time = time.time()
        while time.time() - start_time < SEND_TIMEOUT:

            def has_been_acked(p):
                return self.last_send_acked is not None and uint16diff(self.last_send_acked, p[0].id) < HALF_ID

            for p in packets:
                if not has_been_acked(p):
                    self.log("sending [{0}] len: {1}".format(p[0], len(p[1])))
                    self._send(p[1])
                    time.sleep(TIME_MIDDLE_PACKET)

            self.log("waiting for ACK")
            self.send_cond_var.acquire()

            def has_all_been_acked():
                return all(has_been_acked(x) for x in packets)

            def cond_predicate():
                return has_all_been_acked() or self.disconnection_event

            if self.send_cond_var.wait_for(cond_predicate, TIME_WAIT_FOR_ACK):
                if has_all_been_acked():
                    self.log("send acked")
                    self.send_cond_var.release()
                    return ERROR_OK
                elif self.disconnection_event:
                    self.log("send: disconnection event")
                    self.send_cond_var.release()
                    self.disconnection_event = False
                    return ERROR_CONNECTION_LOST
            else:
                self.log("short timed out")
                self.send_cond_var.release()

        # send timeout, disconnecting
        self.log("big timed out")

        self.mark_disconnection()

        return ERROR_TIMEOUT

    def tmr(self):  # in main thread
        self.log("TMR")
        if self.sess_id != 0 and time.time() - self.last_received_time > 3:
            self.log("ping timeout")
            self.mark_disconnection()


class UdpConnServer:
    transport = None
    client_cls = None
    clients = []  # type: List[UdpConnClient]
    incoming_queue = None  # type: queue.Queue

    def log(self, x):
        logging.info("[{}] {}[server]{} {}".format(get_date_str(), Fore.YELLOW, Fore.RESET, x))

    def __init__(self, client_cls):
        self.client_cls = client_cls

    def process_packet(self, packet: bytes, ip: str, port: int) -> None:
        if len(packet) > MAX_PACKET_SIZE:
            self.log("too long packet")
            return

        self.log("received from {0}:{1}".format(ip, port))

        client = self.find_client(ip, port)
        if client is None:
            client = self.client_cls(self, ip, port)
            self.log("new client connected from {0}:{1}".format(ip, port))
            self.clients.append(client)
        client.process_packet(packet)

    def find_client(self, ip: str, port: int) -> UdpConnClient:
        for client in self.clients:
            if client.ip == ip and client.port == port and not client.to_delete:
                return client
        return None

    def connection_made(self, transport):
        self.transport = transport
        self.incoming_queue = queue.Queue()
        loop = asyncio.get_event_loop()  # type: BaseEventLoop
        loop.call_later(1, self.tmr)

    def tmr(self):
        loop = asyncio.get_event_loop()  # type: BaseEventLoop
        loop.call_later(1, self.tmr)

        for c in self.clients:
            c.tmr()

        self.clients = list(filter(lambda x: not x.to_delete, self.clients))

    def datagram_received(self, data, addr):
        self.process_packet(data, addr[0], addr[1])

    def send(self, data: bytes, ip: str, port: int):
        self.transport.sendto(data, (ip, port))
