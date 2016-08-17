#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <thread>

using namespace std;

#include "UdpSocket.h"
#include "CrossLib.h"

using namespace CrossLib;

UdpSocket sock;

#define UCLOG(x,...) UCLOG_FUNC("[%-14s] " x "\r\n", __FUNCTION__, ##__VA_ARGS__)
#define UCLOGF() UCLOG_FUNC("[%-14s] ", __FUNCTION__)
#define UCLOGNL(x,...) UCLOG_FUNC(x, ##__VA_ARGS__)

#define ERROR_OK               0
#define ERROR_TIMEOUT         -1
#define ERROR_NOSPACE         -2
#define ERROR_CONNECTION_LOST -3

#define FLAG_DATA    1
#define FLAG_ACK     2
#define FLAG_SYN     4
#define FLAG_SYNACK  8
#define FLAG_RST     16

const uint32_t TIME_WAIT_FOR_ACK = 200;
const int MAX_RETRANSMISSIONS = 10;

#pragma pack(1)
struct Header {
	uint16_t sessId;
	uint8_t id;
	uint8_t flags;

	void print()
	{
		UCLOGNL("Header sessId: %d id: %d flags:", sessId, id);
		if (flags & FLAG_DATA) UCLOGNL(" DATA");
		if (flags & FLAG_ACK) UCLOGNL(" ACK");
		if (flags & FLAG_SYN) UCLOGNL(" SYN");
		if (flags & FLAG_SYNACK) UCLOGNL(" SYNACK");
		if (flags & FLAG_RST) UCLOGNL(" RST");
	}
};
#pragma pack()

class UdpConn {
	char ip[16];
	uint16_t port;
	UdpSocket sock;

	uint16_t sessId;

	RecursiveMutex accessMutex;
	CondVar sendCondVar;
	CondVar recvCondVar;

	// sending
	Mutex sendMutex;
	uint8_t lastSendId;
	uint8_t lastSendAcked;
	uint64_t lastPingSendTime;

	// receiving
	bool isInBufFree, connectionLostEvent;
	Mutex readMutex;
	uint8_t lastReceivedId;
	uint64_t lastPacketRecvTime;

	uint8_t outBuf[1200];
	uint8_t inBuf[1200];
	uint8_t dataBuf[1200];
	int dataBufLen;

public:
	UdpConn(const char* ip, uint16_t port);

	void init();

	int connect(uint32_t timeout);

	int send(const void* data, int len, uint32_t timeout);
	int recv(void* data, int len, uint32_t timeout);

	void run();

	void processPacket(int len);
	void tmr();

	void _sendAck();
	void _sendPing();

	uint8_t getNextSendId(bool reset = false)
	{
		MutexGuard guard(accessMutex);
		if (reset)
			lastSendId = 0;
		else
			lastSendId++;
		return lastSendId;
	}
};

UdpConn::UdpConn(const char* ip, uint16_t port)
{
	strcpy(this->ip, ip);
	this->port = port;

	lastSendId = 0;
	isInBufFree = true;
	sessId = 0;
}

void UdpConn::init()
{
	sock.init();
}

int UdpConn::connect(uint32_t timeout)
{
	MutexGuard guard(sendMutex);

	Header* header = (Header*)outBuf;
	header->sessId = 0;
	header->id = getNextSendId(true);
	header->flags = FLAG_SYN;

	uint64_t startTime = OS::getTime();
	while (OS::getTime() - startTime < timeout) {
		UCLOG("sending SYN");
		sock.send(ip, port, header, sizeof(Header));

		UCLOG("waiting for SYNACK");
		MutexGuard guard(accessMutex);
		if (sendCondVar.waitFor(guard, TIME_WAIT_FOR_ACK, [this]() { return sessId != 0; })) {
			UCLOG("connection ACKed");
			connectionLostEvent = false;
			return 0;
		} else {
			UCLOG("connection attempt timed out, resending");
		}
	}
	UCLOG("connection timed out");
	return ERROR_TIMEOUT;
}

int UdpConn::send(const void* data, int len, uint32_t timeout)
{
	MutexGuard guard(sendMutex);

	Header* header = (Header*)outBuf;
	memcpy(outBuf + sizeof(Header), data, len);
	header->id = getNextSendId();
	header->flags = FLAG_DATA;

	int sendLen = sizeof(Header) + len;

	uint64_t startTime = OS::getTime();
	while (OS::getTime() - startTime < timeout) {
		UCLOG("sending DATA");
		sock.send(ip, port, outBuf, sendLen);

		UCLOG("waiting for ACK");
		MutexGuard guard(accessMutex);
		if (sendCondVar.waitFor(guard, TIME_WAIT_FOR_ACK, [this, &header]() { return lastSendAcked == header->id || connectionLostEvent; })) {
			if (lastSendAcked == header->id) {
				UCLOG("send ACKed");
				return ERROR_OK;
			} else if (connectionLostEvent) {
				UCLOG("connection lost event received");
				connectionLostEvent = false;
				return ERROR_CONNECTION_LOST;
			}
		} else {
			UCLOG("send attempt timed out, resending");
		}
	}
	UCLOG("send timed out");
	return ERROR_TIMEOUT;
}
int UdpConn::recv(void* data, int len, uint32_t timeout)
{
	MutexGuard guard(accessMutex);
	if (recvCondVar.waitFor(guard, timeout, [this]() { return !isInBufFree || connectionLostEvent; })) {
		if (!isInBufFree) {
			if (len < dataBufLen)
				return ERROR_NOSPACE;

			memcpy(data, dataBuf, dataBufLen);
			isInBufFree = true;

			UCLOG("recv got");
			return dataBufLen;
		} else if (connectionLostEvent) {
			UCLOG("connection lost event received");
			connectionLostEvent = false;
			return ERROR_CONNECTION_LOST;
		} else {
			return -999;
		}
	} else {
		UCLOG("recv timed out!");
		// retransmissions++;
		return 0;
	}
}

void UdpConn::run()
{
	char rip[16];
	uint16_t rport;
	for (;;) {
		int r = sock.recv(rip, rport, inBuf, sizeof(inBuf), 200);
		if (r >= 1200)
			continue;

		if (r > 0) {
			processPacket(r);
		} else {
			tmr();
		}
	}
}

void UdpConn::processPacket(int len)
{
	MutexGuard guard(accessMutex);
	Header *h = (Header*)inBuf;
	UCLOGF();
	UCLOGNL("received ["); h->print(); UCLOGNL("]\r\n");

	if (h->flags & FLAG_RST) {
		UCLOG("connection reset received");
		connectionLostEvent = true;
		sessId = 0;
		recvCondVar.notifyOne();
		return;
	}

	if (h->flags & FLAG_SYNACK) {
		sessId = h->sessId;
		lastReceivedId = h->id;
		sendCondVar.notifyOne();
		UCLOG("got new sessId %u", sessId);
		// lastPacketRecvTime =  OS::getTime();
		// lastReceivedId = 0f;
		lastPacketRecvTime = lastPingSendTime = OS::getTime();
		return;
	}

	if (sessId == 0) {
		UCLOG("no connection");
		return;
	}

	// connected to server

	if (h->sessId != sessId) {
		UCLOG("connection lost");
		connectionLostEvent = true;
		sessId = 0;
		recvCondVar.notifyOne();
		return;
	}

	if (h->flags & FLAG_DATA) {
		uint8_t diff = h->id - lastReceivedId;
		if (diff == 1) {
			int payloadLen = len - sizeof(Header);
			if (payloadLen > 0) {
				if (isInBufFree) {
					lastReceivedId = h->id;
					dataBufLen = payloadLen;
					memcpy(dataBuf, inBuf + sizeof(Header), dataBufLen);
					isInBufFree = false;
					recvCondVar.notifyOne();
					UCLOG("saved data %d", dataBufLen);
				} else {
					// no space in input data buffer, packet is ignored
					UCLOG("no space in input buffer");
					return;
				}
			}
		} else {
			UCLOG("skipping packet got %d last %d (%d)", h->id, lastReceivedId, diff);
		}
		lastPacketRecvTime =  OS::getTime();
		UCLOG("sending ack");
		_sendAck();
	}

	if (h->flags & FLAG_ACK) {
		lastSendAcked = h->id;
		sendCondVar.notifyOne();
		lastPacketRecvTime = OS::getTime();
	}
}
void UdpConn::tmr()
{
	MutexGuard guard(accessMutex);

	// connected
	if (sessId != 0) {
		if (OS::getTime() - lastPingSendTime >= 1000) {
			if (OS::getTime() - lastPacketRecvTime >= 1000) {
				UCLOG("sending ping");
				_sendPing();
				lastPingSendTime = OS::getTime();
			}
		}
		if (OS::getTime() - lastPacketRecvTime >= 3000) {
			UCLOG("connection lost");
			connectionLostEvent = true;
			sessId = 0;
			sendCondVar.notifyOne();
			recvCondVar.notifyOne();
		}
	}
}

void UdpConn::_sendAck()
{
	Header h;
	h.sessId = sessId;
	h.id = lastReceivedId;
	h.flags = FLAG_ACK;

	sock.send(ip, port, &h, sizeof(h));
}
void UdpConn::_sendPing()
{
	Header h;
	h.sessId = sessId;
	h.id = getNextSendId();
	h.flags = FLAG_DATA;

	sock.send(ip, port, &h, sizeof(h));
}
