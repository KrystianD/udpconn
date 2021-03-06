#include "UdpConn.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define UCLOG(x,...)   UCLOG_FUNC("[%-14s] " x "\r\n", __FUNCTION__, ##__VA_ARGS__)
#define UCLOGF()       UCLOG_FUNC("[%-14s] ", __FUNCTION__)
#define UCLOGNL(x,...) UCLOG_FUNC(x, ##__VA_ARGS__)

#define ERROR_OK               0
#define ERROR_TIMEOUT         -1
#define ERROR_NOSPACE         -2
#define ERROR_CONNECTION_LOST -3
#define ERROR_INVALID_STATE   -4

#define DUMPHEADER(a,b,c) dumpHeader(__FUNCTION__,a,b,c);
void dumpHeader(const char* func, const char* prefix, Header* header, int len)
{
	UCLOGNL("[%-14s] %-12s [", func, prefix);
	header->print();
	if (len != -1)
		UCLOGNL("] UDP len: %d\r\n", len);
	else
		UCLOGNL("]\r\n");
}

UdpConn::UdpConn()
{
	lastSendId = 0;
	isInBufEmpty = true;
	isInBufReceived = true;
	sessId = 0;
}

void UdpConn::init()
{
	sock.init();
	UCLOG("created socket with fd %d", sock.getFd());
}

int UdpConn::connect(const InetAddress& addr, uint32_t timeout)
{
	this->addr = addr;

	UCLOG("connecting to %s:%d", addr.ip().str(), addr.port());

	MutexGuard guard(sendMutex);

	accessMutex.lock();
	sessId = 0;
	accessMutex.unlock();

	Header* header = (Header*)outBuf;
	header->sessId = 0;
	header->id = getNextSendId(true);
	header->flags = FLAG_SYN;

	UCLOG("sending SYN");
	sock.send(addr, header, sizeof(Header));

	UCLOG("waiting for SYNACK");
	MutexGuard guard2(accessMutex);
	if (sendCondVar.waitFor(guard2, timeout, [this]() { return sessId != 0; })) {
		UCLOG("connection ACKed");
		return 0;
	} else {
		UCLOG("connection timed out");
		return ERROR_TIMEOUT;
	}
}

int UdpConn::send(const void* data, uint32_t offset, uint32_t len, uint32_t timeout)
{
	MutexGuard guard(sendMutex);

	{
		MutexGuard guard(accessMutex);
		if (sessId == 0)
			return ERROR_INVALID_STATE;
	}

	if (data)
		memcpy(outBuf + sizeof(Header), (uint8_t*)data + offset, len);
	return _sendInternal(len, timeout);
}

int UdpConn::sendBuffer(uint32_t len, uint32_t timeout)
{
	MutexGuard guard(sendMutex);

	{
		MutexGuard guard(accessMutex);
		if (sessId == 0)
			return ERROR_INVALID_STATE;
	}

	return _sendInternal(len, timeout);
}

int UdpConn::_sendInternal(uint32_t len, uint32_t timeout)
{
	// sendMutex acquired
	Header* header = (Header*)outBuf;
	header->sessId = sessId;
	header->id = getNextSendId();
	header->flags = FLAG_DATA;

	int sendLen = sizeof(Header) + len;

	uint64_t startTime = OS::getTime();
	while (OS::getTime() - startTime < timeout) {
		DUMPHEADER("sending", header, len);
		sock.send(addr, outBuf, sendLen);

		UCLOG("waiting for ACK");
		MutexGuard guard(accessMutex);
		auto predicate = [this, &header]() { return lastSendAcked == header->id || sessId == 0; };
		if (sendCondVar.waitFor(guard, TIME_WAIT_FOR_ACK, predicate)) {
			if (lastSendAcked == header->id) {
				UCLOG("send ACKed");
				return ERROR_OK;
			} else if (sessId == 0) {
				UCLOG("connection lost event received");
				return ERROR_CONNECTION_LOST;
			} else {
				return -999;
			}
		} else {
			UCLOG("send attempt timed out, resending");
		}
	}
	UCLOG("send timed out, closing socket");
	_closeInternal();
	return ERROR_TIMEOUT;
}

int UdpConn::recv(void* data, uint32_t offset, uint32_t len, uint32_t timeout)
{
	MutexGuard guard(accessMutex);
	if (sessId == 0)
		return ERROR_INVALID_STATE;

	auto predicate = [this]() { return (!isInBufEmpty && !isInBufReceived) || sessId == 0; };
	if (recvCondVar.waitFor(guard, timeout, predicate)) {
		if (!isInBufEmpty && !isInBufReceived) {
			if (len < dataBufLen)
				return ERROR_NOSPACE;

			if (data) {
				memcpy((uint8_t*)data + offset, inBuf + sizeof(Header), dataBufLen);
				isInBufEmpty = true;
			}
			isInBufReceived = true;

			UCLOG("recv got");
			return dataBufLen;
		} else if (sessId == 0) {
			UCLOG("connection lost event received");
			return ERROR_CONNECTION_LOST;
		} else {
			return -999;
		}
	} else {
		// UCLOG("recv timed out!");
		// retransmissions++;
		return 0;
	}
}

UdpConnSendSession UdpConn::createSendSession()
{
	UdpConnSendSession c(this);
	c.pos = sizeof(Header);
	return c;
}

void UdpConn::releaseInternalBuffer()
{
	MutexGuard guard(accessMutex);
	isInBufEmpty = true;
}

void UdpConn::close()
{
	UCLOG("close method called");
	_closeInternal();
}

void UdpConn::run()
{
	Header header;
	for (;;) {
		int availRes = sock.waitForData(PING_INTERVAL / 2);
		if (availRes == 1) {
			int pendingLen = sock.available();

			if (pendingLen == sizeof(Header)) {
				// UCLOG("only header");
				int r = sock.recv(&header, sizeof(Header), 0);
				if (r == sizeof(Header)) {
					processPacket(&header, 0);
				}
			} else {
				if (isInBufEmpty && isInBufReceived) {
					// UCLOG("header + payload");
					int r = sock.recv(inBuf, sizeof(inBuf), 0);
					if (r > 0 && (uint32_t)r <= MAX_PACKET_SIZE) {
						Header* header = (Header*)inBuf;
						processPacket(header, r - sizeof(Header));
					}
				} else {
					char d;
					// no space in input data buffer, packet is discarded
					sock.recv(&d, 1, 0);
					UCLOG("no space in input buffer");
				}
			}
		} else if (availRes == 0) {
			tmr();
		}
	}
}

void UdpConn::processPacket(Header* header, int payloadLen)
{
	DUMPHEADER("received", header, payloadLen);

	MutexGuard guard(accessMutex);

	if (header->flags & FLAG_RST) {
		UCLOG("connection reset received");
		_closeInternal();
		return;
	}

	if (header->flags & FLAG_SYNACK) {
		sessId = header->sessId;
		lastReceivedId = header->id;
		UCLOG("got new sessId %u", sessId);
		lastPacketRecvTime = lastPingSendTime = OS::getTime();
		sendCondVar.notifyOne();
		return;
	}

	if (sessId == 0) {
		UCLOG("no connection");
		return;
	}

	// connected to server
	if (header->sessId != sessId) {
		UCLOG("connection lost");
		_closeInternal();
		return;
	}

	if (header->flags & FLAG_PING) {
		lastPacketRecvTime = OS::getTime();
	}

	if (header->flags & FLAG_DATA) {
		uint8_t diff = header->id - lastReceivedId;
		if (diff == 1) {
			if (payloadLen > 0) {
				lastReceivedId = header->id;
				dataBufLen = payloadLen;
				isInBufEmpty = false;
				isInBufReceived = false;
				recvCondVar.notifyOne();
				UCLOG("saved data %d", dataBufLen);
			}
		} else {
			UCLOG("skipping packet got %d last %d (%d)", header->id, lastReceivedId, diff);
		}
		lastPacketRecvTime = OS::getTime();
		_sendAck();
	}

	if (header->flags & FLAG_ACK) {
		lastSendAcked = header->id;
		sendCondVar.notifyOne();
		lastPacketRecvTime = OS::getTime();
	}
}
void UdpConn::tmr()
{
	MutexGuard guard(accessMutex);

	// connected
	if (sessId != 0) {
		if (OS::getTime() - lastPingSendTime >= PING_INTERVAL) {
			if (OS::getTime() - lastPacketRecvTime >= PING_INTERVAL) {
				_sendPing();
				lastPingSendTime = OS::getTime();
			}
		}
		if (OS::getTime() - lastPacketRecvTime >= 3000) {
			UCLOG("no packet received within interval connection lost");
			_closeInternal();
		}
	}
}

uint16_t UdpConn::getNextSendId(bool reset)
{
	// sendMutex acquired
	if (reset)
		lastSendId = 0;
	else
		lastSendId++;
	return lastSendId;
}

void UdpConn::_sendAck()
{
	// accessMutex acquired
	UCLOG("sending ack (%d)", lastReceivedId);

	Header h;
	h.sessId = sessId;
	h.id = lastReceivedId;
	h.flags = FLAG_ACK;

	sock.send(addr, &h, sizeof(h));
}

void UdpConn::_sendPing()
{
	if (sessId == 0)
		return;

	Header h;
	h.sessId = sessId;
	h.id = 0;
	h.flags = FLAG_PING;

	DUMPHEADER("sending ping", &h, -1);

	sock.send(addr, &h, sizeof(h));
}

void UdpConn::_closeInternal()
{
	MutexGuard guard(accessMutex);
	if (sessId != 0) {
		sessId = 0;
		recvCondVar.notifyOne();
		sendCondVar.notifyOne();
	}
}

int UdpConnSendSession::write(const void* data, uint32_t offset, uint32_t len, uint32_t timeout)
{
	const uint8_t* _data = (uint8_t*)data + offset;
	uint32_t i;
	for (i = 0; i < len; i++) {
		if (pos >= MAX_PACKET_SIZE)
			break;
		udpConn->outBuf[pos] = _data[i];
		pos++;
	}
	return i;
}

int UdpConnSendSession::send(uint32_t timeout)
{
	return udpConn->sendBuffer(pos - sizeof(Header), timeout);
}
