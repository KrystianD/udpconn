#ifndef __UDPCONN_H__
#define __UDPCONN_H__

#include <stdint.h>

#include <settings.h>
#include "crosslib.h"
#include "nativelib.h"

using namespace crosslib;
using namespace nativelib;

#define UCLOG(x,...) UCLOG_FUNC("[%-14s] " x "\r\n", __FUNCTION__, ##__VA_ARGS__)
#define UCLOGF() UCLOG_FUNC("[%-14s] ", __FUNCTION__)
#define UCLOGNL(x,...) UCLOG_FUNC(x, ##__VA_ARGS__)

#define ERROR_OK               0
#define ERROR_TIMEOUT         -1
#define ERROR_NOSPACE         -2
#define ERROR_CONNECTION_LOST -3
#define ERROR_INVALID_STATE   -4

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
	IPv4 ip;
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
	UdpConn();

	void init();

	int connect(const char* ip, uint16_t port, uint32_t timeout = 0xffffffff) { return connect(IPv4::parse(ip), port, timeout); }
	int connect(const IPv4& ip, uint16_t port, uint32_t timeout = 0xffffffff);

	int send(const void* data, int len, uint32_t timeout = 0xffffffff);
	int recv(void* data, int len, uint32_t timeout = 0xffffffff);

	void run();
	void close();

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

#endif
