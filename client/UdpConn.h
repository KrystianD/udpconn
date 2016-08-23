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
#define FLAG_PING    32

const uint32_t TIME_WAIT_FOR_ACK = 200;
const uint32_t MAX_PACKET_SIZE = 1200;
const uint32_t PING_INTERVAL = 1000;

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
		if (flags & FLAG_PING) UCLOGNL(" PING");
	}
};
#pragma pack()

class UdpConn;

class UdpConnSendSession : public IStream {
  UdpConn* udpConn;
  uint16_t pos;

public:
  UdpConnSendSession(UdpConn* udpConn) : udpConn(udpConn) { }

	int read(void* data, uint32_t offset, uint32_t length, uint32_t timeout = 0xffffffff) { return -1; }
  int write(const void* data, uint32_t offset, uint32_t len, uint32_t timeout = 0xffffffff);

  int send(uint32_t timeout = 0xffffffff);

  friend class UdpConn;
};

class UdpConn {
	InetAddress addr;
	UdpSocket sock;

	uint16_t sessId;

	RecursiveMutex accessMutex;
	CondVar sendCondVar, recvCondVar;

	// sending
	RecursiveMutex sendMutex;
	uint8_t lastSendId;
	uint8_t lastSendAcked;
	uint64_t lastPingSendTime;

	// receiving
	bool isInBufFree;
	Mutex readMutex;
	uint8_t lastReceivedId;
	uint64_t lastPacketRecvTime;

	uint8_t outBuf[MAX_PACKET_SIZE];
	uint8_t inBuf[MAX_PACKET_SIZE];
	uint32_t dataBufLen;

public:
	UdpConn();

	void init();

	int connect(const char* ip, uint16_t port, uint32_t timeout = 0xffffffff) { return connect(InetAddress(IPv4::parse(ip), port), timeout); }
	int connect(const IPv4& ip, uint16_t port, uint32_t timeout = 0xffffffff) { return connect(InetAddress(ip, port), timeout); }
	int connect(const InetAddress& addr, uint32_t timeout = 0xffffffff);

	int send(const void* data, uint32_t offset, uint32_t len, uint32_t timeout = 0xffffffff);
	int recv(void* data, uint32_t offset, uint32_t len, uint32_t timeout = 0xffffffff);

  UdpConnSendSession createSendSession();

	uint8_t* getInBufPointer() const { return (uint8_t*)inBuf + sizeof(Header); }
	uint32_t getInBufCapacity() const { return sizeof(outBuf) - sizeof(Header); }
	uint8_t* getOutBufPointer() const { return (uint8_t*)outBuf + sizeof(Header); }
	uint32_t getOutBufCapacity() const { return sizeof(outBuf) - sizeof(Header); }

	void run();
	void close();

private:
	int sendBuffer(uint32_t len, uint32_t timeout = 0xffffffff);
	int _sendInternal(uint32_t len, uint32_t timeout = 0xffffffff);

	void tmr();

  void processPacket(Header* h, int payloadLen);

	uint8_t getNextSendId(bool reset = false);

	void _sendAck();
	void _sendPing();
	void _closeInternal();

  friend class UdpConnSendSession;
};

#endif
