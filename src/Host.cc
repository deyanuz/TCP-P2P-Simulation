// Host.cc
#include <omnetpp.h>
#include "TcpMessage_m.h"
#include <string>
#include <vector>
#include <sstream>
#include <map>

using namespace omnetpp;

struct RouteEntry {
    uint32_t net;
    uint32_t mask;
    std::string via; // next-hop IP (empty if on-link)
};

static uint32_t ipStrToUint(const std::string &ip) {
    unsigned a,b,c,d;
    if (sscanf(ip.c_str(), "%u.%u.%u.%u", &a,&b,&c,&d) != 4) return 0;
    return (a<<24) | (b<<16) | (c<<8) | d;
}

static bool ipInNet(uint32_t ip, uint32_t net, uint32_t mask) {
    return (ip & mask) == (net & mask);
}

static uint32_t maskLenToMask(int len) {
    if (len <= 0) return 0;
    if (len >= 32) return 0xFFFFFFFFu;
    return (len==32) ? 0xFFFFFFFFu : (~0u << (32 - len));
}

class Host : public cSimpleModule
{
  private:
    std::string role;
    std::string ipAddress;
    std::string macAddress;
    std::string destIp;
    int totalBytes;
    int chunkSize;

    std::map<std::string,std::string> ipToMac;

    std::vector<RouteEntry> routes;

    enum TcpState { CLOSED, SYN_SENT, LISTEN, SYN_RCVD, ESTABLISHED } state;
    int localSeq;
    int remoteSeq;
    int bytesSent;
    int bytesReceived;

    // --- new members for server-side data sending ---
    std::string peerIp;            // IP of the connected peer (set in LISTEN when SYN arrives)
    std::string peerMac;           // MAC of the connected peer
    int sendTotal = 0;             // total bytes to send (1000 default or totalBytes param)
    int sendChunk = 0;             // chunk size (200 default or chunkSize param)
    int sendBaseSeq = 0;           // initial seq when starting to send
    int bytesAckedByPeer = 0;      // how many bytes the peer has acked
    cMessage *startTimer = nullptr;

  protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    void parseRoutingTable(const std::string &rt);
    std::string lookupNextHop(const std::string &dst);
    void scheduleStartIfNeeded();
    void sendTcpSegment(bool syn, bool ack, const char* payload = nullptr, int len = 0);
    void startHandshake();
    void handleTcpSegment(TcpMessage *tcp);

    // helper to send data chunk to a specific destination (used by pc2 to send DATA to pc1)
    void sendDataChunkTo(const std::string &dstIp, const std::string &dstMac, int len);
};

Define_Module(Host);

void Host::initialize()
{
    role = par("role").stdstringValue();
    ipAddress = par("ipAddress").stdstringValue();
    macAddress = par("macAddress").stdstringValue();  // from NED
    destIp = par("destIp").stdstringValue();
    totalBytes = par("totalBytes");
    chunkSize = par("chunkSize");

    state = CLOSED;
    localSeq = 1000 + (int)(getId() % 1000);
    remoteSeq = 0;
    bytesSent = 0;
    bytesReceived = 0;

    peerIp = "";
    peerMac = "";
    sendTotal = 0;
    sendChunk = 0;
    sendBaseSeq = 0;
    bytesAckedByPeer = 0;

    EV << getFullName() << ": role=" << role << " ip=" << ipAddress
       << " mac=" << macAddress << " dest=" << destIp
       << " totalBytes=" << totalBytes << " chunkSize=" << chunkSize << "\n";

    // parse routing table from parameter
    parseRoutingTable(par("routingTable").stdstringValue());

    scheduleStartIfNeeded();
}

void Host::parseRoutingTable(const std::string &rt)
{
    std::istringstream ss(rt);
    std::string token;
    while (std::getline(ss, token, ';')) {
        // trim spaces
        while (!token.empty() && isspace((unsigned char)token.front())) token.erase(token.begin());
        while (!token.empty() && isspace((unsigned char)token.back())) token.pop_back();
        if (token.empty()) continue;

        size_t eq = token.find('=');
        if (eq != std::string::npos) {
            // IP->MAC mapping: e.g., 192.168.1.11=00:00:00:00:01:02
            std::string ip = token.substr(0, eq);
            std::string mac = token.substr(eq+1);
            ipToMac[ip] = mac;
        } else if (token.rfind("default via ", 0) == 0) {
            RouteEntry e;
            e.net = 0; e.mask = 0;
            e.via = token.substr(strlen("default via "));
            routes.push_back(e);
        } else {
            // network prefix: e.g., 192.168.1.0/24
            size_t slash = token.find('/');
            if (slash == std::string::npos) continue;
            std::string netStr = token.substr(0, slash);
            int prefix = std::stoi(token.substr(slash+1));
            RouteEntry e;
            e.net = ipStrToUint(netStr);
            e.mask = maskLenToMask(prefix);
            e.via = ""; // on-link
            routes.push_back(e);
        }
    }
}


std::string Host::lookupNextHop(const std::string &dst)
{
    uint32_t ip = ipStrToUint(dst);
    int bestPrefix = -1;
    std::string bestVia = "";
    for (auto &r : routes) {
        if (r.mask == 0) {
            if (bestPrefix < 0) { bestPrefix = 0; bestVia = r.via; }
        } else {
            int prefix = 32;
            uint32_t mask = r.mask;
            while (prefix > 0 && ((mask & (1u << (32 - prefix))) == 0)) prefix--;
            if (ipInNet(ip,r.net,r.mask) && prefix > bestPrefix) { bestPrefix = prefix; bestVia = r.via; }
        }
    }
    return bestVia;
}

void Host::scheduleStartIfNeeded()
{
    // src define
    if (strcmp(getName(), "pc2")==0 && !destIp.empty()) {
        startTimer = new cMessage("start");
        scheduleAt(simTime()+0.001, startTimer);
        EV << getFullName() << ": scheduled start\n";
    } else {
        state = LISTEN;
    }
}

void Host::handleMessage(cMessage *msg)
{
    if (msg->isSelfMessage()) {
        if (strcmp(msg->getName(),"start")==0) {
            startHandshake();
            delete msg;
            startTimer = nullptr;
            return;
        }
    }

    TcpMessage *tcp = dynamic_cast<TcpMessage*>(msg);
    if (tcp) {
        handleTcpSegment(tcp);
        return;
    }

    delete msg;
}

std::string msgLabel(bool syn, bool ack, int len) {
    if (syn && ack) return "SYN-ACK";
    if (syn) return "SYN";
    if (ack && len==0) return "ACK";
    if (len>0) return "DATA";
    return "SEG";
}



void Host::startHandshake()
{
    if (state == CLOSED) {
        std::string nextHop = lookupNextHop(destIp);
        std::string sendToIp = nextHop.empty() ? destIp : nextHop;
        std::string nextMac = ipToMac[sendToIp];

        localSeq = 1000;
        TcpMessage *m = new TcpMessage();
        // set textual name for the message (visible in inspector)
        m->setName("SYN");
        m->setSrcIp(ipAddress.c_str());
        m->setDestIp(sendToIp.c_str());
        m->setSrcMac(macAddress.c_str());
        m->setDestMac(nextMac.c_str());
        m->setSeqNum(localSeq);
        m->setAckNum(0);
        m->setSynFlag(true);
        m->setAckFlag(false);
        m->setDataLength(0);
        m->setSrcPort(1000);
        m->setDestPort(1000);

        EV << getFullName() << ": sending SYN to " << sendToIp << " MAC=" << nextMac << "\n";

        // GUI bubble notification (only visible in GUI runs)
        bubble(("sent: " + std::string(m->getName())).c_str());

        send(m,"port$o");
        state = SYN_SENT;
    }
}


void Host::sendTcpSegment(bool syn, bool ack, const char* payload, int len)
{
    std::string nextHop = lookupNextHop(destIp);
    std::string sendToIp = nextHop.empty() ? destIp : nextHop;

    TcpMessage *m = new TcpMessage();

    // set a descriptive name for the message
    std::string label = msgLabel(syn, ack, len);
    m->setName(label.c_str());

    m->setSrcIp(ipAddress.c_str());
    m->setDestIp(sendToIp.c_str());
    m->setSrcMac(macAddress.c_str());
    m->setSeqNum(localSeq);
    m->setAckNum(ack ? remoteSeq : 0);
    m->setSynFlag(syn);
    m->setAckFlag(ack);
    if (payload && len>0) {
        m->setPayload(std::string(payload,len).c_str());
        m->setDataLength(len);
        localSeq += len;
        bytesSent += len;
    } else {
        m->setDataLength(0);
    }
    m->setSrcPort(1000);
    m->setDestPort(1000);

    EV << getFullName() << ": sending segment SEQ="<<m->getSeqNum()<<" NAME="<<m->getName()
       <<" SYN="<<syn<<" ACK="<<ack<<"\n";

    // bubble in GUI
    bubble(("sent: " + label + " SEQ=" + std::to_string(m->getSeqNum())).c_str());

    send(m,"port$o");
}


void Host::sendDataChunkTo(const std::string &dstIp, const std::string &dstMac, int len)
{
    // build payload of 'x' characters (len bytes)
    std::string payload(len, 'x');

    TcpMessage *m = new TcpMessage();
    m->setName("DATA");
    m->setSrcIp(ipAddress.c_str());
    m->setDestIp(dstIp.c_str());
    m->setSrcMac(macAddress.c_str());
    m->setDestMac(dstMac.c_str());
    m->setSeqNum(localSeq);
    m->setAckNum(0);
    m->setSynFlag(false);
    m->setAckFlag(false);
    m->setPayload(payload.c_str());
    m->setDataLength(len);
    m->setSrcPort(1000);
    m->setDestPort(1000);

    // increment localSeq and bytesSent exactly like sendTcpSegment does
    localSeq += len;
    bytesSent += len;

    EV << getFullName() << ": sending DATA to " << dstIp << " SEQ=" << m->getSeqNum()
       << " LEN=" << len << " (totalSent=" << bytesSent << ")\n";

    bubble(("sending: DATA SEQ=" + std::to_string(m->getSeqNum()) + " LEN=" + std::to_string(len)).c_str());

    send(m, "port$o");
}


void Host::handleTcpSegment(TcpMessage *tcp)
{
    EV << getFullName() << ": received segment NAME="<<tcp->getName()
       <<" SEQ="<<tcp->getSeqNum()<<" ACK="<<tcp->getAckNum()
       <<" SYN="<<tcp->getSynFlag()<<" ACKflag="<<tcp->getAckFlag()
       <<" Len="<<tcp->getDataLength()<<"\n";

    // show bubble for reception (visible in GUI)
    std::string rcvLabel = std::string("rcvd: ") + (tcp->getName()?tcp->getName():"SEG")
                         + " SEQ=" + std::to_string(tcp->getSeqNum());
    bubble(rcvLabel.c_str());

    // --- If this is an ACK-only (no-data) in ESTABLISHED, update ack tracking (used by sender pc2) ---
    if (state == ESTABLISHED && tcp->getAckFlag() && tcp->getDataLength() == 0) {
        // only consider ACKs coming from the peer we expect
        if (!peerIp.empty() && tcp->getSrcIp() == peerIp) {
            int ackNum = tcp->getAckNum();
            int acked = ackNum - sendBaseSeq;
            if (acked > bytesAckedByPeer) {
                bytesAckedByPeer = acked;
                EV << getFullName() << ": peer acked " << bytesAckedByPeer << " bytes (ackNum=" << ackNum << ")\n";
                // if we still have more to send, send next chunk (stop-and-wait)
                if (bytesAckedByPeer < sendTotal) {
                    int remain = sendTotal - bytesAckedByPeer;
                    int toSend = std::min(sendChunk, remain);
                    // Determine peer MAC (should have been stored already)
                    std::string dstIp = peerIp;
                    std::string dstMac = peerMac;
                    if (dstMac.empty()) {
                        // fallback: try lookup
                        dstMac = ipToMac[dstIp];
                    }
                    sendDataChunkTo(dstIp, dstMac, toSend);
                } else {
                    EV << getFullName() << ": finished sending all " << sendTotal << " bytes to " << peerIp << "\n";
                    bubble(("finished: sent " + std::to_string(sendTotal) + " bytes").c_str());
                }
            }
        }
    }

    // normal server-side: LISTEN receives SYN -> reply SYN-ACK
    if (state == LISTEN && tcp->getSynFlag()) {
        remoteSeq = tcp->getSeqNum()+1;
        localSeq = 2000;
        // store peer info for later sending
        peerIp = tcp->getSrcIp();
        peerMac = tcp->getSrcMac();

        TcpMessage *m = new TcpMessage();
        m->setName("SYN-ACK");
        m->setSrcIp(ipAddress.c_str());
        m->setDestIp(tcp->getSrcIp());
        m->setSrcMac(macAddress.c_str());      // host MAC only
        m->setSeqNum(localSeq);
        m->setDestMac(tcp->getSrcMac());
        m->setAckNum(remoteSeq);
        m->setSynFlag(true);
        m->setAckFlag(true);
        m->setDataLength(0);
        m->setSrcPort(1000);
        m->setDestPort(1000);

        EV << getFullName() << ": sending " << m->getName() << " to " << m->getDestIp()
           << " SEQ=" << m->getSeqNum() << " ACK=" << m->getAckNum() << "\n";

        // GUI bubble (sending)
        bubble(("sending: " + std::string(m->getName())).c_str());

        send(m,"port$o");
        state = SYN_RCVD;
        delete tcp;
        return;
    }

    // client-side: SYN_SENT receives SYN-ACK -> send final ACK
    if (state == SYN_SENT && tcp->getSynFlag() && tcp->getAckFlag()) {
        remoteSeq = tcp->getSeqNum()+1;
        localSeq = tcp->getAckNum();
        TcpMessage *m = new TcpMessage();
        m->setName("ACK");
        m->setSrcIp(ipAddress.c_str());
        m->setDestIp(tcp->getSrcIp());
        m->setSrcMac(macAddress.c_str());  // host MAC only
        m->setSeqNum(localSeq);
        m->setAckNum(remoteSeq);
        m->setDestMac(tcp->getSrcMac());
        m->setSynFlag(false);
        m->setAckFlag(true);
        m->setDataLength(0);
        m->setSrcPort(1000);
        m->setDestPort(1000);

        EV << getFullName() << ": sending " << m->getName() << " to " << m->getDestIp()
           << " SEQ=" << m->getSeqNum() << " ACK=" << m->getAckNum() << "\n";

        bubble(("sending: " + std::string(m->getName())).c_str());

        send(m,"port$o");
        state = ESTABLISHED;
        delete tcp;
        return;
    }

    // server: SYN_RCVD receives final ACK -> connection established
    if (state == SYN_RCVD && tcp->getAckFlag()) {
        localSeq = tcp->getAckNum();
        state = ESTABLISHED;

        EV << getFullName() << ": connection ESTABLISHED with " << tcp->getSrcIp() << "\n";
        bubble(("state: ESTABLISHED"));

        // If this is pc2 (the server/listener) we start sending data back
        // sendTotal = parameter totalBytes if set, otherwise default 1000
        // sendChunk = parameter chunkSize if set, otherwise default 200
        if (getName()) {
            sendTotal = (totalBytes > 0) ? totalBytes : 1000;
            sendChunk = (chunkSize > 0) ? chunkSize : 200;
            sendBaseSeq = localSeq; // base seq for data sending
            bytesAckedByPeer = 0;

            // send first chunk immediately
            int toSend = std::min(sendChunk, sendTotal - bytesAckedByPeer);
            std::string dstIp = peerIp.empty() ? tcp->getSrcIp() : peerIp;
            std::string dstMac = peerMac.empty() ? tcp->getSrcMac() : peerMac;
            EV << getFullName() << ": starting data transfer to " << dstIp
               << " total=" << sendTotal << " chunk=" << sendChunk << "\n";
            sendDataChunkTo(dstIp, dstMac, toSend);
        }

        delete tcp;
        return;
    }

    // receiver-side: ESTABLISHED and incoming DATA -> send ACK
    if (state == ESTABLISHED && tcp->getDataLength()>0) {
        bytesReceived += tcp->getDataLength();
        remoteSeq = tcp->getSeqNum()+tcp->getDataLength();

        TcpMessage *ack = new TcpMessage();
        ack->setName("ACK");
        ack->setSrcIp(ipAddress.c_str());
        ack->setDestIp(tcp->getSrcIp());
        ack->setSrcMac(macAddress.c_str());  // host MAC only
        ack->setSeqNum(localSeq);
        ack->setAckNum(remoteSeq);
        ack->setDestMac(tcp->getSrcMac());
        ack->setSynFlag(false);
        ack->setAckFlag(true);
        ack->setDataLength(0);
        ack->setSrcPort(1000);
        ack->setDestPort(1000);

        EV << getFullName() << ": sending " << ack->getName() << " to " << ack->getDestIp()
           << " SEQ=" << ack->getSeqNum() << " ACK=" << ack->getAckNum() << " (for DATA)\n";

        // bubble before sending
        bubble(("sending: ACK " + std::to_string(ack->getAckNum())).c_str());

        send(ack,"port$o");
        delete tcp;
        return;
    }

    delete tcp;
}

void Host::finish()
{
    if (startTimer) { cancelAndDelete(startTimer); startTimer=nullptr; }
    EV << getFullName() << ": finished. bytesSent=" << bytesSent << " bytesReceived=" << bytesReceived << "\n";
}
