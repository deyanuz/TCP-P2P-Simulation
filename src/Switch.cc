// Switch.cc
#include <omnetpp.h>
#include "TcpMessage_m.h"
#include <map>
#include <string>
#include <sstream>

using namespace omnetpp;

class Switch : public cSimpleModule
{
  private:
    // FDB: MAC -> portIndex
    std::map<std::string,int> fdb;
    int numPorts = 0;
    int routerPort;

  protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    void parsePresetFdb(const std::string &s);
};

Define_Module(Switch);

void Switch::initialize()
{
    numPorts = gateSize("port");
    EV << getFullName() << ": initialized with " << numPorts << " ports\n";
    routerPort = (std::string(getName()) == "switch1") ? 2 : 0;


    if (hasPar("presetFdb")) {
        parsePresetFdb(par("presetFdb").stdstringValue());
    }
}

void Switch::parsePresetFdb(const std::string &s)
{
    std::istringstream ss(s);
    std::string token;
    while (std::getline(ss, token, ';')) {
        if (token.empty()) continue;
        size_t colon = token.find('=');
        if (colon == std::string::npos) continue;
        std::string mac = token.substr(0, colon);
        int port = atoi(token.substr(colon+1).c_str());
        fdb[mac] = port;
        EV << getFullName() << ": preset FDB " << mac << " -> port " << port << "\n";
    }
}

void Switch::handleMessage(cMessage *msg)
{
    int arrival = msg->getArrivalGate()->getIndex();
    TcpMessage *tcp = dynamic_cast<TcpMessage*>(msg);

    if (!tcp) {
        // fallback for non-TCP messages: flood
        for (int i = 0; i < numPorts; ++i) {
            if (i == arrival) continue;
            send(msg->dup(), "port$o", i);
        }
        delete msg;
        return;
    }

    std::string srcMac = tcp->getSrcMac();
    std::string destMac = tcp->getDestMac();

    // Learn source MAC
    if (!srcMac.empty()) {
        fdb[srcMac] = arrival;
        EV << getFullName() << ": learned " << srcMac << " -> port " << arrival << "\n";
    }

    // Forward based on dest MAC
    auto it = fdb.find(destMac);
    if (it != fdb.end()) {
        int outPort = it->second;
        if (outPort == arrival) {
            EV << getFullName() << ": dest on same port, dropping\n";
            delete msg;
            return;
        }
        EV << getFullName() << ": forwarding to port " << outPort << " (destMAC=" << destMac << ")\n";
        send(msg, "port$o", outPort);
    } else {
        // unknown MAC → flood
        EV << getFullName() << ": MAC not in this network (" << destMac << "), sending to router\n";
            send(msg->dup(), "port$o", routerPort);
        delete msg;
    }
}
