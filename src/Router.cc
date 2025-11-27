// Router.cc
#include <omnetpp.h>
#include "TcpMessage_m.h"
#include <map>

using namespace omnetpp;

class Router : public cSimpleModule
{
  private:
    // map of destination IP (prefix) to out-port index or next-hop IP
    // For simplicity we map exact networks like "192.168.2.0/24" to an out port index.
    std::map<std::string,int> routes;

  protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
};

Define_Module(Router);

void Router::initialize()
{
    EV << getFullName() << ": initialize\n";
    // Example static routes – you can override via NED parameters or fill dynamically.
    // This is just a place to put your custom mapping if you want.
    // For a two-router topology, we assume router1->router2 uses port 1 and router2->router1 uses port 1, etc.
    // Leave empty unless you set presetRoutes param in NED and parse it here.
}

void Router::handleMessage(cMessage *msg)
{
    TcpMessage *tcp = dynamic_cast<TcpMessage*>(msg);
    if (!tcp) {
        delete msg;
        return;
    }

    std::string dst = tcp->getDestIp();
    EV << getFullName() << ": received packet for " << dst << "\n";

    // Very naive forwarding:
    // if dest starts with "192.168.2." then forward to port 1 (towards router2/switch2)
    // else forward to port 0 (towards router1 side)
    int outPort = 0;
    if (dst.rfind("192.168.2.", 0) == 0) {
        // send to right side (port 1)
        // but if this router only has one port assigned, just send to port 0.
        outPort = (gateSize("port") > 1) ? 1 : 0;
    } else {
        outPort = 0;
    }

    EV << getFullName() << ": forwarding out port " << outPort << " dst=" << dst << "\n";
    send(msg, "port$o", outPort);
}
