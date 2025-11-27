#include <omnetpp.h>
#include "TcpMessage_m.h"

using namespace omnetpp;

class Link : public cSimpleModule
{
  protected:
    virtual void initialize() override {}
    virtual void handleMessage(cMessage *msg) override;
};

Define_Module(Link);

void Link::handleMessage(cMessage *msg)
{
    // Get the arrival gate
    cGate *g = msg->getArrivalGate();

    // Send through the **other** end of the inout gate
    if (g == gate("left$i")) {
        send(msg, "right$o");
    }
    else if (g == gate("right$i")) {
        send(msg, "left$o");
    }
    else {
        EV << getFullName() << ": unexpected arrival gate, dropping message\n";
        delete msg;
    }
}
