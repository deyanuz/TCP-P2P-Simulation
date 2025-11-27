package tcp;

simple Host
{
    parameters:
        string role = default("");            // "src" or "dst"
        string ipAddress = default("");       // IP address for routing
        string macAddress = default("");      // MAC address
        string destIp = default("");          // destination IP for flows
        int totalBytes = default(0);
        int chunkSize = default(100);
        double timeout @unit(s) = default(0.5s);
        string routingTable = default("");    // IP -> MAC mapping, semicolon separated
        @display("i=device/pc");
    gates:
        inout port;                           // single bidirectional port
}

simple Router
{
    parameters:
        string ipAddress = default("");
        @display("i=device/router");
    gates:
        inout port[];     // Multiple bidirectional ports (auto-expand)
}

simple Switch
{
    parameters:
        string presetFdb;
        @display("i=device/switch");
    gates:
        inout port[];     // Multiple bidirectional ports (auto-expand)
}

simple Link
{
    parameters:
        double delay @unit(s) = default(0.01s);
        double lossRate = default(0.0);
        double dataRate @unit(bps) = default(1000000bps);
        @display("p=300,200;i=status/connect");
    gates:
        inout left;
        inout right;
}

network ComplexNetwork
{
    submodules:
        // Source hosts (left column)
        pc1: Host {
            parameters:
                role = "src";
                ipAddress = "192.168.1.10";
                macAddress = "00:00:00:00:01:01";
                destIp = "192.168.1.11";
                totalBytes = 1000;
                routingTable = "192.168.1.11=00:00:00:00:01:02;192.168.2.10=00:00:00:00:02:01;192.168.2.11=00:00:00:00:02:02";
            @display("p=40,120");
        }

        pc2: Host {
            parameters:
                role = "src";
                ipAddress = "192.168.1.11";
                macAddress = "00:00:00:00:01:02";
                destIp = "192.168.2.10";
                totalBytes = 1000;
                routingTable = "192.168.1.10=00:00:00:00:01:01;192.168.2.10=00:00:00:00:02:01;192.168.2.11=00:00:00:00:02:02";
            @display("p=40,220");
        }

        // Left-side switch
        switch1: Switch {
             parameters:
		        presetFdb = "00:00:00:00:01:01=0;00:00:00:00:01:02=1";
             @display("p=200,170");
        }

        // Routers
        router1: Router { parameters: ipAddress = "192.168.1.1"; @display("p=320,170"); }
        router2: Router { parameters: ipAddress = "192.168.2.1"; @display("p=440,170"); }

        // Right-side switch
        switch2: Switch {
            parameters:
		        presetFdb = "00:00:00:00:02:01=1;00:00:00:00:02:02=2";
            @display("p=560,170");
        }

        // Destination hosts (right column)
        pc3: Host {
            parameters:
                role = "dst";
                ipAddress = "192.168.2.10";
                totalBytes = 1000;
                destIp = "192.168.1.11";
                macAddress = "00:00:00:00:02:01";
                routingTable = "192.168.2.11=00:00:00:00:02:02;192.168.1.10=00:00:00:00:01:01;192.168.1.11=00:00:00:00:01:02";
            @display("p=700,120");
        }

        pc4: Host {
            parameters:
                role = "dst";
                ipAddress = "192.168.2.11";
                totalBytes = 1000;
                destIp = "192.168.1.11";
                macAddress = "00:00:00:00:02:02";
                routingTable = "192.168.2.10=00:00:00:00:02:01;192.168.1.10=00:00:00:00:01:01;192.168.1.11=00:00:00:00:01:02";
            @display("p=700,220");
        }

        // Links
        link1: Link { parameters: delay = 0.001s; @display("p=120,120"); }
        link2: Link { parameters: delay = 0.001s; @display("p=120,220"); }
        link3: Link { parameters: delay = 0.005s; @display("p=260,170"); }
        link4: Link { parameters: delay = 0.02s; lossRate = 0.1; dataRate = 500000bps; @display("p=380,170"); }
        link5: Link { parameters: delay = 0.005s; dataRate = 1000000bps; @display("p=500,170"); }
        link6: Link { parameters: delay = 0.001s; dataRate = 1000000bps; @display("p=640,120"); }
        link7: Link { parameters: delay = 0.001s; dataRate = 1000000bps; @display("p=640,220"); }

    connections:
        // Source network
        pc1.port <--> link1.left;
        link1.right <--> switch1.port++;
        pc2.port <--> link2.left;
        link2.right <--> switch1.port++;

        switch1.port++ <--> link3.left;
        link3.right <--> router1.port++;

        // Router-router
        router1.port++ <--> link4.left;
        link4.right <--> router2.port++;

        // Destination network
        router2.port++ <--> link5.left;
        link5.right <--> switch2.port++;

        switch2.port++ <--> link6.left;
        link6.right <--> pc3.port;

        switch2.port++ <--> link7.left;
        link7.right <--> pc4.port;
}
