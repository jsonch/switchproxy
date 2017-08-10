 /* 
 *  Switch <--> Controller proxy with Datapath connection. 
 *   
 *  Simple TCP proxy based on :
 *  A simple TCP proxy by Martin Broadhurst (www.martinbroadhurst.com)
 *
 *  g++ -o simpleproxy simpleproxy.cpp -std=c++11 -lpthread
 *  or, to statically link when building for the pica8: 
 *  g++ -static -o simpleproxy simpleproxy.cpp -std=c++0x -pthread
 *  g++ -g -O0 -static -std=c++11 t.cpp -lpthread -Wl,-u,pthread_join,-u,pthread_equal
 *  g++ -std=c++11 -static -g b.cpp -Wl,-u,pthread_create,-u,pthread_once,-u,pthread_mutex_lock,-u,pthread_mutex_unlock,-u,pthread_join,-u,pthread_equal
,-u,pthread_detach,-u,pthread_cond_wait,-u,pthread_cond_signal,-u,pthread_cond_destroy,-u,pthread_cond_broadcast,-u,pthread_cancel -o b

 *  Static linking pthreads is buggy with the g++ on the switch. Need to use:
 *  g++ -static -o simpleproxy simpleproxy.cpp -std=c++0x -Wl,--whole-archive -lpthread -Wl,--no-whole-archive
 *  sudo ./simpleproxy 127.0.0.1 6634 127.0.0.1 6633 5000 1000 0
 *  sudo ./simpleproxy 127.0.0.1 9999 10.1.1.2 6633 5000 1000 0
 */

#include <stdio.h>
#include <string.h> /* memset() */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <signal.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <sys/ioctl.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <stdlib.h>

// New includes.
#include <unordered_map>
#include <time.h>       /* clock_t, clock, CLOCKS_PER_SEC */
#include <iostream>       // std::cout
#include <chrono>
#include <thread>
#include <mutex>          // std::mutex
#include <algorithm>    // std::find
#include <vector>
#include <deque>
#include <sys/time.h>
#include <iomanip>
#include <pthread.h>
#include <cstring>
#include <netinet/ip.h>


using std::cout;
using std::endl;
using std::string;
using std::deque;
using std::vector;


#define BACKLOG  10      /* Passed to listen() */
#define BUF_SIZE 4096    /* Buffer for  transfers */


/* Generic header on all OpenFlow packets. */
struct ofp_header {
    uint8_t version;
    uint8_t type;
    uint16_t length;
    uint32_t xid;
};

#pragma pack(push)
#pragma pack(0)
struct vlan_ethhdr {
  u_int8_t  ether_dhost[ETH_ALEN];  /* destination eth addr */
  u_int8_t  ether_shost[ETH_ALEN];  /* source ether addr    */
  u_int16_t          h_vlan_proto;
  u_int16_t          h_vlan_TCI;
  u_int16_t ether_type;
 };
#pragma pack(pop)

// mutexes for sockets.
std::mutex mtx;           // mutex for critical section
std::mutex switchMtx;           // mutex for critical section
std::mutex controllerMtx;           // mutex for critical section
std::mutex datapathMtx;           // mutex for critical section


// Functions that you can modify to intercept packets between switch and controller. 
// and handle fast path messages.
int processSwitchMessage(int outSocket, char *pkt, size_t pkt_len);
int processControllerMessage(int outSocket, char *pkt, size_t pkt_len);
void processDpMessage(int dpsock);


// low level proxy functions.
// keepAlive sends messages to the switch agent to keep the OF connection alive. 
// Sometimes useful in high load scenarios.
void keepAlive(int switchsock); // thread loop. 
void handle(int client, const char *remote_host, const char *remote_port, int dpsock); // thread loop.
unsigned int transfer(int from, int to, int direction);

// raw socket functions.
int create_rawsocket(int protocol_to_sniff);
int bind_rawsocket(char *device, int rawsock, int protocol) ;
int send_rawpacket(int rawsock, char *pkt, int pkt_len);

// Convenience functions.
int print_pkt(char * bytes, int len);
void print_hex_memory(void *mem, int len);
int tag_packet(char * dstBuf, char * srcBuf, int packetlen, int tag);
int untag_packet(char *dstBuf, char * srcBuf, int packetlen);
long long current_timestamp();

// sudo ./simpleproxy localhost 9999 localhost 6633 ofxveth1


// MAIN.
int main(int argc, char **argv)
{
    int dpsock; // socket to datapath. 

    int sock;
    int reuseaddr = 1; /* True */
    const char *from_ovs_host, *from_ovs_port, *to_controller_host, *to_controller_port;

    /* Get the server host and port from the command line */
    if (argc < 3) {
        fprintf(stderr, "Usage: simpleproxy from_ovs_host from_ovs_port to_controller_host to_controller_port fastPathInterface\n");
        return 1;
    }
    from_ovs_host = argv[1];
    from_ovs_port = argv[2];
    to_controller_host = argv[3];
    to_controller_port = argv[4];

    char * fastPathInterface = argv[5];


    // Open socket to listen for connections from OVS manager.
    sockaddr_in listenAddr;
    listenAddr.sin_family = AF_INET;
    listenAddr.sin_port = htons(atoi(from_ovs_port));
    inet_pton(AF_INET, from_ovs_host, &listenAddr.sin_addr);
    memset(&listenAddr.sin_zero, 0, 8);

    /* Create the socket */
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("socket");
        return 1;
    }

    /* Enable the socket to reuse the address */
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(int)) == -1) {
        perror("setsockopt");
        return 1;
    }

    /* Bind to the address */
    if (bind(sock, (sockaddr *)&listenAddr, sizeof(listenAddr)) == -1) {
        perror("bind");
        return 1;
    }

    /* Listen */
    if (listen(sock, BACKLOG) == -1) {
        perror("listen");
        return 1;
    }


    /* Ignore broken pipe signal */
    signal(SIGPIPE, SIG_IGN);

    /* Create the fast path socket to the fe */
    printf("opening socket to FE.\n");
    dpsock = create_rawsocket(ETH_P_ALL);
    printf ("binding to interface %s \n",fastPathInterface);
    bind_rawsocket(fastPathInterface, dpsock, ETH_P_ALL);
    printf ("done binding.\n");


    /* Main loop */
    while (1) {
        socklen_t size = sizeof(struct sockaddr_in);
        struct sockaddr_in their_addr;
        // Accept socket from client (i.e., OVS switch agent, and connect to controller.)
        int newsock = accept(sock, (struct sockaddr*)&their_addr, &size);

        if (newsock == -1) {
            perror("accept");
        }
        else {
            printf("Got a connection from %s on port %d\n",
                    inet_ntoa(their_addr.sin_addr), htons(their_addr.sin_port));
            std::thread th2 (keepAlive, newsock);  
            printf("starting connection to controller.\n");          
            handle(newsock, to_controller_host, to_controller_port, dpsock);
        }
    }

    close(sock);

    return 0;
}


// ****************** Functions you modify **********************************

// Process a packet from OF switch agent to controller. 
// Might contain multiple OF messages!
int processSwitchMessage(int outSocket, char *pkt, size_t pkt_len){
    char * currentPtr = pkt;
    // loop to process multiple openflow messages, which may be combined into 1 packet.
    while (currentPtr < pkt+pkt_len){
        ofp_header *ofpHdf = (ofp_header*) currentPtr;
        cout << "got a message from controller to switch agent.. (" << ntohs(ofpHdf->length) << " bytes)" << endl;
        cout << "\t OF message type: " << int(ofpHdf->type) << endl;

        // Write this individual OF packet to the OpenFlow switch agent.
        controllerMtx.lock();
        int bytes_sent = write(outSocket, currentPtr, ntohs(ofpHdf->length));
        controllerMtx.unlock();
        currentPtr+= ntohs(ofpHdf->length);
    }
    return 0; // not disconnected. 
}

// process a packet from controller to switch.
// Might contain multiple OF messages!
int processControllerMessage(int outSocket, char *pkt, size_t pkt_len){
    char * currentPtr = pkt;
    // loop to process multiple openflow messages, which may be combined into 1 packet.
    while (currentPtr < pkt+pkt_len){
        int retVal = 1; // allow message, because it hasn't timed out yet.
        ofp_header *ofpHdf = (ofp_header*) currentPtr;
        cout << "got a message from controller to switch agent.. (" << ntohs(ofpHdf->length) << " bytes)" << endl;
        cout << "\t OF message type: " << int(ofpHdf->type) << endl;

        // Write this individual OF packet to the OpenFlow switch agent.
        switchMtx.lock();
        int bytes_sent = write(outSocket, currentPtr, ntohs(ofpHdf->length));
        switchMtx.unlock();
        currentPtr+= ntohs(ofpHdf->length);
    }
    return 0; // not disconnected
}


int packetId = 0;
// Process a packet on the fast path to the FE.
void processDpMessage(int dpsock){
    // New packet from the datapath. Add it to the timeout queue.
    struct vlan_ethhdr* vlanHeader;
    struct ethhdr * ethHeader;
    char strippedPktBuf[BUF_SIZE-4];

    char pktBuf[BUF_SIZE];
    int bytesRead = read(dpsock, pktBuf, BUF_SIZE);


    // Send the packet back down.
    // send_rawpacket(dpsock, pktBuf, bytesRead);

    cout << "proxy fast path got packet # " << packetId << endl;
    packetId++;
    // cout << "----------------" << endl;
    // print_hex_memory((void *) pktBuf, bytesRead);
    // cout << "----------------" << endl;
    // char textBuf[2*sizeof(vlan_ethhdr)+1];
    // for(int j = 0; j < sizeof(vlan_ethhdr); j++)
    //     sprintf(&textBuf[2*j], "%02X", pktBuf[j]);
    // textBuf[2*sizeof(vlan_ethhdr)] = 0;
    // cout << textBuf << endl;
    // cout << "----------------" << endl;
    // // printf("read: %i bytes from datapath. (packet # %i)\n",bytesRead, dpPktCt);
    // cout << "ether address len: " << ETH_ALEN << endl;
    // cout << "packet len from dp: " << bytesRead << endl;
}

//****************** Low level proxy functions. **********************************


// Send messages to the openflow agent to keep the connection alive.
void keepAlive(int switchsock){
    cout << "starting keepalive echo thread." << endl;
    std::this_thread::sleep_for(std::chrono::microseconds(1000000));        
    char msg[8];
    ofp_header * hdr = (ofp_header *) msg;
    hdr -> version = 3;
    hdr -> type = 0x02;
    hdr -> length = htons(16);
    hdr -> xid = htonl(666);
    while (0){
        cout << "sending keepalive echo." << endl;
        switchMtx.lock();
        write(switchsock, msg, 8);
        switchMtx.unlock();
        cout << "keepalive echo send from proxy to openflow agent." << endl;
        // send once per second.
        std::this_thread::sleep_for(std::chrono::microseconds(1000000));        
    }
}

// Direction: 1 = client to server (switch to controller)
// 2 = server to client (controller to switch)
unsigned int transfer(int from, int to, int direction)
{
    char buf[BUF_SIZE];
    unsigned int disconnected = 0;
    size_t bytes_read, bytes_written, more_read;
    bytes_read = read(from, buf, 8);
    while (bytes_read < 8){
        more_read = read(from, buf+bytes_read, BUF_SIZE);
        bytes_read+= more_read;
    }
    // Grab at least 1 full openflow message.
    ofp_header * tmpHdr = (ofp_header *) buf;
    size_t read_left = ntohs(tmpHdr->length) - bytes_read;
    // cout << " Read left: " << read_left << endl;
    while (read_left>0){
        more_read = read(from, buf+bytes_read, read_left);
        bytes_read += more_read;
        read_left = ntohs(tmpHdr->length) - bytes_read;        
        // cout << "\tRead left: " << read_left << endl;
    }
    // cout << "READ " << bytes_read << " BYTES ( " << direction << " )" << endl;
    // Process controller -> switch packets, because the packet_outs 
    if (direction == 2){
        disconnected = processControllerMessage(to, buf, bytes_read);
    }
    // Process switch --> controller packets
    else{
        disconnected = processSwitchMessage(to, buf, bytes_read);
    }
    if (disconnected == 1){
        cout << " got disconnected in direction: " << direction << endl;
    }

    return disconnected;
}

void handle(int client, const char *remote_host, const char *remote_port, int dpsock)
{
    int server = -1; // socket to controller.
    unsigned int disconnected = 0;
    fd_set set;
    unsigned int max_sock;

    // Manually build the address info based on input. 
    sockaddr_in clientAddr;
    clientAddr.sin_family = AF_INET;
    clientAddr.sin_port = htons(atoi(remote_port));
    inet_pton(AF_INET, remote_host, &clientAddr.sin_addr);
    memset(&clientAddr.sin_zero, 0, 8);

    cout << "opening socket to server" << endl;
    /* Create the socket */
    server = socket(AF_INET, SOCK_STREAM, 0);
    if (server == -1) {
        perror("socket");
        close(client);
        return;
    }

    cout << "connecting socket to server" << endl;
    /* Connect to the host */
    if (connect(server,  (sockaddr *)&clientAddr, sizeof(clientAddr)) == -1) {
        perror("connect");
        close(client);
        return;
    }

    if (client > server) {
        max_sock = client;
    }
    else {
        max_sock = server;
    }

    /* Main transfer loop */
    cout << "connection to server established. starting main transfer loop." << endl;
    while (1) {
        FD_ZERO(&set);
        FD_SET(client, &set);
        FD_SET(server, &set);
        FD_SET(dpsock, &set); // also read from dp socket.
        if (select(max_sock + 1, &set, NULL, NULL, NULL) == -1) {
            perror("select");
            break;
        }
        // transfer from switch to controller.
        if (FD_ISSET(client, &set)) {
            disconnected = transfer(client, server, 1);
        } // transfer from controller to switch.
        if (FD_ISSET(server, &set)) {
            disconnected = transfer(server, client, 2);
        }
        // Handle a message on the data plane port.
        if (FD_ISSET(dpsock, &set)) {
            processDpMessage(dpsock);
        }
    }
    close(server);
    close(client);
}

//****************** Raw socket functions **********************************


// create a raw socket.
int create_rawsocket(int protocol_to_sniff)
{
    int rawsock;
    if((rawsock = socket(PF_PACKET, SOCK_RAW, htons(protocol_to_sniff)))== -1)
    {
        perror("Error creating raw socket: "); exit(-1);
    }
return rawsock; 
}

// bind to a raw socket.
int bind_rawsocket(char *device, int rawsock, int protocol) 
{
    struct sockaddr_ll sll;
    struct ifreq ifr;
    bzero(&sll, sizeof(struct sockaddr_ll));
    bzero(&ifr, sizeof(struct ifreq));
    /* First Get the Interface Index */
    strncpy((char *)ifr.ifr_name, device, IFNAMSIZ); 
    if((ioctl(rawsock, SIOCGIFINDEX, &ifr)) == -1)
    {
        printf("Error getting Interface index !\n"); 
        exit(-1); 
    }
    /* Bind our raw socket to this interface */
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(protocol);
    if((bind(rawsock, (struct sockaddr *)&sll, sizeof(sll)))== -1)
    {
        printf("Error binding raw socket to interface\n"); 
        exit(-1);
    }
    return 1; 
}


// Sends a raw packet to the data path. 
int send_rawpacket(int rawsock, char *pkt, int pkt_len)
{
    char taggedpkt[pkt_len + 4];
    int taggedlen = tag_packet(taggedpkt, pkt, pkt_len, 66);
    // cout << "sending packet back down to switch. " << endl;
    // cout << "\toriginal length: " << pkt_len << " tagged length: " << taggedlen << endl;
    datapathMtx.lock();
    int sent=write(rawsock, taggedpkt, taggedlen);
    datapathMtx.unlock();
    if((sent) != taggedlen)
    {
        if (sent == -1){
            perror("socket write error.\n");
            exit(-1);
        }
        printf("Could only send %d bytes of packet of length %d\n", sent, taggedlen);
        return 0; 
    }
    return 1; 
}


//****************** convenience functions **********************************
int print_pkt(char * bytes, int len){
    char textBuf[2*len+1];
    for(int j = 0; j < sizeof(bytes); j++)
        sprintf(&textBuf[2*j], "%02X", bytes[j]);
    textBuf[2*len] = 0;
    cout << textBuf << endl;    
}

void print_hex_memory(void *mem, int len) {
  int i;
  unsigned char *p = (unsigned char *)mem;
  for (i=0;i<len;i++) {
    printf("0x%02x ", p[i]);
    if (i%16==0)
      printf("\n");
  }
  printf("\n");
}

// Put a vlan tag on a packet. Return new length.
int tag_packet(char * dstBuf, char * srcBuf, int packetlen, int tag){
    struct vlan_ethhdr* vlanHeader = (vlan_ethhdr*) dstBuf;
    struct ethhdr * ethHeader = (ethhdr*) srcBuf;
    memcpy(vlanHeader, ethHeader, ETH_ALEN*2);
    vlanHeader -> ether_type = ethHeader -> h_proto;
    vlanHeader -> h_vlan_proto = htons(0x8100);
    vlanHeader -> h_vlan_TCI = htons(tag);
    memcpy( (char *)dstBuf+sizeof(vlan_ethhdr), (char *)srcBuf+sizeof(ethhdr), packetlen - sizeof(ethhdr));        
    return packetlen -sizeof(ethhdr) + sizeof(vlan_ethhdr);
}


// Strip a vlan tag from a packet. Return new length. 
int untag_packet(char *dstBuf, char * srcBuf, int packetlen){
    struct vlan_ethhdr* vlanHeader = (vlan_ethhdr*) srcBuf;
    struct ethhdr * ethHeader = (ethhdr*) dstBuf;
    memcpy(ethHeader, vlanHeader, ETH_ALEN*2);
    ethHeader -> h_proto = vlanHeader -> ether_type;
    memcpy( (char*) dstBuf + sizeof(ethhdr), (char*) srcBuf + sizeof(vlan_ethhdr), packetlen - sizeof(vlan_ethhdr));    

    // cout << " original packet:" << endl;
    // cout << " ---------------------------" << endl;
    // print_hex_memory((void *) srcBuf, packetlen);
    // cout << " ---------------------------" << endl;
    // cout << " after strip:" << endl;
    // cout << " ---------------------------" << endl;
    // print_hex_memory((void *) dstBuf, packetlen-4);
    // cout << " ---------------------------" << endl;

    return packetlen - sizeof(vlan_ethhdr) + sizeof(ethhdr);
}

long long current_timestamp() {
    struct timeval te; 
    gettimeofday(&te, NULL); // get current time
    long long microseconds = te.tv_sec*1000000LL + te.tv_usec; // caculate milliseconds
    // printf("milliseconds: %lld\n", milliseconds);
    return microseconds;
}

