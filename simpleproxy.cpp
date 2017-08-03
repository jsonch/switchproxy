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


int send_rawpacket(int rawsock, char *pkt, int pkt_len);




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


#define OFP_NO_BUFFER 0xffffffff


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

int dpPktCt = 0;

// How many MS to wait before sending back the packet. 
long long timeLimit;
// How often to check for timeouts.
unsigned int sleepTime;
// Minimum length of time to wait before sending a packet out.
long long minLen;

std::unordered_map<std::string, deque<long long>> packetToTses;
// Packets, in the order that they arrived.
deque<std::string> packets;
deque<long long> tses;

std::mutex mtx;           // mutex for critical section


std::mutex switchMtx;           // mutex for critical section
std::mutex controllerMtx;           // mutex for critical section
std::mutex datapathMtx;           // mutex for critical section


long long current_timestamp() {
    struct timeval te; 
    gettimeofday(&te, NULL); // get current time
    long long microseconds = te.tv_sec*1000000LL + te.tv_usec; // caculate milliseconds
    // printf("milliseconds: %lld\n", milliseconds);
    return microseconds;
}

// Remove a packet from the to timeout queue. 
long long removedPacketDuration = 0;
int removedPacketCt = 0;
long long maxRemovedPacketDuration = 0;
long long minRemovedPacketDuration = 10;


int dpsock; // socket to datapath. 
int server = -1; // socket to controller.

int removePacket(char *packet, int packetLen){
    // return -1;
    string packetStr = string(packet, packet+packetLen);
    // Enter locked area.
    mtx.lock();
    auto got = packetToTses.find(packetStr);
    // Did not find packet.. Can we assume it timed out already?
    // In any normal switch, yes.
    if (got == packetToTses.end()){
        // cout << "DID NOT FIND PACKET IN TIMEOUT QUEUE." << endl;
        // cout << "length: " << packetLen << endl;
        mtx.unlock();
        return -1;
        // packetToTses.emplace(packetStr, std::vector<long long>());
    }
    // Found a packet. Remove the earliest one to be sent up.
    else{
        // cout << "FOUND PACKET IN TIMEOUT QUEUE AT " << current_timestamp() << " , REMOVING." << endl;
        // cout << "\ttimestamp "<<packetToTses[packetStr].front()<<endl;
        if (packetToTses[packetStr].size() > 0){
            long long pktDuration = (current_timestamp()-packetToTses[packetStr].front());
            if (pktDuration > maxRemovedPacketDuration){
                maxRemovedPacketDuration = pktDuration;
            }
            if (pktDuration < minRemovedPacketDuration){
                minRemovedPacketDuration = pktDuration;
            }
            // send back down if its been here long enough.
            if (pktDuration>minLen){            	
	            removedPacketDuration += pktDuration;           
	            removedPacketCt += 1;
	            packetToTses[packetStr].pop_front();
	            // cout << "sending packet back down." << endl;
	            }
	        // If not, just leave it in the queue.
	        else{
	        	// cout << " got packet, but not here long enough." << endl;
	        	mtx.unlock();
	        	return -1;
	        }
        }
        // If there are no packets in this queue, they already timed out..
        else{
            // cout << "already timed out, but found an entry.." << endl;
            mtx.unlock();
            return -1;
        }
        if (packetToTses[packetStr].size() == 0){
            packetToTses.erase(packetStr);
        }

        // cout << "\t remaining packets: " << packetToTses[packetStr].size() << endl;
        // cout << "tses: ";
        // for (auto timestamp : packetToTses[packetStr]){
        //     cout << timestamp << " ; ";
        // }
        // cout << endl;
    }
    // Leave locked area.
    mtx.unlock();

    // cout << "sent controller message for packet at " << current_timestamp() << " : ";
    // for (int i=0; i<6; i++){
    //     cout << std::hex << setw(2) << setfill('0') << static_cast<int>(static_cast<unsigned char>(packetStr.data()[i]));
    // }
    // cout << std::dec;
    // cout << endl;
    // Packet is OK to be sent back down to the switch....
    send_rawpacket(dpsock, packet, packetLen);
    return -1;
    return 1;
}



#define OFPT_PACKET_OUT 13
#define OFPT_PACKET_IN 10
/* Header on all OpenFlow packets. */
struct ofp_header {
    uint8_t version;
    uint8_t type;
    uint16_t length;
    uint32_t xid;
};

struct ofp_action_header{
    uint16_t type;
    uint16_t len;
    uint8_t pad;
};

/* Fields to match against flows */
struct ofp_match {
uint16_t type;             /* One of OFPMT_* */
uint16_t length;           /* Length of ofp_match (excluding padding) */
uint8_t oxm_fields[4];     /* OXMs start here - Make compiler happy */
};

struct ofp_packet_in {
    struct ofp_header header;
    uint32_t buffer_id;
    uint16_t total_len;
    uint8_t reason;
    uint8_t tbl_id;
    struct ofp_match match;
    uint16_t pad;
    uint8_t data[0];
};



struct ofp_packet_out {
    struct ofp_header header;
    uint32_t buffer_id;
    uint32_t in_port;
    uint16_t actions_len;
    uint8_t pad[6];
    struct ofp_action_header actions[0];
    uint8_t data[0];
};


struct oxm_header {
    uint16_t oxm_class;
    uint8_t oxm_field;
    uint8_t oxm_length;
    uint8_t oxm_payload[0];
};

// int processSwitchMessage(char *pkt, size_t pkt_len){
//     char * currentPtr = pkt;
//     cout << "packet from siwtch to controller (" << pkt_len << " bytes)" << endl;
//     while (currentPtr < pkt+pkt_len){
//         int retVal = 1; // allow message, because it hasn't timed out yet.
//         ofp_header *ofpHdf = (ofp_header*) currentPtr;
//         // cout << "got an OF message from controller to switch.. (" << ntohs(ofpHdf->length) << " bytes)" << endl;
//         if (ofpHdf->type == OFPT_PACKET_IN){
//             cout << "got a packet in" << endl;
//             ofp_packet_in *pktInHeader = (ofp_packet_in*) pkt;
//             cout << "info" << endl;
//             cout << "\theader version: " << (int) pktInHeader ->header.version << endl;
//             cout << "\theader type: " << (int) pktInHeader ->header.type << endl;
//             cout << "\theader length: " << (int) pktInHeader ->header.length << endl;
//             cout << "\theader xid: " <<pktInHeader ->header.xid << endl;
//             cout << "\tbuffer ID: " << pktInHeader->buffer_id << endl;
//             cout << "\ttotal len: " << pktInHeader->total_len << endl;
//             cout << "\treason: " << (int)pktInHeader->reason << endl;
//             cout << "\ttbl_id: " << (int)pktInHeader->tbl_id << endl;
//             cout << "\tmatch type: " << (int)pktInHeader->match.type << endl;
//             cout << "\tmatch len: " << (int)pktInHeader->match.length << endl;
//             if (pktInHeader->match.length > 0){
//                 cout << sizeof(oxm_header) << endl;
//                 oxm_header *oxh = (oxm_header *) &pktInHeader->match.oxm_fields;
//                 cout << "\t oxm class: " << (int)oxh ->oxm_class << endl;
//                 cout << "\t oxm field: " << (int)oxh ->oxm_field << endl;
//                 cout << "\t oxm length: " << (int)oxh ->oxm_length << endl;
//                 uint32_t * in_port = (uint32_t *) oxh->oxm_payload;
//                 cout << "\t oxm payload: " << ntohl(*in_port) << endl;
//                 // cout << "\t oxm class: " << pktInHeader->match.oxm_fields
//                 cout << "\tpayload offset: " << (char *)pktInHeader -> data - (char *)pktInHeader + (int)oxh ->oxm_length << endl;
//             }
//             cout << "packet in contents:" << endl;
//             cout << "_____________________________" << endl;
//             print_hex_memory(pktInHeader, pktInHeader->header.length);
//             cout << "_____________________________" << endl;
//             // char textBuf[2*sizeof(vlan_ethhdr)+1];
//             // for(int j = 0; j < sizeof(vlan_ethhdr); j++)
//             //     sprintf(&textBuf[2*j], "%02X", pktBuf[j]);
//             // textBuf[2*sizeof(vlan_ethhdr)] = 0;
//             // cout << textBuf << endl;

//         }
//         currentPtr+= ntohs(ofpHdf->length);
//     }

// }

// process a message from controller to switch.
// Might contain multiple OF messages!
int processControllerMessage(int outSocket, char *pkt, size_t pkt_len){
    char * currentPtr = pkt;
    // cout << "start packet. (" << pkt_len << " bytes)" << endl;
    while (currentPtr < pkt+pkt_len){
        int retVal = 1; // allow message, because it hasn't timed out yet.
        ofp_header *ofpHdf = (ofp_header*) currentPtr;
        // cout << "got an OF message from controller to switch.. (" << ntohs(ofpHdf->length) << " bytes)" << endl;
        if (ofpHdf->type == OFPT_PACKET_OUT){
            // cout << "\t its a packet out" << endl;
            // Figure out how many bytes the actions are.
            ofp_packet_out *ofpMsg = (ofp_packet_out*) currentPtr;
            int ethPktLen = ntohs(ofpMsg->header.length) - sizeof(ofp_packet_out) - ntohs(ofpMsg->actions_len);

            char *ethPkt = (char *)ofpMsg->data+ntohs(ofpMsg->actions_len);
            // cout << "\tsize of message: " << ntohs(ofpMsg -> header.length) << endl;
            // cout << "\tsize of actions: " << ntohs(ofpMsg -> actions_len);
            // cout << "\tsize of packet out struct: " << sizeof(ofp_packet_out) << endl;            
            // cout << "\t eth packet length: " << ethPktLen << endl;
            // cout << (unsigned int) ofpMsg -> actions << endl;
            // cout << (unsigned int) ofpMsg -> data << endl;
            retVal = removePacket(ethPkt, ethPktLen);
            if (retVal == 1){
                cout << " retval = 1 from removepacket." << endl;
            }
        }
        if (retVal == 1){
            // cout << "WRITING PACKET" << endl;
            // cout << "type: " << (int)ofpHdf ->type << endl;
            switchMtx.lock();
            int bytes_sent = write(outSocket, currentPtr, ntohs(ofpHdf->length));
            switchMtx.unlock();
            // cout << "WRITING PACKET DONE" << endl;
            if (bytes_sent == -1) return 1;
        }
        // else{
        //     cout << "DROPPING PACKET!" << endl;
        // }
        currentPtr+= ntohs(ofpHdf->length);
    }
    // cout << "end packet." << endl;
    return 0; // not disconnected
}

// Sends a raw packet. Needs to have a tag.
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

long long timeInQueue = 0;
float evictedCt = 0;

unsigned int timeoutCount = 0;
void sendBackToSwitch(string packetStr, int dpsock){
    // char buf[packetStr.size()];
    // memcpy(buf, packetStr.data(), packetStr.size());
    send_rawpacket(dpsock, (char *)packetStr.data(), packetStr.size());
    timeoutCount++;
    // if ((timeoutCount % 100) == 0){
    //     cout << timeoutCount << " control requests have times out so far." << endl;
    // }
    // cout << "sent " << packetStr.size() << " bytes to the switch." << endl;
    // cout << "\t(sent " << timeoutCount << " packets back to switch, overall)" << endl;
    return;
}

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

long long lastTime = 0;
long long maxTimeInQueue = 0;
void timerLoop(int dpsock){
    while (1){

        // get current time. 
        long long currentTime = current_timestamp();
        // cout << "time since last: " << currentTime-lastTime << endl;
        lastTime = currentTime;

        if (tses.size()>0){
            // Enter locked area.
            mtx.lock();
            long long ts = tses.front();
            string packet = packets.front();
            // For all expired events, find the packet and send it 
            // back to the switch. If no packet, send nothing back.
            while ((currentTime - ts) > timeLimit){
                // cout << "-----" << endl;
                auto index = find(packetToTses[packet].begin(), packetToTses[packet].end(), ts);
                if (index!=packetToTses[packet].end()){
                    // cout << "at " << currentTime << " found expired packet with the right TS: " << ts << endl;
                    long long val = *index;
                    // cout << "real ts: " << val << endl;
                    long long diff = (current_timestamp()  - ts);
                    if (diff > maxTimeInQueue){
                        maxTimeInQueue = diff;
                    }

                    timeInQueue += diff;
                    evictedCt += 1;
                    // cout << "its been here for: " << diff << " ms" << endl;
                    // Send to switch here.
                    // cout << "erasing element at index: " << index-packetToTses[packet].begin() << endl;
                    sendBackToSwitch(packet, dpsock);
                    packetToTses[packet].erase(index);
                }
                // Remove the packet from the timeout queue, if this was the last entry for it.
                if (packetToTses[packet].empty()){
                    // cout << "erasing entry for packet at " << current_timestamp() << " : ";
                    // for (int i=0; i<6; i++){
                    //     cout << std::hex << setw(2) << setfill('0') << static_cast<int>(static_cast<unsigned char>(packet.data()[i]));
                    // }
                    // cout << std::dec;
                    // cout << endl;
                    packetToTses.erase(packet);
                }
                // cout << "-----" << endl;
                tses.pop_front();
                packets.pop_front();            
                if ((tses.size()>0)) {
                    ts = tses.front();
                    packet = packets.front();
                    if ((currentTime - ts) <= timeLimit) break;
                }
                else break;
            }
            // Leave locked area.
            mtx.unlock();
        }
        // sleep for 1 ms.
        std::this_thread::sleep_for(std::chrono::microseconds(sleepTime));
    }
}

// Headers for when you just send a packet_in with in_port. (OpenFlow 1.2)
struct oxm_header_in_port {
    uint16_t oxm_class;
    uint8_t oxm_field;
    uint8_t oxm_length;
    uint32_t in_port;    
};

struct ofp_match_in_port {
    uint16_t type;
    uint16_t length;
    struct oxm_header_in_port oxm_inport;
    uint32_t padding;    
};

struct ofp_packet_in_in_port {
    struct ofp_header header;
    uint32_t buffer_id;
    uint16_t total_len;
    uint8_t reason;
    uint8_t tbl_id;
    struct ofp_match_in_port match;
    // uint8_t pad[2];
    // uint8_t data[0];
};


int packetId = 0;
// Encapsulate packets from the datapath in a packet_in,  
// and send them to the controller.
void handleDpMessage(int dpsock){
    // New packet from the datapath. Add it to the timeout queue.
    struct vlan_ethhdr* vlanHeader;
    struct ethhdr * ethHeader;
    char strippedPktBuf[BUF_SIZE-4];

    char pktBuf[BUF_SIZE];
    int bytesRead = read(dpsock, pktBuf, BUF_SIZE);


    // Send the packet back down.
    // send_rawpacket(dpsock, pktBuf, bytesRead);

    // cout << "packet # " << packetId << endl;
    // packetId++;
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

    // Extract vlan id from header.
    vlanHeader = (struct vlan_ethhdr*)pktBuf;
    uint16_t vlan_proto = ntohs(vlanHeader->h_vlan_proto);
    if (vlan_proto!= 0x8100){
        // cout << "got a non-vlan packet. Discarding." << endl;
        return;
    }
    // cout << "got vlan packet." << endl;
    // cout << "raw TCI: " << vlanHeader->h_vlan_TCI << endl;
    uint16_t tci = ntohs(vlanHeader->h_vlan_TCI);
    // cout << "ntohs TCI: " << vlanHeader->h_vlan_TCI << endl;
    unsigned  mask;
    mask = (1 << 12) - 1;
    uint16_t vid = tci & mask;    
    // if (vid == 66){
    //     // cout << "got a vid 66 packet. Dropping." << endl;
    // }
    // cout << "\tvlan id: " << vid << endl;
    int strippedLen = untag_packet(strippedPktBuf, pktBuf, bytesRead);

    // cout << " original length: " << bytesRead << " stripped length: " << strippedLen << endl;
    // char retaggedPkt[BUF_SIZE];
    // tag_packet(retaggedPkt, strippedPktBuf, strippedLen, vid);
    // int res = memcmp(retaggedPkt, pktBuf, bytesRead);
    // if (res == 0) {
    //     cout << "packet the same after strip / retag" << endl;        
    // }
    // else {
    //     cout << " packet changed after strip / retag" << endl;
    // }


    // cout << sizeof(ofp_packet_in_in_port) << endl;
    // cout << sizeof(ofp_match_in_port) << endl;
    // cout << sizeof(oxm_header_in_port) << endl;

    // cout << sizeof(ofp_packet_in) << endl;
    // cout << sizeof(oxm_header) << endl;

    // Now, pack this into a message to the controller.
    // header length: 94
    // packet length: 60
    // packet starts @ 34...
    // header = 8
    // up to tbl_id = 16
    // match + pad = 18
    // match = 16 
    // pad = 2



    char pktInBuf[sizeof(ofp_packet_in_in_port)+2+strippedLen];
    ofp_packet_in_in_port *pktInHeader = (ofp_packet_in_in_port*) pktInBuf;
    // pktInHeader -> header.
    pktInHeader -> header.version = 3;
    pktInHeader -> header.type = OFPT_PACKET_IN;
    pktInHeader -> header.length = htons(sizeof(ofp_packet_in_in_port)+2+strippedLen);
    pktInHeader -> header.xid = htonl(0);
    pktInHeader -> buffer_id = OFP_NO_BUFFER;
    pktInHeader -> total_len = htons(strippedLen);
    pktInHeader -> reason = 0x01;
    pktInHeader -> tbl_id = 0x00;
    pktInHeader -> match.type = htons(1);
    pktInHeader -> match.length = htons(sizeof(pktInHeader->match)-sizeof(pktInHeader->match.padding));
    pktInHeader -> match.oxm_inport.oxm_class = htons(0x8000);
    pktInHeader -> match.oxm_inport.oxm_field = 0;
    pktInHeader -> match.oxm_inport.oxm_length = 4; // length of the payload.
    pktInHeader -> match.oxm_inport.in_port = htonl(vid);

    pktInHeader -> match.padding =  0x00000000;
    // pktInHeader -> pad[0] = 0x00;
    // pktInHeader -> pad[1] = 0x00;
    // Get that nasty padding in there..
    memset(pktInBuf+ sizeof(ofp_packet_in_in_port), 0, 2);
    memcpy(pktInBuf + sizeof(ofp_packet_in_in_port) + 2, strippedPktBuf, strippedLen);
    // cout << "\tpayload offset: " << sizeof(ofp_packet_in_in_port)+ 2 << endl;

    // cout << "GENERATED MESSAGE DETAILS:" << endl;
    // cout << "---------------------------" << endl;
    // ofp_packet_in *pktInHeader2 = (ofp_packet_in*) pktInBuf;
    // cout << "info" << endl;
    // cout << "\theader version: " << (int) pktInHeader2 ->header.version << endl;
    // cout << "\theader type: " << (int) pktInHeader2 ->header.type << endl;
    // cout << "\theader length: " << (int) pktInHeader2 ->header.length << endl;
    // cout << "\theader xid: " << pktInHeader2 ->header.xid << endl;
    // cout << "\tbuffer ID: " << pktInHeader2->buffer_id << endl;
    // cout << "\ttotal len: " << pktInHeader2->total_len << endl;
    // cout << "\treason: " << (int)pktInHeader2->reason << endl;
    // cout << "\ttbl_id: " << (int)pktInHeader2->tbl_id << endl;
    // cout << "\tmatch type: " << (int)pktInHeader2->match.type << endl;
    // cout << "\tmatch len: " << (int)pktInHeader2->match.length << endl;
    // if (pktInHeader2->match.length > 0){
    //     cout << sizeof(oxm_header) << endl;
    //     oxm_header *oxh = (oxm_header *) &pktInHeader2->match.oxm_fields;
    //     cout << "\t oxm class: " << (int)oxh ->oxm_class << endl;
    //     cout << "\t oxm field: " << (int)oxh ->oxm_field << endl;
    //     cout << "\t oxm length: " << (int)oxh ->oxm_length << endl;
    //     uint32_t * in_port = (uint32_t *) oxh->oxm_payload;
    //     cout << "\t oxm payload: " << ntohl(*in_port) << endl;
    //     // cout << "\t oxm class: " << pktInHeader2->match.oxm_fields
    // }

    // cout << "packet in contents:" << endl;
    // cout << "_____________________________" << endl;
    // print_hex_memory(pktInHeader, pktInHeader->header.length);
    // cout << "_____________________________" << endl;

    // cout << "---------------------------" << endl;


    // Send message to controller. 
    // cout << "writing " << pktInHeader -> header.length << " bytes to the controller" << endl;
    controllerMtx.lock();
    write(server, pktInBuf, pktInHeader -> header.length);
    controllerMtx.unlock();
    // Add the stripped packet to the timeout queue.
    std::string packetStr = std::string(strippedPktBuf, strippedPktBuf + strippedLen);
    long long  arrivalTs = current_timestamp();
    // Enter locked area.
    mtx.lock();
    auto got = packetToTses.find(packetStr);
    if (got == packetToTses.end()){
        packetToTses[packetStr] = std::deque<long long>();
        // old g++ doesn't support emplace.
        // packetToTses.emplace(packetStr, std::deque<long long>());
    }
    // cout << "packet arriving at: " << arrivalTs << endl;
    packetToTses[packetStr].push_back(arrivalTs);
    packets.push_back(packetStr);
    tses.push_back(arrivalTs);
    // Leave locked area.
    mtx.unlock();

    if ((dpPktCt % 1000) == 0){
        cout << timeoutCount << " requests to the controller timed out." << endl;
        cout << "average time to timeout: " << float(timeInQueue)/float(evictedCt) << endl;
        cout << "max time to timeout: " << float(maxTimeInQueue) << endl;
        cout << removedPacketCt << " responses from controller sent. " << endl;
        cout << " average controller response time: " << float(removedPacketDuration)/float(removedPacketCt) << endl;
        cout << " max controller response time: " << float(maxRemovedPacketDuration) << endl;
        cout << " min controller response time: " << float(minRemovedPacketDuration) << endl;
    }
    dpPktCt++;
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
    // might need to be dropped.
    if (direction == 2){
        // This handles all the writing to the switch.
        disconnected = processControllerMessage(to, buf, bytes_read);
    }
    else{
        // processSwitchMessage(buf, bytes_read);
        controllerMtx.lock();
        bytes_written = write(to, buf, bytes_read);
        controllerMtx.unlock();            
        if (bytes_written == -1) {
            disconnected = 1;
        }
    }
    if (disconnected == 1){
        cout << " got disconnected in direction: " << direction << endl;
    }

    return disconnected;
}

void handle(int client, const char *remote_host, const char *remote_port, int dpsock)
{
    unsigned int disconnected = 0;
    fd_set set;
    unsigned int max_sock;

    // Manually build the address info based on input. 
    sockaddr_in clientAddr;
    clientAddr.sin_family = AF_INET;
    clientAddr.sin_port = htons(atoi(remote_port));
    inet_pton(AF_INET, remote_host, &clientAddr.sin_addr);
    memset(&clientAddr.sin_zero, 0, 8);


    /* Create the socket */
    server = socket(AF_INET, SOCK_STREAM, 0);
    if (server == -1) {
        perror("socket");
        close(client);
        return;
    }

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
            handleDpMessage(dpsock);
        }
    }
    close(server);
    close(client);
}

int main(int argc, char **argv)
{
    int sock;
    int reuseaddr = 1; /* True */
    const char *local_host, *local_port, *remote_host, *remote_port;

    /* Get the server host and port from the command line */
    if (argc < 3) {
        fprintf(stderr, "Usage: tcpproxy local_host local_port remote_host remote_port datapath_device_name TIMEOUT_LEN CHECK_INTERVAL MIN_LEN \n");
        return 1;
    }
    local_host = argv[1];
    local_port = argv[2];
    remote_host = argv[3];
    remote_port = argv[4];

    char * devicename = argv[5];
    timeLimit = atoi(argv[6]);
    sleepTime = atoi(argv[7]);
    minLen = atoi(argv[8]);
    cout << "time out: " << timeLimit <<  " microseconds" << endl;
    cout << "\t (i.e. " << double(timeLimit)/1000.0 << " milliseconds )" << endl;
    cout << "checking every: " << sleepTime << " microseconds" << endl;
    cout << "keeping packets for at least: " <<minLen << " microseconds" << endl;



    // Manually build the address info based on input. 
    sockaddr_in listenAddr;
    listenAddr.sin_family = AF_INET;
    listenAddr.sin_port = htons(atoi(local_port));
    inet_pton(AF_INET, local_host, &listenAddr.sin_addr);
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

    /* Create the socket to the datapath */
    printf("opening socket to datapath.\n");
    dpsock = create_rawsocket(ETH_P_ALL);
    printf ("binding to DATAPATH interface %s \n",devicename);
    bind_rawsocket(devicename, dpsock, ETH_P_ALL);
    printf ("done binding.\n");
    // Start the timeout loop. 
    std::thread th1 (timerLoop, dpsock);
    printf("thread started\n");

    /* Main loop */
    while (1) {
        socklen_t size = sizeof(struct sockaddr_in);
        struct sockaddr_in their_addr;
        int newsock = accept(sock, (struct sockaddr*)&their_addr, &size);

        if (newsock == -1) {
            perror("accept");
        }
        else {
            printf("Got a connection from %s on port %d\n",
                    inet_ntoa(their_addr.sin_addr), htons(their_addr.sin_port));
            std::thread th2 (keepAlive, newsock);            
            handle(newsock, remote_host, remote_port, dpsock);
        }
    }

    close(sock);

    return 0;
}

