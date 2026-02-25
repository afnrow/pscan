#ifndef LOG_H
#define LOG_H

#include <stdint.h>

struct pcap_global_header
{
    uint32_t magic_number;   
    uint16_t version_major;
    uint16_t version_minor;  
    int32_t  thiszone;       
    uint32_t sigfigs;        
    uint32_t snaplen;        
    uint32_t network;        
};

struct pcap_packet_header
{
    uint32_t ts_sec;    
    uint32_t ts_usec;   
    uint32_t incl_len;  
    uint32_t orig_len;  
};

#endif
