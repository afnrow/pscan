#ifndef LOG_H
#define LOG_H

#include <stdint.h>
#include <stdio.h>

struct pcap_global_header {
  uint32_t magic_number;
  uint16_t version_major;
  uint16_t version_minor;
  int32_t thiszone;
  uint32_t sigfigs;
  uint32_t snaplen;
  uint32_t network;
}__attribute__((packed));

struct pcap_packet_header {
  uint32_t ts_sec;
  uint32_t ts_usec;
  uint32_t incl_len;
  uint32_t orig_len;
};

struct shb {
    uint32_t block_type; 
    uint32_t block_total_length;
    uint32_t byte_order_magic; 
    uint16_t major_version; 
    uint16_t minor_version; 
    int64_t  section_len;
};

struct idb {
  uint32_t block_type;
  uint32_t block_total_length;
  uint16_t link_type;
  uint16_t reserved;
  uint32_t snaplen;
  uint32_t block_total_length2;
};

struct epb {
  uint32_t block_type;
  uint32_t block_total_length;
  uint32_t interface_id;
  uint32_t ts_high;
  uint32_t ts_low;
  uint32_t cap_len;
  uint32_t orig_len;
}__attribute__((packed));

int logger_write_packet(FILE *fd, const uint8_t *packet, uint32_t length , char *ext);
void logger_close(FILE *fd);

#endif
