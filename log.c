#include "log.h"
#include <arpa/inet.h>
#include <bits/time.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static inline uint32_t pad4(uint32_t len) { return (len + 3) & ~3; }

int logger_write_packet(FILE *fd, const uint8_t *packet, uint32_t length,
                        char *ext) {
  int fdd = fileno(fd);
  if (fdd < 0 || !packet || length == 0)
    return -1;
  if (strcmp(ext, "pcap") == 0) {
    struct pcap_packet_header ph;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ph.ts_sec = ts.tv_sec;
    ph.ts_usec = ts.tv_nsec / 1000;
    ph.incl_len = length;
    ph.orig_len = length;
    fwrite(&ph, sizeof(ph), 1, fd);
    fwrite(packet, 1, length, fd);
    fflush(fd);
    return 0;
  } else if (strcmp(ext, "pcapng") == 0) {
    struct epb epb;
    epb.block_type = 0x00000006;
    epb.interface_id = 0;
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
      perror("clock_gettime");
      return -1;
    }
    uint64_t t = (uint64_t)ts.tv_sec * 1000000ULL + (ts.tv_nsec / 1000);
    epb.ts_high = (uint32_t)(t >> 32);
    epb.ts_low = (uint32_t)(t & 0xffffffff);
    epb.cap_len = length;
    epb.orig_len = length;
    uint32_t padded_len = pad4(length);
    uint32_t total_len = 28 + padded_len + 4;
    epb.block_total_length = total_len;
    write(fdd, &epb, sizeof(epb));
    write(fdd, packet, length);
    for (uint32_t i = length; i < padded_len; i++) {
      uint8_t zero = 0;
      write(fdd, &zero, 1);
    }
    write(fdd, &epb.block_total_length, 4);
    return 0;
  }
  return 0;
}

void logger_close(FILE *fd) {
  int fdd = fileno(fd);
  if (fd >= 0)
    close(fdd);
}
