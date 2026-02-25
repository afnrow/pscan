#define _GNU_SOURCE
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include "scan.h"
#include <getopt.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include "global.h"
#include <sys/syscall.h>
#include <fcntl.h>

#define OPT_FILTER 1000

volatile sig_atomic_t running = 1;

struct filter_args
{
  char *ip;
  char *dip;
  int proto;
  int targetport;
};

void parse_filter(const char *arg, struct filter_args *f)
{
  if (!arg) return;
  char *tmp = strdup(arg);
  char *tok = strtok(tmp, ",");
  while (tok)
  {
      if (strncmp(tok, "ip=", 3) == 0) f->ip = strdup(tok + 3);
      else if (strncmp(tok, "dip=", 4) == 0) f->dip = strdup(tok + 4);
      else if (strncmp(tok, "proto=", 6) == 0) f->proto = atoi(tok + 6);
      else if (strncmp(tok, "port=", 5) == 0) f->targetport = atoi(tok + 5);
      tok = strtok(NULL, ",");
    }
  free(tmp);
}

int load_module(struct filter_args *f)
{
  int fd = open("filter.ko" , O_RDONLY);
  if (fd < 0)
  {
    perror("Loading NetFilter Module");
    return -1;
  }
  char params[256];
  snprintf(params, sizeof(params), "ip=%s dip=%s targetport=%d proto=%d", 
         f->ip ? f->ip : "", 
         f->dip ? f->dip : "", 
         f->targetport, 
         f->proto);
  if (syscall(SYS_finit_module , fd , params , 0) != 0)
  {
    perror("finit_module failed");
    close(fd);
    return -1;
  }
  printf("Loaded Module with: %s\n" , params);
  close(fd);
  return 0;
}

void unload_module()
{
  int ret = syscall(SYS_delete_module , "filter" , O_NONBLOCK);
  if (ret != 0)
  {
    perror("delete_module");
    fprintf(stderr , "Please Restart Your Device To Unload The Module");
  }
  printf("Unloaded Module\n");
}

void handle_sigint(int sig)
{
   (void)sig;
   running = 0;
}

int main(int argc , char *argv[])
{
  char *filename = NULL;
  int module_loaded = 0;
  struct option options[] = {
    {"file" , no_argument , 0 , 'f'},
    {"help" , no_argument , 0 , 'h'},
    {"filter" , required_argument , 0 , OPT_FILTER},
    {0,0,0,0}
  };
  int opt;
  struct filter_args f = {0};
  while ((opt = getopt_long(argc , argv , "f:h" , options , NULL)) != -1)
  {
    switch (opt)
    {
      case 'f':
        filename = optarg;
        break;
      case OPT_FILTER:
        parse_filter(optarg, &f);
        if (load_module(&f) == 0) module_loaded = 1;
        break;
      default:
        fprintf(stderr ,  "Usage: %s [-f filename] [-filter targetport ip dip proto]\n" , argv[0]);
        exit(EXIT_FAILURE);
    }
  }
  int fd  = socket(AF_PACKET , SOCK_RAW , htons(ETH_P_ALL));
  if (fd < 0) return 1;
  struct tpacket_req3 req;
    memset(&req, 0, sizeof(req));
    req.tp_block_size = 4096 * 10;      
    req.tp_frame_size = 2048;          
    req.tp_block_nr = 100;            
    req.tp_frame_nr = (req.tp_block_size * req.tp_block_nr) / req.tp_frame_size;
    req.tp_retire_blk_tov = 60;      
    req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;
  signal(SIGINT , handle_sigint);
  scan(fd , req , filename);
  if (module_loaded) unload_module();
  close(fd);
  return 0;
}
