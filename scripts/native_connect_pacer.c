#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
/* Native connect calls are scoped and paced; scanner protocol bytes are untouched. */
int connect(int fd, const struct sockaddr *address, socklen_t length) {
  static int (*real_connect)(int,const struct sockaddr *,socklen_t);
  if (!real_connect) real_connect=dlsym(RTLD_NEXT,"connect");
  if (address->sa_family != AF_INET && address->sa_family != AF_INET6)
    return real_connect(fd,address,length);
  char ip[INET6_ADDRSTRLEN]; int port;
  if(address->sa_family==AF_INET) {
    const struct sockaddr_in *a=(const struct sockaddr_in *)address;
    inet_ntop(AF_INET,&a->sin_addr,ip,sizeof(ip));port=ntohs(a->sin_port);
  } else {
    const struct sockaddr_in6 *a=(const struct sockaddr_in6 *)address;
    inet_ntop(AF_INET6,&a->sin6_addr,ip,sizeof(ip));port=ntohs(a->sin6_port);
  }
  const char *allowed=getenv("TGEN_NATIVE_IP");
  if(!allowed || strcmp(ip,allowed) || (port!=80 && port!=443)) {errno=EACCES;return -1;}
  const char *file=getenv("TGEN_NATIVE_CONNECT_LOG");
  if(!file) {errno=EACCES;return -1;}
  int log=open(file,O_CREAT|O_RDWR,0600);
  if(log<0 || flock(log,LOCK_EX)) {if(log>=0)close(log);errno=EACCES;return -1;}
  struct timespec now;clock_gettime(CLOCK_MONOTONIC,&now);
  double current=now.tv_sec+now.tv_nsec/1e9,last=0;
  char buffer[8192];off_t size=lseek(log,0,SEEK_END);
  off_t start=size>8191?size-8191:0;lseek(log,start,SEEK_SET);
  ssize_t count=read(log,buffer,sizeof(buffer)-1);
  if(count>0) {
    buffer[count]=0;char *line=buffer;
    for(char *cursor=buffer;*cursor;cursor++)if(*cursor=='\n' && cursor[1])line=cursor+1;
    last=strtod(line,NULL);
  }
  double delay=last+0.1-current;
  if(delay>0) {struct timespec wait={(time_t)delay,(long)((delay-(time_t)delay)*1e9)};while(nanosleep(&wait,&wait)&&errno==EINTR){} }
  clock_gettime(CLOCK_MONOTONIC,&now);current=now.tv_sec+now.tv_nsec/1e9;
  lseek(log,0,SEEK_END);dprintf(log,"%.9f %s %d\n",current,ip,port);fsync(log);
  flock(log,LOCK_UN);close(log);
  return real_connect(fd,address,length);
}
