#ifndef REAL_STAT_H
#define REAL_STAT_H

#include "libts.h"
#include "P_EventSystem.h"
#include "P_Net.h"

#define MAX_BUCKETS 97
#define MAX_DOMAIN_LEN 256

struct RealStatEntry
{
  LINK(RealStatEntry, hash_link);

  uint32_t key;
  int16_t port;
  int16_t domain_len;
  int64_t out_bytes;
  int64_t rt; // ms
  int64_t hits;
  int32_t memhits;
  int32_t count;
  
  int32_t client_abort; // 0
  int32_t http_info;  // 1xx
  int32_t http_ok;  // 200
  int32_t http_partial_ok;  // 206
  int32_t http_successful;  // 2xx
  int32_t http_move_permanent;  // 301
  int32_t http_found; // 302
  int32_t http_not_modified;  // 304
  int32_t http_redirection; // 3xx
  int32_t http_bad_request; // 400
  int32_t http_forbidden; // 403
  int32_t http_not_found; // 404
  int32_t http_request_timeout; // 408
  int32_t http_precondition_failed; // 412
  int32_t http_range_not_statisfiable;  // 416
  int32_t http_client_error;  // 4xx
  int32_t http_bad_gateway; // 502
  int32_t http_service_unavailable; // 503
  int32_t http_gateway_timeout; // 504
  int32_t http_server_error;  // 5xx
  int32_t http_others;

  char domain[MAX_DOMAIN_LEN];
};

struct RealStatTable
{
  ink_spinlock b_locks[MAX_BUCKETS];
  DList(RealStatEntry, hash_link) buckets[MAX_BUCKETS];

  
  void init();
  void add_one(const char *scheme, int scheme_len, const char * host, int host_len, int64_t s,
      int64_t rt, int hit, int ret_code, bool remap_failed, short port = 0);
  void add_entry(RealStatEntry *entry);
  void write_file(FILE *file);
  int write_buffer(MIOBuffer *buf);
};

struct RealStatHdr
{
  unsigned int magic; //0xabcd1324
  int length;
};

struct RealStatCollectionAccept : public Continuation
{
  RealStatCollectionAccept(int port);
  ~RealStatCollectionAccept();
  int accept_event(int event, NetVConnection *net_vc);

  int m_port;
  Action *m_accept_action;
};

enum ReadStat
{
  UNDEFINED,
  READ_HDR,
  READ_DATA
};

struct RealStatCollectionSM : public Continuation
{
  RealStatCollectionSM(NetVConnection *vc);
  int main_handler(int event, void *e);

  NetVConnection *m_net_vc;
  VIO *m_read_vio;

  MIOBuffer m_client_buffer;
  RealStatHdr hdr;

  RealStatEntry *entry;
  IOBufferReader *m_client_reader;
  int64_t m_read_bytes_wanted;
  int64_t m_read_bytes_received;

  int m_client_ip;
  int m_client_port;
  char *p;
  ReadStat rs;


  void read_head();
  void read_body();
};


struct RealStatClientSM : public Continuation
{
  RealStatClientSM();
  int startEvent(int event, void *e);
  int connectEvent(int event, void *e);
  int mainEvent(int event, void *e);
  int write_data();

  Action *pending_action;
  Event *timer;
  UnixNetVConnection *net_vc;
  VIO *m_abort_vio;
  VIO *m_write_vio;

  IpAddr m_ip;
  in_port_t m_port;
  bool config_changed;
  IOBufferReader *m_send_reader;
  MIOBuffer m_buf;
  MIOBuffer m_abort_buffer;
};

void realstat_init(const char *run_dir);

extern RealStatTable rst;
extern int realstat_mode;
  
#endif
