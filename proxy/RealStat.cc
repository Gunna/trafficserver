#include "RealStat.h"
#include "I_RecProcess.h"

RealStatTable rst;
IpAddr realstat_ip;
RealStatCollectionAccept *real_stat_collation_accept = NULL;
int realstat_port;
int realstat_mode;
int node_no;
char real_snap_filename[PATH_NAME_MAX + 1];

static const char unknown_domain[] = "unkown_domain";
static ClassAllocator<RealStatEntry> realStatEntryAllocator("RealStatEntryAllocator");
FILE *real_stat_file = NULL;

static inline
unsigned int makeHash(const char *string, int len)
{
  if (!string || len <= 0 || *string == 0)
    return 0;

  const uint32_t InitialFNV = 2166136261U;
  const int32_t FNVMultiple = 16777619;

  uint64_t hash = InitialFNV;
  uint32_t *p = (uint32_t *) &hash;
  while(len > 0) {
    p[0] = p[0] ^ (toupper(*string));
    hash = (p[1] ^ p[0]) * FNVMultiple;
    ++string;
    --len;
  }

  return (p[1] ^ p[0]);
}

struct RealStatSyncer : public Continuation
{
  int mainEvent(int event, void *data) {
    rst.write_file(real_stat_file);
    return EVENT_CONT;
  }

  RealStatSyncer() : Continuation(new_ProxyMutex())
  {
    SET_HANDLER(&RealStatSyncer::mainEvent);
  }
};

static inline
void set_http_code(RealStatEntry *entry, int ret_code)
{
  if (ret_code == 0) {
    entry->client_abort++;
    return;
  }

  if (ret_code < 100 || ret_code >= 600) {
    entry->http_others++;
    return;
  }

  if (ret_code < 200) {
    entry->http_info++;
    return;
  }

  if (ret_code < 300) {
    if (ret_code == 200)
      entry->http_ok++;
    else if (ret_code == 206)
      entry->http_partial_ok++;
    else
      entry->http_successful++;

    return;
  }

  if (ret_code < 400) {
    switch (ret_code) {
      case 301:
        entry->http_move_permanent++;
        break;
      case 302:
        entry->http_found++;
        break;
      case 304:
        entry->http_not_modified++;
        break;
      default:
        entry->http_redirection++;
    }
    return;
  }

  if (ret_code < 500) {
    switch (ret_code) {
      case 400:
        entry->http_bad_request++;
        break;
      case 403:
        entry->http_forbidden++;
        break;
      case 404:
        entry->http_not_found++;
        break;
      case 408:
        entry->http_request_timeout++;
        break;
      case 412:
        entry->http_precondition_failed++;
        break;
      case 416:
        entry->http_range_not_statisfiable++;
        break;
      default:
        entry->http_client_error++;
    }
    return;
  }

  if (ret_code < 600) {
    switch (ret_code) {
      case 502:
        entry->http_bad_gateway++;
        break;
      case 503:
        entry->http_service_unavailable++;
        break;
      case 504:
        entry->http_gateway_timeout++;
        break;
      default:
        entry->http_server_error++;
    }
    return;
  }
}

void
RealStatTable::add_one(int proto, const char *host, int host_len, int64_t s,
    int64_t rt, int hit, int ret_code, bool remap_failed, short port)
{
  const char *domain;
  int domain_len;
  int old_proto = proto;
  short old_port = port;

  if (!host || host_len <= 0) {
    domain = unknown_domain;
    domain_len = sizeof unknown_domain - 1;
  }
  domain = host;
  domain_len = host_len;

  if (domain_len >= MAX_DOMAIN_LEN)
    domain_len = MAX_DOMAIN_LEN - 1;

  const char *old_domain = domain;
  int old_domain_len = domain_len;

  if (remap_failed) {
    domain = unknown_domain;
    domain_len = sizeof unknown_domain - 1;
  }

  uint32_t key = makeHash(domain, domain_len);
  int idx = key % MAX_BUCKETS;
  RealStatEntry *entry;

  ink_spinlock_acquire(&b_locks[idx]);

  for (entry = buckets[idx].head; entry; entry = entry->hash_link.next) {
    if (entry->key == key && entry->domain_len == domain_len && entry->proto == proto &&
        entry->port == (short) port && !memcmp(entry->domain, domain, domain_len))
        break;
  }

  if (!entry) {
    entry = realStatEntryAllocator.alloc();
    entry->key = key;
    entry->proto = proto;
    entry->port = port;
    entry->domain_len = (int16_t) domain_len;
    memcpy(entry->domain, domain, domain_len);

    buckets[idx].push(entry);
  }

  entry->count++;
  entry->rt += rt;
  entry->out_bytes += s;

  if (hit > 0) {
    entry->hits += s;
    if (hit > 1)
      entry->memhits++;
  }

  set_http_code(entry, ret_code);

  ink_spinlock_release(&b_locks[idx]);


  if (remap_failed) {
    if (old_domain != unknown_domain && old_domain_len > 0) {
      key = makeHash(old_domain, old_domain_len);
      idx = key % MAX_BUCKETS;

      ink_spinlock_acquire(&b_locks[idx]);

      for (entry = buckets[idx].head; entry; entry = entry->hash_link.next) {
        if (entry->key == key && entry->domain_len == old_domain_len && entry->proto == old_proto &&
            entry->port == old_port && !memcmp(entry->domain, old_domain, old_domain_len))
            break;
      }

      if (entry) {
        buckets[idx].remove(entry);
        realStatEntryAllocator.free(entry);
      }

      ink_spinlock_release(&b_locks[idx]);
    }
  }
}

void
RealStatTable::add_entry(RealStatEntry *entry)
{
  RealStatEntry *e;
  uint32_t key = entry->key;
  int idx = key % MAX_BUCKETS;
  ink_assert(key == makeHash(entry->domain, entry->domain_len));

  ink_spinlock_acquire(&b_locks[idx]);

  for (e = buckets[idx].head; e; e = e->hash_link.next) {
    if (e->key == key && e->domain_len == entry->domain_len && e->proto == entry->proto &&
        e->port == entry->port && !memcmp(e->domain, entry->domain, e->domain_len))
      break;
  }

  if (e) {
    e->out_bytes += entry->out_bytes;
    e->rt += entry->rt;
    e->count += entry->count;
    e->hits += entry->hits;
    e->memhits += entry->memhits;

    e->client_abort += entry->client_abort;
    e->http_info += entry->http_info;
    e->http_ok += entry->http_ok;
    e->http_partial_ok += entry->http_partial_ok;
    e->http_successful += entry->http_successful;
    e->http_move_permanent += entry->http_move_permanent;
    e->http_found += entry->http_found;
    e->http_not_modified += entry->http_not_modified;
    e->http_redirection += entry->http_redirection;
    e->http_bad_request += entry->http_bad_request;
    e->http_forbidden += entry->http_forbidden;
    e->http_not_found += entry->http_not_found;
    e->http_request_timeout += entry->http_request_timeout;
    e->http_precondition_failed += entry->http_precondition_failed;
    e->http_range_not_statisfiable += entry->http_range_not_statisfiable;
    e->http_client_error += entry->http_client_error;
    e->http_bad_gateway += entry->http_bad_gateway;
    e->http_service_unavailable += entry->http_service_unavailable;
    e->http_gateway_timeout += entry->http_gateway_timeout;
    e->http_server_error += entry->http_server_error;
    e->http_others += entry->http_others;
  } else
    buckets[idx].push(entry);

  ink_spinlock_release(&b_locks[idx]);
}



static inline
int write_entry(FILE *file, RealStatEntry *entry)
{
  return
    fprintf(file, "%" PRId64 " %d %.*s %d;out_bytes %" PRId64 ",rt %" PRId64 ",count %d,hits %" PRId64 ",memhits %d," 
      "client_abort %d,1xx %d,200 %d,206 %d,2xx %d,301 %d,302 %d,304 %d,3xx %d,400 %d,403 %d,404 %d,408 %d,"
      "412 %d,416 %d,4xx %d,502 %d,503 %d,504 %d,5xx %d,others %d\n",
      ink_get_hrtime() / 1000, node_no, entry->domain_len, entry->domain, entry->proto, entry->out_bytes, entry->rt / 1000, entry->count, 
      entry->hits, entry->memhits, entry->client_abort, entry->http_info, entry->http_ok, entry->http_partial_ok, entry->http_successful,
      entry->http_move_permanent, entry->http_found, entry->http_not_modified, entry->http_redirection, entry->http_bad_request,
      entry->http_forbidden, entry->http_not_found, entry->http_request_timeout, entry->http_precondition_failed,
      entry->http_range_not_statisfiable, entry->http_client_error, entry->http_bad_gateway,
      entry->http_service_unavailable, entry->http_gateway_timeout, entry->http_server_error, entry->http_others);
}

static inline
int write_entry(MIOBuffer *buf, RealStatEntry *entry)
{
  RealStatHdr hdr;
  hdr.magic = 0xabcd1234;
  hdr.length = (char *) &entry->domain - (char *) &entry->key + entry->domain_len;
  buf->write(&hdr, sizeof hdr);
  buf->write(&entry->key, hdr.length);

  memset(&entry->out_bytes, 0, (char *) &entry->domain - (char *) &entry->out_bytes);
  return hdr.length + sizeof hdr;
}

void
RealStatTable::init()
{
  for (int i = 0; i < MAX_BUCKETS; ++i)
    ink_spinlock_init(&b_locks[i]);
}

void
RealStatTable::write_file(FILE *file)
{
  if (!file) return;

  for (int i = 0; i < MAX_BUCKETS; i++) {
    ink_spinlock_acquire(&b_locks[i]);
    for (RealStatEntry *entry = buckets[i].head; entry;) {
      RealStatEntry *p = entry;
      entry = entry->hash_link.next;

      if (p->count <= 0) {
        buckets[i].remove(p);
        realStatEntryAllocator.free(p);
        continue;
      }
      write_entry(file, p);
      // reset the data
      int len = (char *) &p->domain - (char *) &p->out_bytes;
      memset(&p->out_bytes, 0, len);
    }
    ink_spinlock_release(&b_locks[i]);
  }

  fflush(file);
}

int
RealStatTable::write_buffer(MIOBuffer *buf) {
  ink_assert(buf);
  int sz = 0;

  for (int i = 0; i < MAX_BUCKETS; i++) {
    ink_spinlock_acquire(&b_locks[i]);
    for (RealStatEntry *entry = buckets[i].head; entry;) {
      RealStatEntry *p = entry;
      entry = entry->hash_link.next;

      if (p->count <= 0) {
        buckets[i].remove(p);
        realStatEntryAllocator.free(p);
        continue;
      }

      sz += write_entry(buf, p);
    }
    ink_spinlock_release(&b_locks[i]);
  }
  return sz;
}

RealStatCollectionAccept::RealStatCollectionAccept(int port) :
  Continuation(new_ProxyMutex()), m_port(port), m_accept_action(NULL)
{
  NetProcessor::AcceptOptions opt;
  SET_HANDLER(&RealStatCollectionAccept::accept_event);

  opt.local_port = m_port;
  opt.ip_family = AF_INET;
  opt.accept_threads = 0;
  m_accept_action = netProcessor.accept(this, opt);
  ink_assert(NULL != m_accept_action);
}

int
RealStatCollectionAccept::accept_event(int event, NetVConnection * net_vc)
{
  RealStatCollectionSM *sm;

  switch (event) {
    case NET_EVENT_ACCEPT:
      sm = NEW(new RealStatCollectionSM(net_vc));
      break;
    default:
      ink_assert(!"[ERROR] Unexpected Event");
  }

  return EVENT_CONT; 
}

RealStatCollectionAccept::~RealStatCollectionAccept()
{
  if (m_accept_action) {
    m_accept_action->cancel();
    m_accept_action = NULL;
  }
}

RealStatCollectionSM::RealStatCollectionSM(NetVConnection *netvc) :
  Continuation(netvc->mutex), m_net_vc(netvc), m_read_vio(NULL), m_client_reader(NULL),
  m_read_bytes_wanted(0), m_read_bytes_received(0), p(NULL), rs(UNDEFINED)
{
  m_client_ip = netvc->get_remote_ip();
  m_client_port = netvc->get_remote_port();
  m_client_buffer.set_size_index((1 << 15));

  SET_HANDLER(&RealStatCollectionSM::main_handler);
  eventProcessor.schedule_imm(this);
}

static inline
void free_RealStatCollectionSM(RealStatCollectionSM *sm)
{
  sm->m_net_vc->do_io_close();
  sm->m_read_vio = NULL;
  sm->m_client_buffer.clear();
  
  if (sm->entry) {
    realStatEntryAllocator.free(sm->entry);
    sm->entry = NULL;
  }
  sm->mutex.clear();

  delete(sm);
}

int
RealStatCollectionSM::main_handler(int event, void *e)
{
  int64_t n_avail;

  switch (event) {
    case EVENT_IMMEDIATE:
      m_client_reader = m_client_buffer.alloc_reader();
      rs = READ_HDR;
      m_read_bytes_wanted = sizeof hdr;
      m_read_bytes_received = 0;
      p = (char *) &hdr;
      m_read_vio = m_net_vc->do_io_read(this, INT64_MAX, &m_client_buffer);
      break;
    case VC_EVENT_READ_READY:
      n_avail = m_client_reader->read_avail(); 
      while (n_avail > 0) {
        n_avail -= m_read_bytes_wanted;
        if (n_avail >= 0) {
          m_client_reader->read(p, m_read_bytes_wanted);
          if (rs == READ_HDR) {
            rs = READ_DATA;
            ink_assert(hdr.magic == 0xabcd1234);
            m_read_bytes_wanted = hdr.length;
            entry = realStatEntryAllocator.alloc();
            p = (char *) &entry->key;
          } else if (rs == READ_DATA) {
            rst.add_entry(entry);
            entry = NULL;
            rs = READ_HDR;
            m_read_bytes_wanted = sizeof hdr;
            p = (char *) &hdr;
          } else
            ink_assert(!"not here");
        } else {
          m_client_reader->read(p, m_read_bytes_wanted + n_avail);
          p += m_read_bytes_wanted + n_avail;
          m_read_bytes_wanted = -n_avail;
        }
      }

      m_read_vio->reenable();
      break;
    case VC_EVENT_READ_COMPLETE:
    case VC_EVENT_EOS:
    case VC_EVENT_ERROR:
    default:
      free_RealStatCollectionSM(this);
    return EVENT_DONE;
  }

  return EVENT_CONT;
}

RealStatClientSM::RealStatClientSM() :
  Continuation(new_ProxyMutex()), pending_action(NULL), timer(NULL), net_vc(NULL), config_changed(false)
{
  m_abort_buffer.set_size_index(1);
  m_buf.set_size_index((1 << 15));
  SET_HANDLER(&RealStatClientSM::startEvent);
}

int
RealStatClientSM::startEvent(int event, void *data)
{
  IpEndpoint target;
  target.assign(realstat_ip, htons(realstat_port));
  SET_HANDLER(&RealStatClientSM::connectEvent);

  Action *connect_action = netProcessor.connect_re(this, &target.sa);

  if (connect_action != ACTION_RESULT_DONE) {
    ink_assert(!pending_action);
    pending_action = connect_action;
  }

  return EVENT_CONT;
}

int
RealStatClientSM::connectEvent(int event, void *data)
{
  pending_action = NULL;

  switch (event) {
    case NET_EVENT_OPEN:
      SET_HANDLER(&RealStatClientSM::mainEvent);
      net_vc = (UnixNetVConnection *) data;
      m_send_reader = m_buf.alloc_reader();
      m_abort_vio = net_vc->do_io_read(this, 1, &m_abort_buffer);
      timer = eventProcessor.schedule_every(this, HRTIME_SECONDS(3));
      m_write_vio = net_vc->do_io_write(this, INT64_MAX, m_send_reader);
      break;
    case NET_EVENT_OPEN_FAILED:
      SET_HANDLER(&RealStatClientSM::startEvent);
      eventProcessor.schedule_in(this, HRTIME_MSECONDS(50));
      break;
    default:
      ink_assert(!"unexpected event!");
  }

  return EVENT_CONT;
}

int
RealStatClientSM::mainEvent(int event, void *data)
{
  switch (event) {
    case EVENT_IMMEDIATE:
      break;
    case EVENT_INTERVAL:
      if (write_data() > 0)
        m_write_vio->reenable();
      break;
    case VC_EVENT_WRITE_READY:
      break;
    case VC_EVENT_WRITE_COMPLETE:
    case VC_EVENT_EOS:
    case VC_EVENT_ERROR:
    default:
      net_vc->do_io_close(); 
      m_write_vio = NULL;
      m_abort_vio = NULL;
      if (timer) {
        timer->cancel();
        timer = NULL;
      }
      m_buf.dealloc();
      SET_HANDLER(&RealStatClientSM::startEvent);
      eventProcessor.schedule_in(this, HRTIME_MSECONDS(50));
      break;
  }

  return EVENT_CONT;
}

int
RealStatClientSM::write_data()
{
  ink_assert(net_vc);

  int sz = rst.write_buffer(&m_buf);
  //m_send_reader = m_buf->alloc_reader();
  //net_vc->do_io_write(this, sz, m_send_reader);

  return sz;
}
  
void
realstat_init(const char *run_dir)
{
  IOCORE_EstablishStaticConfigInt32(realstat_mode, "proxy.local.log.real_collation_mode");
  
  char *p = real_snap_filename;
  int len = strlen(run_dir);
  memcpy(p, run_dir, len);
  p += len;
  if (*(p - 1) != '/')
    *p++ = '/';
    
  IOCORE_ReadConfigString(p, "proxy.config.stats.real_snap_file", PATH_NAME_MAX);

  IOCORE_EstablishStaticConfigInt32(realstat_port, "proxy.config.log.real_collation_port");

  char *hostname = REC_ConfigReadString("proxy.config.log.real_collation_host");

  char *proxyname = REC_ConfigReadString("proxy.config.proxy_name");
  node_no = atoi(proxyname);

  rst.init();
  if (hostname)
    realstat_ip.load(hostname);
  if (realstat_mode == 1)
    eventProcessor.schedule_imm(NEW(new RealStatClientSM));
  else if (realstat_mode == 2) {
    real_stat_file = fopen(real_snap_filename, "a");
    if (!real_stat_file) {
      Warning("real stat file %s open failed!", real_snap_filename);
    } else {
      eventProcessor.schedule_every((NEW (new RealStatSyncer)), HRTIME_SECONDS(5));
    }

    real_stat_collation_accept = NEW(new RealStatCollectionAccept(realstat_port));
  }
}

