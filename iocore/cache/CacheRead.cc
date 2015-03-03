/** @file

  A brief file description

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 */

#include "P_Cache.h"

#ifdef HTTP_CACHE
#include "HttpCacheSM.h"      //Added to get the scope of HttpCacheSM object.
#endif

#ifdef SSD_CACHE
extern int64_t cache_config_ram_cache_cutoff;
#endif
#define READ_WHILE_WRITER 1

Action *
Cache::open_read(Continuation * cont, CacheKey * key, CacheFragType type, char *hostname, int host_len)
{
  if (!CACHE_READY(type)) {
    cont->handleEvent(CACHE_EVENT_OPEN_READ_FAILED, (void *) -ECACHE_NOT_READY);
    return ACTION_RESULT_DONE;
  }
  ink_assert(caches[type] == this);

  Vol *vol = key_to_vol(key, hostname, host_len);
  Dir result, *last_collision = NULL;
  Ptr<CacheWriterEntry> cw;
  ProxyMutex *mutex = cont->mutex;
  OpenDirEntry *od = NULL;
  CacheVC *c = NULL;
  {
    CACHE_TRY_LOCK(lock, vol->mutex, mutex->thread_holding);
    if (writerTable.probe_entry(key, &cw) || !lock || dir_probe(key, vol, &result, &last_collision)) {
      c = new_CacheVC(cont);
      c->vio.op = VIO::READ;
      c->base_stat = cache_read_active_stat;
      CACHE_INCREMENT_DYN_STAT(c->base_stat + CACHE_STAT_ACTIVE);
      c->first_key = c->key = c->earliest_key = *key;
      c->vol = vol;
      c->frag_type = type;
      c->od = od;
    }

    if (cw) {
      c->cw = cw;
      goto Lwriter;
    }

    if (!lock) {
      SET_CONTINUATION_HANDLER(c, &CacheVC::openReadStartHead);
      CONT_SCHED_LOCK_RETRY(c);
      return &c->_action;
    }

    if (!c)
      goto Lmiss;

    c->dir = result;
    c->last_collision = last_collision;
    SET_CONTINUATION_HANDLER(c, &CacheVC::openReadStartHead);
    switch(c->do_read_call(&c->key)) {
      case EVENT_DONE: return ACTION_RESULT_DONE;
      case EVENT_RETURN: goto Lcallreturn;
      default: return &c->_action;
    }
  }
Lmiss:
  CACHE_INCREMENT_DYN_STAT(cache_read_failure_stat);
  cont->handleEvent(CACHE_EVENT_OPEN_READ_FAILED, (void *) -ECACHE_NO_DOC);
  return ACTION_RESULT_DONE;
Lwriter:
  SET_CONTINUATION_HANDLER(c, &CacheVC::openReadFromWriterHead);
  if (c->handleEvent(EVENT_IMMEDIATE, 0) == EVENT_DONE)
    return ACTION_RESULT_DONE;
  return &c->_action;
Lcallreturn:
  if (c->handleEvent(AIO_EVENT_DONE, 0) == EVENT_DONE)
    return ACTION_RESULT_DONE;
  return &c->_action;
}

#ifdef HTTP_CACHE
Action *
Cache::open_read(Continuation * cont, CacheKey * key, CacheHTTPHdr * request,
                 CacheLookupHttpConfig * params, CacheFragType type, char *hostname, int host_len)
{

  if (!CACHE_READY(type)) {
    cont->handleEvent(CACHE_EVENT_OPEN_READ_FAILED, (void *) -ECACHE_NOT_READY);
    return ACTION_RESULT_DONE;
  }
  ink_assert(caches[type] == this);

  Vol *vol = key_to_vol(key, hostname, host_len);
  Dir result, *last_collision = NULL;
  Ptr<CacheWriterEntry> cw;
  ProxyMutex *mutex = cont->mutex;
  CacheVC *c = NULL;

  {
    CACHE_TRY_LOCK(lock, vol->mutex, mutex->thread_holding);
    if (writerTable.probe_entry(key, &cw) || !lock || dir_probe(key, vol, &result, &last_collision)) {
      c = new_CacheVC(cont);
      c->first_key = c->key = c->earliest_key = *key;
      c->vol = vol;
      c->vio.op = VIO::READ;
      c->base_stat = cache_read_active_stat;
      CACHE_INCREMENT_DYN_STAT(c->base_stat + CACHE_STAT_ACTIVE);
      c->request.copy_shallow(request);
      c->frag_type = CACHE_FRAG_TYPE_HTTP;
      c->params = params;
    }

    if (cw) {
      c->cw = cw;
      goto Lwriter;
    }

    if (!lock) {
      SET_CONTINUATION_HANDLER(c, &CacheVC::openReadStartHead);
      CONT_SCHED_LOCK_RETRY(c);
      return &c->_action;
    }

    if (!c)
      goto Lmiss;

    // hit
    c->dir = c->first_dir = result;
    c->last_collision = last_collision;
    SET_CONTINUATION_HANDLER(c, &CacheVC::openReadStartHead);
    switch(c->do_read_call(&c->key)) {
      case EVENT_DONE: return ACTION_RESULT_DONE;
      case EVENT_RETURN: goto Lcallreturn;
      default: return &c->_action;
    }
  }
Lmiss:
  CACHE_INCREMENT_DYN_STAT(cache_read_failure_stat);
  cont->handleEvent(CACHE_EVENT_OPEN_READ_FAILED, (void *) -ECACHE_NO_DOC);
  return ACTION_RESULT_DONE;
Lwriter:
  // this is a horrible violation of the interface and should be fixed (FIXME)
  //((HttpCacheSM *)cont)->set_readwhilewrite_inprogress(true);
//  SET_CONTINUATION_HANDLER(c, &CacheVC::openReadFromWriter);
  SET_CONTINUATION_HANDLER(c, &CacheVC::openReadFromWriterHead);
  if (c->handleEvent(EVENT_IMMEDIATE, 0) == EVENT_DONE)
    return ACTION_RESULT_DONE;
  return &c->_action;
Lcallreturn:
  if (c->handleEvent(AIO_EVENT_DONE, 0) == EVENT_DONE)
    return ACTION_RESULT_DONE;
  return &c->_action;
}
#endif

int
CacheVC::openReadFromWriterFailure(int event, Event * e)
{

  od = NULL;
  vector.clear(false);
  CACHE_INCREMENT_DYN_STAT(cache_read_failure_stat);
  CACHE_INCREMENT_DYN_STAT(cache_read_busy_failure_stat);
  _action.continuation->handleEvent(event, e);
  free_CacheVC(this);
  return EVENT_DONE;
}

int
CacheVC::openReadChooseWriter(int event, Event * e)
{
  NOWARN_UNUSED(e);
  NOWARN_UNUSED(event);

  intptr_t err = ECACHE_DOC_BUSY;
  CacheVC *w = NULL;

  ink_debug_assert(vol->mutex->thread_holding == mutex->thread_holding && write_vc == NULL);

  if (!od)
    return EVENT_RETURN;

  if (frag_type != CACHE_FRAG_TYPE_HTTP) {
    ink_assert(od->num_writers == 1);
    w = od->writers.head;
    if (w->start_time > start_time || w->closed < 0) {
      od = NULL;
      return EVENT_RETURN;
    }
    if (!w->closed)
      return -err;
    write_vc = w;
  }
#ifdef HTTP_CACHE
  else {
    write_vector = &od->vector;
    int write_vec_cnt = write_vector->count();
    for (int c = 0; c < write_vec_cnt; c++)
      vector.insert(write_vector->get(c));
    // check if all the writers who came before this reader have
    // set the http_info.
    for (w = (CacheVC *) od->writers.head; w; w = (CacheVC *) w->opendir_link.next) {
      if (w->start_time > start_time || w->closed < 0)
        continue;
      if (!w->closed && !cache_config_read_while_writer) {
        return -err;
      }
      if (w->alternate_index != CACHE_ALT_INDEX_DEFAULT)
        continue;

      if (!w->closed && !w->alternate.valid()) {
        od = NULL;
        ink_debug_assert(!write_vc);
        vector.clear(false);
        return EVENT_CONT;
      }
      // construct the vector from the writers.
      int alt_ndx = CACHE_ALT_INDEX_DEFAULT;
      if (w->f.update) {
        // all Update cases. Need to get the alternate index.
        alt_ndx = get_alternate_index(&vector, w->update_key);
        // if its an alternate delete
        if (!w->alternate.valid()) {
          if (alt_ndx >= 0)
            vector.remove(alt_ndx, false);
          continue;
        }
      }
      ink_assert(w->alternate.valid());
      if (w->alternate.valid())
        vector.insert(&w->alternate, alt_ndx);
    }

    if (!vector.count()) {
      if (od->reading_vec) {
       // the writer(s) are reading the vector, so there is probably
        // an old vector. Since this reader came before any of the
        // current writers, we should return the old data
        od = NULL;
        return EVENT_RETURN;
      }
      return -ECACHE_NO_DOC;
    }
#ifdef FIXME_NONMODULAR
    if (cache_config_select_alternate) {
      alternate_index = HttpTransactCache::SelectFromAlternates(&vector, &request, params);
      if (alternate_index < 0)
        return -ECACHE_ALT_MISS;
    } else
#endif
      alternate_index = 0;
    CacheHTTPInfo *obj = vector.get(alternate_index);
    for (w = (CacheVC *) od->writers.head; w; w = (CacheVC *) w->opendir_link.next) {
      if (obj->m_alt == w->alternate.m_alt) {
        write_vc = w;
        break;
      }
    }
    vector.clear(false);
    if (!write_vc) {
      DDebug("cache_read_agg", "%p: key: %X writer alternate different: %d", this, first_key.word(1), alternate_index);
      od = NULL;
      return EVENT_RETURN;
    }

    DDebug("cache_read_agg",
          "%p: key: %X eKey: %d # alts: %d, ndx: %d, # writers: %d writer: %p",
          this, first_key.word(1), write_vc->earliest_key.word(1),
          vector.count(), alternate_index, od->num_writers, write_vc);
  }
#endif //HTTP_CACHE
  return EVENT_NONE;
}

int
CacheVC::openReadFromWriterHead(int event, Event * e)
{
  ink_debug_assert(cw);
  ink_assert(!is_io_in_progress() && mutex.m_ptr->thread_holding == this_ethread());

  if (!f.read_from_writer_called) {
    // The assignment to last_collision as NULL was
    // made conditional after INKqa08411
    last_collision = NULL;
    // Let's restart the clock from here - the first time this a reader
    // gets in this state. Its possible that the open_read was called
    // before the open_write, but the reader could not get the volume
    // lock. If we don't reset the clock here, we won't choose any writer
    // and hence fail the read request.
    start_time = ink_get_hrtime();
    f.read_from_writer_called = 1;
    dir_clean(&first_dir);
    dir_clean(&earliest_dir);
  }

  if (_action.cancelled) {
    od = NULL; // only open for read so no need to close
    Debug("read_from_writer", "reader be cancelled in reading from writer");
    return free_CacheVC(this);
  }

  bool header_only = false;
  bool nd = true;
  int result = cw->get_writer_meta(this, &header_only, &nd);

  if (result == 0) {
    Debug("cache_read_agg", "get writer meta: %d, %p, doc_len = %"PRId64"", result, this, doc_len);
    if (header_only) {
      key = earliest_key;
      if (first_buf._ptr()) {
        Doc *doc = (Doc *) first_buf->data();
        if (doc_len == doc->data_len()) {
          frag_len = doc->flen;
          buf = first_buf;
          doc_pos = doc->prefix_len();
          SET_HANDLER(&CacheVC::openReadMain);
          CACHE_INCREMENT_DYN_STAT(cache_read_busy_success_stat);
          return callcont(CACHE_EVENT_OPEN_READ);
        }
      }
      f.single_fragment = 0;
      SET_HANDLER(&CacheVC::openReadStartEarliest);
      return openReadStartEarliest(event, e);
    }

    if (nd) {
      key = earliest_key;
      f.single_fragment = 0;
      SET_HANDLER(&CacheVC::openReadStartEarliest);
      return openReadStartEarliest(event, e);
    }
    SET_HANDLER(&CacheVC::openReadFromWriterMain);
    CACHE_INCREMENT_DYN_STAT(cache_read_busy_success_stat);
    return callcont(CACHE_EVENT_OPEN_READ);
  } else if (result > 0) {
    PUSH_HANDLER(&CacheVC::handleReadFromWriter);
    return EVENT_CONT;
  } else {
    ink_debug_assert(cw == NULL);
    SET_HANDLER(&CacheVC::openReadStartHead);
    CONT_SCHED_LOCK_RETRY(this);
  }
  return EVENT_CONT;
}

int
CacheVC::handleReadFromWriter(int event, Event * e)
{
  cancel_trigger();
  ink_assert(mutex.m_ptr->thread_holding == this_ethread());
  if (event == EVENT_IMMEDIATE || event == EVENT_INTERVAL) {
    if (event != EVENT_IMMEDIATE && cw->in_and_remove(this)) {
      Debug("read_from_writer", "delay too long, give up read from writer.");
      // rww delay timeout, just read from cache
      cw = NULL;
      SET_HANDLER(&CacheVC::openReadStartHead);
      return openReadStartHead(EVENT_IMMEDIATE, 0);
    }
    return EVENT_CONT;
  }

  ink_debug_assert(is_io_in_progress());
  set_io_not_in_progress();
  POP_HANDLER;

  if (closed) {
    return die();
  }
  if (event == CACHE_EVENT_WRITER_CLOSED || event == CACHE_EVENT_WRITER_ABORTED)
    write_vc = NULL;
  return handleEvent(event, e);
}
int
CacheVC::openReadFromWriter(int event, Event * e)
{
  if (!f.read_from_writer_called) {
    // The assignment to last_collision as NULL was
    // made conditional after INKqa08411
    last_collision = NULL;
    // Let's restart the clock from here - the first time this a reader
    // gets in this state. Its possible that the open_read was called
    // before the open_write, but the reader could not get the volume
    // lock. If we don't reset the clock here, we won't choose any writer
    // and hence fail the read request.
    start_time = ink_get_hrtime();
    f.read_from_writer_called = 1;
  }
  cancel_trigger();
  intptr_t err = ECACHE_DOC_BUSY;
  DDebug("cache_read_agg", "%p: key: %X In openReadFromWriter", this, first_key.word(1));
#ifndef READ_WHILE_WRITER
  return openReadFromWriterFailure(CACHE_EVENT_OPEN_READ_FAILED, (Event *) -err);
#else
  if (_action.cancelled) {
    od = NULL; // only open for read so no need to close
    return free_CacheVC(this);
  }
  CACHE_TRY_LOCK(lock, vol->mutex, mutex->thread_holding);
  if (!lock)
    VC_SCHED_LOCK_RETRY();
  od = vol->open_read(&first_key); // recheck in case the lock failed
  if (!od) {
    MUTEX_RELEASE(lock);
    write_vc = NULL;
    SET_HANDLER(&CacheVC::openReadStartHead);
    return openReadStartHead(event, e);
  } else
    ink_debug_assert(od == vol->open_read(&first_key));
  if (!write_vc) {
    int ret = openReadChooseWriter(event, e);
    if (ret < 0) {
      MUTEX_RELEASE(lock);
      SET_HANDLER(&CacheVC::openReadFromWriterFailure);
      return openReadFromWriterFailure(CACHE_EVENT_OPEN_READ_FAILED, reinterpret_cast<Event *> (ret));
    } else if (ret == EVENT_RETURN) {
      MUTEX_RELEASE(lock);
      SET_HANDLER(&CacheVC::openReadStartHead);
      return openReadStartHead(event, e);
    } else if (ret == EVENT_CONT) {
      ink_debug_assert(!write_vc);
      VC_SCHED_WRITER_RETRY();
    } else
      ink_assert(write_vc);
  } else {
    if (writer_done()) {
      MUTEX_RELEASE(lock);
      DDebug("cache_read_agg",
            "%p: key: %X writer %p has left, continuing as normal read", this, first_key.word(1), write_vc);
      od = NULL;
      write_vc = NULL;
      SET_HANDLER(&CacheVC::openReadStartHead);
      return openReadStartHead(event, e);
    }
  }
#ifdef HTTP_CACHE
  OpenDirEntry *cod = od;
#endif
  od = NULL;
  // someone is currently writing the document
  if (write_vc->closed < 0) {
    MUTEX_RELEASE(lock);
    write_vc = NULL;
    //writer aborted, continue as if there is no writer
    SET_HANDLER(&CacheVC::openReadStartHead);
    return openReadStartHead(EVENT_IMMEDIATE, 0);
  }
  // allow reading from unclosed writer for http requests only.
  ink_assert(frag_type == CACHE_FRAG_TYPE_HTTP || write_vc->closed);
  if (!write_vc->closed && !write_vc->fragment) {
    if (!cache_config_read_while_writer || frag_type != CACHE_FRAG_TYPE_HTTP) {
      MUTEX_RELEASE(lock);
      return openReadFromWriterFailure(CACHE_EVENT_OPEN_READ_FAILED, (Event *) - err);
    }
    DDebug("cache_read_agg",
          "%p: key: %X writer: closed:%d, fragment:%d, retry: %d",
          this, first_key.word(1), write_vc->closed, write_vc->fragment, writer_lock_retry);
    VC_SCHED_WRITER_RETRY();
  }

  CACHE_TRY_LOCK(writer_lock, write_vc->mutex, mutex->thread_holding);
  if (!writer_lock) {
    DDebug("cache_read_agg", "%p: key: %X lock miss", this, first_key.word(1));
    VC_SCHED_LOCK_RETRY();
  }
  MUTEX_RELEASE(lock);

  if (!write_vc->io.ok())
    return openReadFromWriterFailure(CACHE_EVENT_OPEN_READ_FAILED, (Event *) - err);
#ifdef HTTP_CACHE
  if (frag_type == CACHE_FRAG_TYPE_HTTP) {
    DDebug("cache_read_agg",
          "%p: key: %X http passed stage 1, closed: %d, frag: %d",
          this, first_key.word(1), write_vc->closed, write_vc->fragment);
    if (!write_vc->alternate.valid())
      return openReadFromWriterFailure(CACHE_EVENT_OPEN_READ_FAILED, (Event *) - err);
    alternate.copy(&write_vc->alternate);
    vector.insert(&alternate);
    alternate.object_key_get(&key);
    write_vc->f.readers = 1;
    if (!(write_vc->f.update && write_vc->total_len == 0)) {
      key = write_vc->earliest_key;
      if (!write_vc->closed) {
        if (write_vc->vio.nbytes == INT64_MAX && alternate.response_get()->presence(MIME_PRESENCE_CONTENT_LENGTH))
          alternate.object_size_set(alternate.response_get()->get_content_length());
        else
          alternate.object_size_set(write_vc->vio.nbytes);
      } else
        alternate.object_size_set(write_vc->total_len);
      doc_len = alternate.object_size_get();
    } else {
      key = write_vc->update_key;
      ink_assert(write_vc->closed);
      DDebug("cache_read_agg", "%p: key: %X writer header update", this, first_key.word(1));
      // Update case (b) : grab doc_len from the writer's alternate
      doc_len = alternate.object_size_get();
      if (write_vc->update_key == cod->single_doc_key &&
          (cod->move_resident_alt || write_vc->f.rewrite_resident_alt) && write_vc->first_buf._ptr()) {
        // the resident alternate is being updated and its a
        // header only update. The first_buf of the writer has the
        // document body.
        Doc *doc = (Doc *) write_vc->first_buf->data();
        writer_buf = new_IOBufferBlock(write_vc->first_buf, doc->data_len(), doc->prefix_len());
        MUTEX_RELEASE(writer_lock);
        ink_assert(doc_len == doc->data_len());
        length = doc_len;
        f.single_fragment = 1;
        doc_pos = 0;
        earliest_key = key;
        dir_clean(&first_dir);
        dir_clean(&earliest_dir);
        SET_HANDLER(&CacheVC::openReadFromWriterMain);
        CACHE_INCREMENT_DYN_STAT(cache_read_busy_success_stat);
        return callcont(CACHE_EVENT_OPEN_READ);
      }
      // want to snarf the new headers from the writer
      // and then continue as if nothing happened
      last_collision = NULL;
      MUTEX_RELEASE(writer_lock);
      SET_HANDLER(&CacheVC::openReadStartEarliest);
      return openReadStartEarliest(event, e);
    }
  } else {
#endif //HTTP_CACHE
    DDebug("cache_read_agg", "%p: key: %X non-http passed stage 1", this, first_key.word(1));
    key = write_vc->earliest_key;
    doc_len = write_vc->vio.nbytes;
#ifdef HTTP_CACHE
  }
#endif
  if (write_vc->fragment) {
    last_collision = NULL;
    DDebug("cache_read_agg",
          "%p: key: %X closed: %d, fragment: %d, len: %d starting first fragment",
          this, first_key.word(1), write_vc->closed, write_vc->fragment, (int)doc_len);
    MUTEX_RELEASE(writer_lock);
    // either a header + body update or a new document
    SET_HANDLER(&CacheVC::openReadStartEarliest);
    return openReadStartEarliest(event, e);
  }
  writer_buf = write_vc->blocks;
  writer_offset = write_vc->offset;
  length = write_vc->length;
  // copy the vector
  f.single_fragment = !write_vc->fragment;        // single fragment doc
  doc_pos = 0;
  earliest_key = write_vc->earliest_key;
  ink_assert(earliest_key == key);
  doc_len = write_vc->total_len;
  dir_clean(&first_dir);
  dir_clean(&earliest_dir);
  DDebug("cache_read_agg", "%p: key: %X %X: single fragment read", this, first_key.word(1), key.word(0));
  MUTEX_RELEASE(writer_lock);
  SET_HANDLER(&CacheVC::openReadFromWriterMain);
  CACHE_INCREMENT_DYN_STAT(cache_read_busy_success_stat);
  return callcont(CACHE_EVENT_OPEN_READ);
#endif //READ_WHILE_WRITER
}

//int
//CacheVC::openReadFromWriterData(int event, Event * e)
//{
//
//}
int
CacheVC::openReadFromWriterMain(int event, Event * e)
{
  NOWARN_UNUSED(e);
  NOWARN_UNUSED(event);

  cancel_trigger();
  ink_assert(!closed && !is_io_in_progress() && mutex.m_ptr->thread_holding == this_ethread());

  if (offset < seek_to) {
    if (seek_to >= (int64_t) doc_len)
      return calluser(VC_EVENT_EOS);
    offset = seek_to;
  }

  if (vio.ntodo() <= 0)
    return EVENT_CONT;

  ink_assert(cw);
  int result = cw->get_writer_data(this);

  if (result == 0) {
    if (vio.ntodo() <= 0)
      return calluser(VC_EVENT_READ_COMPLETE);
    else if (offset >= (int64_t) doc_len)
      return calluser(VC_EVENT_EOS);
    else
      return calluser(VC_EVENT_READ_READY);
  } else if (result < 0)
    return calluser(VC_EVENT_ERROR);

  // wait for the writer wake me up
  ink_assert(is_io_in_progress());
  PUSH_HANDLER(&CacheVC::handleReadFromWriter);
  return EVENT_CONT;
}

int
CacheVC::openReadClose(int event, Event * e)
{
  NOWARN_UNUSED(e);
  NOWARN_UNUSED(event);

  cancel_trigger();
  if (is_io_in_progress()) {
    if (event != AIO_EVENT_DONE)
      return EVENT_CONT;
    set_io_not_in_progress();
  }
  CACHE_TRY_LOCK(lock, vol->mutex, mutex->thread_holding);
  if (!lock)
    VC_SCHED_LOCK_RETRY();
#ifdef HIT_EVACUATE
  if (f.hit_evacuate && dir_valid(vol, &first_dir) && closed > 0) {
    if (f.single_fragment)
      vol->force_evacuate_head(&first_dir, dir_pinned(&first_dir));
    else if (dir_valid(vol, &earliest_dir)) {
      vol->force_evacuate_head(&first_dir, dir_pinned(&first_dir));
      vol->force_evacuate_head(&earliest_dir, dir_pinned(&earliest_dir));
    }
  }
#endif
  vol->close_read(this);
  return free_CacheVC(this);
}

int
CacheVC::openReadReadDone(int event, Event * e)
{
  Doc *doc = NULL;

  cancel_trigger();
  if (event == EVENT_IMMEDIATE)
    return EVENT_CONT;
  ink_assert(!is_io_in_progress());
  {
    CACHE_TRY_LOCK(lock, vol->mutex, mutex->thread_holding);
    if (!lock)
      VC_SCHED_LOCK_RETRY();
    if (event == AIO_EVENT_DONE && !io.ok()) {
      dir_delete(&earliest_key, vol, &earliest_dir);
      goto Lerror;
    }
    if (last_collision &&         // no missed lock
        dir_valid(vol, &dir))    // object still valid
    {
      doc = (Doc *) buf->data();
      if (doc->magic != DOC_MAGIC) {
        char tmpstring[100];
        if (doc->magic == DOC_CORRUPT)
          Warning("Middle: Doc checksum does not match for %s", key.string(tmpstring));
        else
          Warning("Middle: Doc magic does not match for %s", key.string(tmpstring));
#ifdef SSD_CACHE
        if (dir_inssd(&dir)) {
          dir_delete(&key, vol, &dir);
          goto Lread;
        }
#endif
        goto Lerror;
      }
      if (doc->key == key)
        goto LreadMain;
    }
    if (last_collision && dir_get_offset(&dir) != dir_get_offset(last_collision))
      last_collision = 0;       // object has been/is being overwritten
Lread:
    if (dir_probe(&key, vol, &dir, &last_collision)) {
      int ret = do_read_call(&key);
      if (ret == EVENT_RETURN)
        goto Lcallreturn;
      return EVENT_CONT;
    } else if (write_vc) {
      if (writer_done()) {
        last_collision = NULL;
        while (dir_probe(&earliest_key, vol, &dir, &last_collision)) {
          if (dir_get_offset(&dir) == dir_get_offset(&earliest_dir)) {
            DDebug("cache_read_agg", "%p: key: %X ReadRead complete: %d",
                  this, first_key.word(1), (int)vio.ndone);
            doc_len = vio.ndone;
            goto Ldone;
          }
        }
        DDebug("cache_read_agg", "%p: key: %X ReadRead writer aborted: %d",
              this, first_key.word(1), (int)vio.ndone);
        goto Lerror;
      }
      DDebug("cache_read_agg", "%p: key: %X ReadRead retrying: %d", this, first_key.word(1), (int)vio.ndone);
      VC_SCHED_WRITER_RETRY(); // wait for writer
    }
    // fall through for truncated documents
  }
Lerror:
  char tmpstring[100];
  Warning("Document %s truncated", earliest_key.string(tmpstring));
  return calluser(VC_EVENT_ERROR);
Ldone:
  return calluser(VC_EVENT_EOS);
Lcallreturn:
  return handleEvent(AIO_EVENT_DONE, 0);
LreadMain:
  fragment++;
  doc_pos = doc->prefix_len();
  next_CacheKey(&key, &key);
  SET_HANDLER(&CacheVC::openReadMain);
  return openReadMain(event, e);
}

int
CacheVC::openReadMain(int event, Event * e)
{
  NOWARN_UNUSED(e);
  NOWARN_UNUSED(event);

  cancel_trigger();
  Doc *doc = (Doc *) buf->data();
  int64_t ntodo = vio.ntodo();
  int64_t bytes = doc->len - doc_pos;
  IOBufferBlock *b = NULL;
  int i = 0;

  if (offset < seek_to && bytes > 0) {
    if (seek_to >= (int64_t)doc_len) {
      return calluser(VC_EVENT_EOS);
    }

    if (!f.single_fragment) {
      ink_assert(frag_len);
      i = (seek_to - offset) / frag_len;
      if (i > 0) {
        while (i > 1) {
          next_CacheKey(&key, &key);
          offset += frag_len;
          --i;
        }
        // mark the current fragment as garbage
        doc_pos = doc->len;
        offset += frag_len;
        goto Lread;
      }
    }
    doc_pos = doc->prefix_len() + (seek_to - offset);
    bytes = doc->len - doc_pos;
    offset = seek_to;
  }

  if (ntodo <= 0)
    return EVENT_CONT;
  if (vio.buffer.mbuf->max_read_avail() > vio.buffer.writer()->water_mark && vio.ndone) // initiate read of first block
    return EVENT_CONT;
  if ((bytes <= 0) && vio.ntodo() >= 0)
    goto Lread;
  if (bytes > vio.ntodo())
    bytes = vio.ntodo();
  b = new_IOBufferBlock(buf, bytes, doc_pos);
  b->_buf_end = b->_end;
  vio.buffer.mbuf->append_block(b);
  vio.ndone += bytes;
  doc_pos += bytes;
  offset += bytes;
  if (vio.ntodo() <= 0)
    return calluser(VC_EVENT_READ_COMPLETE);
  else {
    if (calluser(VC_EVENT_READ_READY) == EVENT_DONE)
      return EVENT_DONE;
    // we have to keep reading until we give the user all the
    // bytes it wanted or we hit the watermark.
    if (vio.ntodo() > 0 && !vio.buffer.writer()->high_water())
      goto Lread;
    return EVENT_CONT;
  }
Lread: {
    cancel_trigger();
    if (cw.m_ptr && !cw->writer_done()) {
      // read from writer
      SET_HANDLER(&CacheVC::openReadMain);
      int result = cw->read_write_frag(this);
      if (result == -1)
        goto Lerror;
      if (result > 0) {
        PUSH_HANDLER(&CacheVC::handleReadFromWriter);
        return EVENT_CONT;
      }
    }
    if (offset >= (int64_t)doc_len)
      // reached the end of the document and the user still wants more
      return calluser(VC_EVENT_EOS);
    last_collision = 0;
    writer_lock_retry = 0;
    // if the state machine calls reenable on the callback from the cache,
    // we set up a schedule_imm event. The openReadReadDone discards
    // EVENT_IMMEDIATE events. So, we have to cancel that trigger and set
    // a new EVENT_INTERVAL event.

    CACHE_TRY_LOCK(lock, vol->mutex, mutex->thread_holding);
    if (!lock) {
      SET_HANDLER(&CacheVC::openReadMain);
      VC_SCHED_LOCK_RETRY();
    }
    if (dir_probe(&key, vol, &dir, &last_collision)) {
      SET_HANDLER(&CacheVC::openReadReadDone);
      int ret = do_read_call(&key);
      if (ret == EVENT_RETURN)
        goto Lcallreturn;
      return EVENT_CONT;
    }
    if (is_action_tag_set("cache"))
      ink_release_assert(false);
    Warning("Document %X truncated at %d of %d, missing fragment %X", first_key.word(1), (int)vio.ndone, (int)doc_len, key.word(1));
    // remove the directory entry
    dir_delete(&earliest_key, vol, &earliest_dir);
  }
Lerror:
  return calluser(VC_EVENT_ERROR);
Lcallreturn:
  return handleEvent(AIO_EVENT_DONE, 0);
}

/*
  This code follows CacheVC::openReadStartHead closely,
  if you change this you might have to change that.
*/
int
CacheVC::openReadStartEarliest(int event, Event * e)
{
  NOWARN_UNUSED(e);
  NOWARN_UNUSED(event);

  int ret = 0;
  Doc *doc = NULL;
#ifdef SSD_CACHE
  bool okay = false;
  bool read_from_ssd = false;
  bool remove_dir = false;
#endif
  cancel_trigger();
  set_io_not_in_progress();
  if (_action.cancelled)
    return free_CacheVC(this);
  {
    CACHE_TRY_LOCK(lock, vol->mutex, mutex->thread_holding);
    if (!lock)
      VC_SCHED_LOCK_RETRY();
    if (!buf)
      goto Lread;
#ifdef SSD_CACHE
    read_from_ssd = dir_inssd(&dir);
#endif
    if (!io.ok())
      goto Ldone;
    // an object needs to be outside the aggregation window in order to be
    // be evacuated as it is read
    if (!dir_agg_valid(vol, &dir)) {
      // a directory entry which is nolonger valid may have been overwritten
      if (!dir_valid(vol, &dir))
        last_collision = NULL;
      goto Lread;
    }
    doc = (Doc *) buf->data();
    if (doc->magic != DOC_MAGIC) {
      char tmpstring[100];
      if (is_action_tag_set("cache")) {
        ink_release_assert(false);
      }
      if (doc->magic == DOC_CORRUPT)
        Warning("Earliest: Doc checksum does not match for %s", key.string(tmpstring));
      else
        Warning("Earliest : Doc magic does not match for %s", key.string(tmpstring));
      // remove the dir entry
      remove_dir = true;
      goto Lread;
    }
    if (!(doc->key == key)) // collisiion
      goto Lread;
    // success
#ifdef SSD_CACHE
    okay = true;
    if (read_from_ssd) {
      ink_assert(dir_inssd(&dir));
      goto Lread;
    }
Lcont:
#endif
    earliest_key = key;
    doc_pos = doc->prefix_len();
    frag_len = doc->flen;
    next_CacheKey(&key, &doc->key);
    vol->begin_read(this);
#ifdef HIT_EVACUATE
    if (vol->within_hit_evacuate_window(&earliest_dir) &&
        (!cache_config_hit_evacuate_size_limit || doc_len <= (uint64_t)cache_config_hit_evacuate_size_limit)) {
      DDebug("cache_hit_evac", "dir: %"PRId64", write: %"PRId64", phase: %d",
            dir_offset(&earliest_dir), offset_to_vol_offset(vol, vol->header->write_pos), vol->header->phase);
      f.hit_evacuate = 1;
    }
#endif
    goto Lsuccess;
Lread:
#ifdef SSD_CACHE
    if ((read_from_ssd && !okay) || remove_dir) {
      dir_delete(&key, vol, &dir);
      last_collision = NULL;
      remove_dir = false;
    }
#endif
    if (dir_probe(&key, vol, &earliest_dir, &last_collision) ||
        dir_lookaside_probe(&key, vol, &earliest_dir, NULL))
    {
#ifdef SSD_CACHE
      if (read_from_ssd) {
        if (dir_inssd(&earliest_dir)) {
          dir = earliest_dir;
          remove_dir = true;
          goto Lread;
        } else if (okay)
          goto Lcont;
      }
#endif
      dir = earliest_dir;
      if ((ret = do_read_call(&key)) == EVENT_RETURN)
        goto Lcallreturn;
      return ret;
    }
    // read has detected that alternate does not exist in the cache.
    // rewrite the vector.
#ifdef HTTP_CACHE
    if (!f.read_from_writer_called && frag_type == CACHE_FRAG_TYPE_HTTP) {
      // don't want any writers while we are evacuating the vector
      if (!vol->open_write(this, false, 1)) {
        Doc *doc1 = (Doc *) first_buf->data();
        uint32_t len = write_vector->get_handles(doc1->hdr(), doc1->hlen);
        ink_assert(len == doc1->hlen && write_vector->count() > 0);
        write_vector->remove(alternate_index, true);
        // if the vector had one alternate, delete it's directory entry
        if (len != doc1->hlen || !write_vector->count()) {
          // sometimes the delete fails when there is a race and another read
          // finds that the directory entry has been overwritten
          // (cannot assert on the return value)
          dir_delete(&first_key, vol, &first_dir);
        }
#ifdef SSD_CACHE
        else if (dir_inssd(&first_dir))
          dir_delete(&first_key, vol, &first_dir);
#endif
        else {
          buf = NULL;
          last_collision = NULL;
          write_len = 0;
          header_len = write_vector->marshal_length();
          f.evac_vector = 1;
          f.use_first_key = 1;
          key = first_key;
          // always use od->first_dir to overwrite a directory.
          // If an evacuation happens while a vector is being updated
          // the evacuator changes the od->first_dir to the new directory
          // that it inserted
          od->first_dir = first_dir;
          od->writing_vec = 1;
          earliest_key = zero_key;

          // set up this VC as a alternate delete write_vc
          vio.op = VIO::WRITE;
          total_len = 0;
          f.update = 1;
          alternate_index = CACHE_ALT_REMOVED;
          /////////////////////////////////////////////////////////////////
          // change to create a directory entry for a resident alternate //
          // when another alternate does not exist.                      //
          /////////////////////////////////////////////////////////////////
          if (doc1->total_len > 0) {
            od->move_resident_alt = 1;
            od->single_doc_key = doc1->key;
            dir_assign(&od->single_doc_dir, &dir);
            dir_set_tag(&od->single_doc_dir, od->single_doc_key.word(2));
          }
          SET_HANDLER(&CacheVC::openReadVecWrite);
          if ((ret = do_write_call()) == EVENT_RETURN)
            goto Lcallreturn;
          return ret;
        }
      }
    }
#endif
    // open write failure - another writer, so don't modify the vector
  Ldone:
    if (od)
      vol->close_write(this);
  }
  CACHE_INCREMENT_DYN_STAT(cache_read_failure_stat);
  _action.continuation->handleEvent(CACHE_EVENT_OPEN_READ_FAILED, (void *) -ECACHE_NO_DOC);
  return free_CacheVC(this);
Lcallreturn:
  return handleEvent(AIO_EVENT_DONE, 0); // hopefully a tail call
Lsuccess:
  if (cw.m_ptr)
    CACHE_INCREMENT_DYN_STAT(cache_read_busy_success_stat);
  SET_HANDLER(&CacheVC::openReadMain);
  return callcont(CACHE_EVENT_OPEN_READ);
}

// create the directory entry after the vector has been evacuated
// the volume lock has been taken when this function is called
#ifdef HTTP_CACHE
int
CacheVC::openReadVecWrite(int event, Event * e)
{
  NOWARN_UNUSED(e);
  NOWARN_UNUSED(event);

  cancel_trigger();
  set_io_not_in_progress();
  ink_assert(od);
  od->writing_vec = 0;
  if (_action.cancelled)
    return openWriteCloseDir(EVENT_IMMEDIATE, 0);
  {
    CACHE_TRY_LOCK(lock, vol->mutex, mutex->thread_holding);
    if (!lock)
      VC_SCHED_LOCK_RETRY();
    if (io.ok()) {
      ink_assert(f.evac_vector);
      ink_assert(frag_type == CACHE_FRAG_TYPE_HTTP);
      ink_assert(!buf.m_ptr);
      f.evac_vector = false;
      last_collision = NULL;
      f.update = 0;
      alternate_index = CACHE_ALT_INDEX_DEFAULT;
      f.use_first_key = 0;
      vio.op = VIO::READ;
      dir_overwrite(&first_key, vol, &dir, &od->first_dir);
      if (od->move_resident_alt)
        dir_insert(&od->single_doc_key, vol, &od->single_doc_dir);
#ifdef FIXME_NONMODULAR
      int alt_ndx = HttpTransactCache::SelectFromAlternates(write_vector, &request, params);
#else
      int alt_ndx = 0;
#endif
      vol->close_write(this);
      if (alt_ndx >= 0) {
        vector.clear();
        // we don't need to start all over again, since we already
        // have the vector in memory. But this is simpler and this
        // case is rare.
        goto Lrestart;
      }
    } else
      vol->close_write(this);
  }

  CACHE_INCREMENT_DYN_STAT(cache_read_failure_stat);
  _action.continuation->handleEvent(CACHE_EVENT_OPEN_READ_FAILED, (void *) -ECACHE_ALT_MISS);
  return free_CacheVC(this);
Lrestart:
  SET_HANDLER(&CacheVC::openReadStartHead);
  return openReadStartHead(EVENT_IMMEDIATE, 0);
}
#endif

/*
  This code follows CacheVC::openReadStartEarliest closely,
  if you change this you might have to change that.
*/
int
CacheVC::openReadStartHead(int event, Event * e)
{
  intptr_t err = ECACHE_NO_DOC;
  Doc *doc = NULL;
  cancel_trigger();
  set_io_not_in_progress();
  if (_action.cancelled)
    return free_CacheVC(this);
  {
    CACHE_TRY_LOCK(lock, vol->mutex, mutex->thread_holding);
    if (!lock)
      VC_SCHED_LOCK_RETRY();
    if (!buf)
      goto Lread;
    if (!io.ok())
      goto Ldone;
    // an object needs to be outside the aggregation window in order to be
    // be evacuated as it is read
    if (!dir_agg_valid(vol, &dir)) {
      // a directory entry which is nolonger valid may have been overwritten
      if (!dir_valid(vol, &dir))
        last_collision = NULL;
#ifdef SSD_CACHE
      if (dir_inssd(&dir)) {
        dir_delete(&key, vol, &dir);
        last_collision = NULL;
      }
#endif
      goto Lread;
    }
    doc = (Doc *) buf->data();
    if (doc->magic != DOC_MAGIC) {
      char tmpstring[100];
      if (is_action_tag_set("cache")) {
        ink_release_assert(false);
      }
      if (doc->magic == DOC_CORRUPT)
        Warning("Head: Doc checksum does not match for %s", key.string(tmpstring));
      else
        Warning("Head : Doc magic does not match for %s", key.string(tmpstring));
      // remove the dir entry
      dir_delete(&key, vol, &dir);
      // try going through the directory entries again
      // in case the dir entry we deleted doesnt correspond
      // to the key we are looking for. This is possible
      // because of directory collisions
      last_collision = NULL;
      goto Lread;
    }
    if (!(doc->first_key == key)) {
#ifdef SSD_CACHE
      if (dir_inssd(&dir)) {
        dir_delete(&key, vol, &dir);
        last_collision = NULL;
      }
#endif
      goto Lread;
    }
    if (f.lookup)
      goto Lookup;
    earliest_dir = dir;
#ifdef HTTP_CACHE
    CacheHTTPInfo *alternate_tmp;
    if (frag_type == CACHE_FRAG_TYPE_HTTP) {
      ink_assert(doc->hlen);
      if (!doc->hlen)
        goto Ldone;
      if ((intptr_t) e == -ECACHE_BAD_META_DATA || vector.get_handles(doc->hdr(), doc->hlen) != doc->hlen) {
        if (buf) {
          Note("OpenReadHead failed for cachekey %X : vector inconsistency with %d", key.word(0), doc->hlen);
          dir_delete(&key, vol, &dir);
        }
        err = ECACHE_BAD_META_DATA;
        goto Ldone;
      }
      if (cache_config_select_alternate) {
#ifdef FIXME_NONMODULAR
        alternate_index = HttpTransactCache::SelectFromAlternates(&vector, &request, params);
#else
        alternate_index = 0;
#endif
        if (alternate_index < 0) {
          err = ECACHE_ALT_MISS;
          goto Ldone;
        }
      } else
        alternate_index = 0;
      alternate_tmp = vector.get(alternate_index);
      if (!alternate_tmp->valid()) {
        if (buf) {
          Note("OpenReadHead failed for cachekey %X : alternate inconsistency", key.word(0));
          dir_delete(&key, vol, &dir);
        }
        goto Ldone;
      }

      alternate.copy_shallow(alternate_tmp);
      doc_len = alternate.object_size_get();
      // check the doc_len and the C-L
      if (alternate.response_get()->presence(MIME_PRESENCE_CONTENT_LENGTH)) {
        if(alternate.response_get()->get_content_length() != (int64_t)doc_len) {
          HTTPHdr *hdr = alternate.response_get();
          char b[4096];
          fprintf(stderr, "+++++++++ %s +++++++++\n", "Content-Length not match doc size");
          int used, tmp, offset, done;
          offset = 0;

          do {
            used = 0;
            tmp = offset;
            done = hdr->print (b, 4095, &used, &tmp);
            offset += used;
            b[used] = '\0';
            fprintf (stderr, "%s", b);
          } while((!done));

          dir_delete(&key, vol, &dir);
          goto Ldone;
        }
      }

      alternate.object_key_get(&key);

      if (key == doc->key) {      // is this my data?
        f.single_fragment = doc->single_fragment();
        ink_assert(f.single_fragment);     // otherwise need to read earliest
        ink_assert(doc->hlen);
        doc_pos = doc->prefix_len();
        next_CacheKey(&key, &doc->key);
      } else {
        f.single_fragment = false;
      }
    } else
#endif
    {
      next_CacheKey(&key, &doc->key);
      f.single_fragment = doc->single_fragment();
      doc_pos = doc->prefix_len();
      doc_len = doc->total_len;
    }
    // the first fragment might have been gc'ed. Make sure the first
    // fragment is there before returning CACHE_EVENT_OPEN_READ
    if (!f.single_fragment)
      goto Learliest;

#ifdef HIT_EVACUATE
    if (!f.read_from_ssd && vol->within_hit_evacuate_window(&dir) &&
        (!cache_config_hit_evacuate_size_limit || doc_len <= (uint64_t)cache_config_hit_evacuate_size_limit)) {
      DDebug("cache_hit_evac", "dir: %"PRId64", write: %"PRId64", phase: %d",
            dir_offset(&dir), offset_to_vol_offset(vol, vol->header->write_pos), vol->header->phase);
      f.hit_evacuate = 1;
    }
#endif

    frag_len = doc->flen;
    first_buf = buf;
    vol->begin_read(this);

    goto Lsuccess;

  Lread:
    // check for collision
    // INKqa07684 - Cache::lookup returns CACHE_EVENT_OPEN_READ_FAILED.
    // don't want to go through this BS of reading from a writer if
    // its a lookup. In this case lookup will fail while the document is
    // being written to the cache.

    // fix me: move this out of vol lock`s range. has no need anymore.
    if (!f.read_from_writer_called && writerTable.probe_entry(&key, &cw)) {
      if (f.lookup) {
        err = ECACHE_DOC_BUSY;
        goto Ldone;
      }
      goto Lwriter;
    }
    if (dir_probe(&key, vol, &dir, &last_collision)) {
      first_dir = dir;
      int ret = do_read_call(&key);
      if (ret == EVENT_RETURN)
        goto Lcallreturn;
      return ret;
    }
  }
Ldone:
  if (!f.lookup) {
    CACHE_INCREMENT_DYN_STAT(cache_read_failure_stat);
    _action.continuation->handleEvent(CACHE_EVENT_OPEN_READ_FAILED, (void *) -err);
  } else {
    CACHE_INCREMENT_DYN_STAT(cache_lookup_failure_stat);
    _action.continuation->handleEvent(CACHE_EVENT_LOOKUP_FAILED, (void *) -err);
  }
  return free_CacheVC(this);
Lwriter:
  SET_HANDLER(&CacheVC::openReadFromWriterHead);
  return handleEvent(EVENT_IMMEDIATE, 0);
Lcallreturn:
  return handleEvent(AIO_EVENT_DONE, 0); // hopefully a tail call
Lsuccess:
  SET_HANDLER(&CacheVC::openReadMain);
  return callcont(CACHE_EVENT_OPEN_READ);
Lookup:
  CACHE_INCREMENT_DYN_STAT(cache_lookup_success_stat);
  _action.continuation->handleEvent(CACHE_EVENT_LOOKUP, 0);
  return free_CacheVC(this);
Learliest:
  first_buf = buf;
  buf = NULL;
  earliest_key = key;
  last_collision = NULL;
  SET_HANDLER(&CacheVC::openReadStartEarliest);
  return openReadStartEarliest(event, e);
}
//
//int
//ClusterCacheVC::handleRead(int event, void *data)
//{
//  in_progress = true;
//  PUSH_HANDLER(&ClusterCacheVC::openReadReadDone);
//  if (!cluster_send_message(cs, CLUSTER_CACHE_DATA_REENABLE, NULL, 0, PRIORITY_HIGH))
//    return EVENT_CONT;
//  cluster_close_session(cs);
//  return calluser(VC_EVENT_ERROR);
//}
//
//int
//ClusterCacheVC::openReadReadDone(int event, void *data)
//{
//  cancel_trigger();
//  in_progress = false;
//  POP_HANDLER;
//
//  switch (event) {
//    case CLUSTER_CACHE_DATA_ERR_FUNCTION:
//      event = *(int *)data;
//      break;
//    case CLUSTER_CACHE_DATA_DONE_FUNCTION:
//    {
//      ClusterBuffer *cb = (ClusterBuffer *) data;
//      cb->get_data(&d_len);
//      doc_pos = 0;
//      buf = cb->data;
//      free_ClusterBuffer(cb);
//      break;
//    }
//    case CLUSTER_INTERNEL_ERROR:
//    default:
//      event = VC_EVENT_ERROR;
//      break;
//  }
//  // recevied data from cluster
//
//  return handleEvent(event, data);
//}
//
//int
//ClusterCacheVC::openReadStart(int event, void *data)
//{
//  if (event != CACHE_EVENT_OPEN_READ) {
//    // prevent further trigger
//    remote_closed = true;
//    cluster_close_session(cs);
//    _action.continuation->handleEvent(CACHE_EVENT_OPEN_READ_FAILED, data);
//    free_ClusterCacheVC(this);
//    return EVENT_DONE;
//  }
//
//  doc_len = alternate.object_size_get();
//  SET_HANDLER(&ClusterCacheVC::openReadMain);
//  callcont(CACHE_EVENT_OPEN_READ);
//  return EVENT_CONT;
//}
//int
//ClusterCacheVC::openReadMain(int event, void *e)
//{
//  NOWARN_UNUSED(e);
//  NOWARN_UNUSED(event);
//
//  cancel_trigger();
//
//  if (event == VC_EVENT_ERROR || event == VC_EVENT_EOS) {
//    remote_closed = true;
//    cluster_close_session(cs);
//    return calluser(event);
//  }
//
//  int64_t ntodo = vio.ntodo();
//  int64_t bytes = d_len - doc_pos;
//  IOBufferBlock *b = NULL;
//  if (ntodo <= 0)
//    return EVENT_CONT;
//  if (vio.buffer.mbuf->max_read_avail() > vio.buffer.writer()->water_mark && vio.ndone) // initiate read of first block
//    return EVENT_CONT;
//  if ((bytes <= 0) && vio.ntodo() >= 0)
//    goto Lread;
//  if (bytes > vio.ntodo())
//    bytes = vio.ntodo();
//  b = new_IOBufferBlock(buf, bytes, doc_pos);
//  b->_buf_end = b->_end;
//  vio.buffer.mbuf->append_block(b);
//  vio.ndone += bytes;
//
//  if (vio.ntodo() <= 0)
//    return calluser(VC_EVENT_READ_COMPLETE);
//  else {
//    if (calluser(VC_EVENT_READ_READY) == EVENT_DONE)
//      return EVENT_DONE;
//    // we have to keep reading until we give the user all the
//    // bytes it wanted or we hit the watermark.
//    if (vio.ntodo() > 0 && !vio.buffer.writer()->high_water())
//      goto Lread;
//    return EVENT_CONT;
//  }
//Lread: {
//    if (vio.ndone >= (int64_t)doc_len) {
//      // reached the end of the document and the user still wants more
//      return calluser(VC_EVENT_EOS);
//    }
//    // if the state machine calls reenable on the callback from the cache,
//    // we set up a schedule_imm event. The openReadReadDone discards
//    // EVENT_IMMEDIATE events. So, we have to cancel that trigger and set
//    // a new EVENT_INTERVAL event.
//    cancel_trigger();
//    return handleRead(event, e);
//  }
//}
