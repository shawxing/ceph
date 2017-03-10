// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
#ifndef CEPH_TEST_OSDC_MEMWRITEBACK_H
#define CEPH_TEST_OSDC_MEMWRITEBACK_H

#include "include/atomic.h"
#include "include/Context.h"
#include "include/types.h"
#include "osd/osd_types.h"
#include "osdc/WritebackHandler.h"

class Finisher;
class Mutex;

class MemWriteback : public WritebackHandler {
public:
  MemWriteback(CephContext *cct, Mutex *lock, uint64_t delay_ns);
  virtual ~MemWriteback();

  virtual void read(const object_t& oid, uint64_t object_no,
		    const object_locator_t& oloc, uint64_t off, uint64_t len,
		    snapid_t snapid, bufferlist *pbl, uint64_t trunc_size,
		    __u32 trunc_seq, int op_flags, Context *onfinish);

  virtual ceph_tid_t write(const object_t& oid, const object_locator_t& oloc,
			   uint64_t off, uint64_t len,
			   const SnapContext& snapc, const bufferlist &bl,
			   utime_t mtime, uint64_t trunc_size,
			   __u32 trunc_seq,
			   Context *oncommit);

  using WritebackHandler::write;

  virtual bool may_copy_on_write(const object_t&, uint64_t, uint64_t,
				 snapid_t);
  void write_object_data(const object_t& oid, uint64_t off, uint64_t len,
			 const bufferlist& data_bl);
  int read_object_data(const object_t& oid, uint64_t off, uint64_t len,
		       bufferlist *data_bl);
private:
  std::map<object_t, bufferlist> object_data;
  CephContext *m_cct;
  Mutex *m_lock;
  uint64_t m_delay_ns;
  atomic_t m_tid;
  Finisher *m_finisher;
};

#endif
