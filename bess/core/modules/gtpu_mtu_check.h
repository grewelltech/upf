/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Intel Corporation
 */
#ifndef BESS_MODULES_GTPU_MTU_CHECK_H_
#define BESS_MODULES_GTPU_MTU_CHECK_H_
/*----------------------------------------------------------------------------------*/
#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../utils/endian.h"
#include <atomic>
/*----------------------------------------------------------------------------------*/
class GtpuMtuCheck final : public Module {
 public:
  /* gates: (0) fits, or not a downlink forward; (1) ICMP fragmentation needed;
   * (2) DF set and too big, ICMP sent; (3) DF set and too big, no ICMP sent;
   * (4) DF clear and too big, forwarded */
  enum : gate_idx_t {
    kGateFits = 0,
    kGateIcmp,
    kGateDfDrop,
    kGateDfDropNoIcmp,
    kGateNoDfOversize,
  };
  static const gate_idx_t kNumOGates = 5;

  static const Commands cmds;

  GtpuMtuCheck() { max_allowed_workers_ = Worker::kMaxWorkers; }

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;
  CommandResponse Init(const bess::pb::GtpuMtuCheckArg &arg);
  CommandResponse CommandSetMtu(
      const bess::pb::GtpuMtuCheckCommandSetMtuArg &arg);

  std::string GetDesc() const override;

 private:
  /* takes one ICMP from the rate limit; false when there is none left */
  bool TakeIcmpToken(uint64_t now_ns);
  /* the ICMP fragmentation needed for p, or nullptr when out of packets */
  bess::Packet *BuildIcmp(bess::Packet *p, uint16_t mtu);

  /* largest inner IPv4 packet, in bytes, that fits through N3 once
   * encapsulated */
  std::atomic<uint16_t> mtu_{0};
  bess::utils::be32_t icmp_src_;
  /* nanoseconds of rate limit spent per ICMP, and the burst it allows */
  uint64_t icmp_interval_ns_ = 0;
  uint64_t icmp_burst_ns_ = 0;
  /* time at which the rate limit is full again (GCRA) */
  std::atomic<uint64_t> icmp_tat_ns_{0};
  std::atomic<uint16_t> next_ip_id_{0};
  int action_attr_ = -1;
};
/*----------------------------------------------------------------------------------*/
#endif  // BESS_MODULES_GTPU_MTU_CHECK_H_
