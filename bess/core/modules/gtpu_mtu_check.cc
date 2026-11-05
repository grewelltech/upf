/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Intel Corporation
 */
/* for gtpu_mtu_check decls */
#include "gtpu_mtu_check.h"
/* for std::min, std::max */
#include <algorithm>
/* for IPVERSION */
#include <netinet/ip.h>
/* for CalculateIpv4Checksum(), CalculateGenericChecksum() */
#include "utils/checksum.h"
/* for ethernet header */
#include "utils/ether.h"
/* for GetDesc() */
#include "utils/format.h"
/* for icmp header */
#include "utils/icmp.h"
/* for ip header, ParseIpv4Address() */
#include "utils/ip.h"
/*----------------------------------------------------------------------------------*/
using bess::utils::be16_t;
using bess::utils::be32_t;
using bess::utils::Ethernet;
using bess::utils::Icmp;
using bess::utils::Ipv4;

/* the FAR action of a downlink forward (farForwardDAction in up4.bess) */
static const uint8_t kActionForwardDownlink = 0;
/* ICMP destination unreachable, fragmentation needed and DF set (RFC 792) */
static const uint8_t kIcmpDestUnreachable = 3;
static const uint8_t kIcmpFragNeeded = 4;
/* an ICMP error datagram is at most this long (RFC 1812 4.3.2.3) */
static const size_t kIcmpErrorMaxLen = 576;
/* precedence Internet control (RFC 1812 4.3.2.5), as Linux sends errors */
static const uint8_t kIcmpErrorTos = 0xc0;
static const uint8_t kIcmpErrorTtl = 64;

/* the fragment offset, without the flags */
static const uint16_t kFragOffsetMask = 0x1fff;

static const uint64_t kDefaultIcmpRate = 1000;
static const uint64_t kDefaultIcmpBurst = 50;
/*----------------------------------------------------------------------------------*/
const Commands GtpuMtuCheck::cmds = {
    {"set_mtu", "GtpuMtuCheckCommandSetMtuArg",
     MODULE_CMD_FUNC(&GtpuMtuCheck::CommandSetMtu), Command::THREAD_SAFE},
};
/*----------------------------------------------------------------------------------*/
/* whether an error about this packet may be sent (RFC 1812 4.3.2.7): not about
 * an ICMP error, a fragment other than the first, or a packet whose source is
 * not one host */
static bool IcmpAllowed(const Ipv4 *ip, size_t ip_bytes, size_t avail) {
  if ((ip->fragment_offset.value() & kFragOffsetMask) != 0) {
    return false;
  }

  uint32_t src = ip->src.value();
  uint8_t first = src >> 24;
  /* this network, loopback, multicast, reserved and limited broadcast */
  if (first == 0 || first == 127 || first >= 224) {
    return false;
  }

  if (ip->protocol == Ipv4::Proto::kIcmp) {
    if (ip_bytes + 1 > avail) {
      return false;
    }
    uint8_t type = reinterpret_cast<const uint8_t *>(ip)[ip_bytes];
    /* destination unreachable, source quench, redirect, time exceeded,
     * parameter problem */
    if (type == 3 || type == 4 || type == 5 || type == 11 || type == 12) {
      return false;
    }
  }

  return true;
}
/*----------------------------------------------------------------------------------*/
bool GtpuMtuCheck::TakeIcmpToken(uint64_t now_ns) {
  uint64_t tat = icmp_tat_ns_.load(std::memory_order_relaxed);
  uint64_t next;

  do {
    uint64_t base = std::max(tat, now_ns);
    if (base - now_ns > icmp_burst_ns_) {
      return false;
    }
    next = base + icmp_interval_ns_;
  } while (!icmp_tat_ns_.compare_exchange_weak(tat, next,
                                               std::memory_order_relaxed));

  return true;
}
/*----------------------------------------------------------------------------------*/
bess::Packet *GtpuMtuCheck::BuildIcmp(bess::Packet *p, uint16_t mtu) {
  bess::Packet *icmp_pkt = current_worker.packet_pool()->Alloc();
  if (icmp_pkt == nullptr) {
    return nullptr;
  }

  const Ethernet *eth_in = p->head_data<const Ethernet *>();
  const Ipv4 *ip_in = reinterpret_cast<const Ipv4 *>(eth_in + 1);

  /* the original IP header and as much of its payload as fits in 576 bytes,
   * from the first segment */
  size_t quote_len =
      std::min<size_t>(p->head_len() - sizeof(Ethernet),
                       kIcmpErrorMaxLen - sizeof(Ipv4) - sizeof(Icmp));
  size_t ip_len = sizeof(Ipv4) + sizeof(Icmp) + quote_len;
  size_t frame_len = sizeof(Ethernet) + ip_len;

  char *ptr = static_cast<char *>(icmp_pkt->buffer()) + SNBUF_HEADROOM;
  icmp_pkt->set_data_off(SNBUF_HEADROOM);
  icmp_pkt->set_total_len(frame_len);
  icmp_pkt->set_data_len(frame_len);

  Ethernet *eth = reinterpret_cast<Ethernet *>(ptr);
  Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);
  Icmp *icmp = reinterpret_cast<Icmp *>(ip + 1);

  /* back where the original came from; the route and port modules after
   * this one rewrite both addresses */
  eth->dst_addr = eth_in->src_addr;
  eth->src_addr = eth_in->dst_addr;
  eth->ether_type = be16_t(Ethernet::Type::kIpv4);

  ip->version = IPVERSION;
  ip->header_length = sizeof(Ipv4) >> 2;
  ip->type_of_service = kIcmpErrorTos;
  ip->length = be16_t(ip_len);
  ip->id = be16_t(next_ip_id_.fetch_add(1, std::memory_order_relaxed));
  ip->fragment_offset = be16_t(0);
  ip->ttl = kIcmpErrorTtl;
  ip->protocol = Ipv4::Proto::kIcmp;
  ip->checksum = 0;
  ip->src = icmp_src_;
  ip->dst = ip_in->src;

  /* the unused half of the second word, then the next-hop MTU (RFC 1191) */
  icmp->type = kIcmpDestUnreachable;
  icmp->code = kIcmpFragNeeded;
  icmp->checksum = 0;
  icmp->ident = be16_t(0);
  icmp->seq_num = be16_t(mtu);
  bess::utils::Copy(icmp + 1, ip_in, quote_len);

  icmp->checksum =
      bess::utils::CalculateGenericChecksum(icmp, sizeof(Icmp) + quote_len);
  ip->checksum = bess::utils::CalculateIpv4Checksum(*ip);

  return icmp_pkt;
}
/*----------------------------------------------------------------------------------*/
void GtpuMtuCheck::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  int cnt = batch->cnt();
  uint16_t mtu = mtu_.load(std::memory_order_relaxed);
  bess::metadata::mt_offset_t off = attr_offset(action_attr_);

  for (int i = 0; i < cnt; i++) {
    bess::Packet *p = batch->pkts()[i];

    /* the length GtpuEncap encapsulates: the frame without its Ethernet
     * header */
    uint32_t inner_len = p->total_len() - sizeof(Ethernet);
    if (inner_len <= mtu ||
        get_attr_with_offset<uint8_t>(off, p) != kActionForwardDownlink) {
      EmitPacket(ctx, p, kGateFits);
      continue;
    }

    /* only an IPv4 header in the first segment can be judged */
    if (p->head_len() < static_cast<int>(sizeof(Ethernet) + sizeof(Ipv4))) {
      EmitPacket(ctx, p, kGateFits);
      continue;
    }

    Ethernet *eth = p->head_data<Ethernet *>();
    Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);
    size_t avail = p->head_len() - sizeof(Ethernet);
    if (eth->ether_type != be16_t(Ethernet::Type::kIpv4) ||
        ip->version != IPVERSION) {
      EmitPacket(ctx, p, kGateFits);
      continue;
    }

    if ((ip->fragment_offset.value() & Ipv4::Flag::kDF) == 0) {
      EmitPacket(ctx, p, kGateNoDfOversize);
      continue;
    }

    size_t ip_bytes = ip->header_length << 2;
    if (ip_bytes < sizeof(Ipv4) || !IcmpAllowed(ip, ip_bytes, avail) ||
        !TakeIcmpToken(ctx->current_ns)) {
      EmitPacket(ctx, p, kGateDfDropNoIcmp);
      continue;
    }

    bess::Packet *icmp_pkt = BuildIcmp(p, mtu);
    if (icmp_pkt == nullptr) {
      EmitPacket(ctx, p, kGateDfDropNoIcmp);
      continue;
    }

    EmitPacket(ctx, icmp_pkt, kGateIcmp);
    EmitPacket(ctx, p, kGateDfDrop);
  }
}
/*----------------------------------------------------------------------------------*/
CommandResponse GtpuMtuCheck::Init(const bess::pb::GtpuMtuCheckArg &arg) {
  if (arg.mtu() < 68 || arg.mtu() > 65535) {
    return CommandFailure(EINVAL, "mtu must be between 68 and 65535");
  }
  mtu_ = arg.mtu();

  if (!bess::utils::ParseIpv4Address(arg.icmp_src(), &icmp_src_)) {
    return CommandFailure(EINVAL, "icmp_src is not an IPv4 address: %s",
                          arg.icmp_src().c_str());
  }

  uint64_t rate = arg.icmp_rate() ? arg.icmp_rate() : kDefaultIcmpRate;
  uint64_t burst = arg.icmp_burst() ? arg.icmp_burst() : kDefaultIcmpBurst;
  icmp_interval_ns_ = 1000000000ull / rate;
  icmp_burst_ns_ = (burst - 1) * icmp_interval_ns_;

  using AccessMode = bess::metadata::Attribute::AccessMode;
  action_attr_ = AddMetadataAttr("action", sizeof(uint8_t), AccessMode::kRead);

  return CommandSuccess();
}
/*----------------------------------------------------------------------------------*/
CommandResponse GtpuMtuCheck::CommandSetMtu(
    const bess::pb::GtpuMtuCheckCommandSetMtuArg &arg) {
  if (arg.mtu() < 68 || arg.mtu() > 65535) {
    return CommandFailure(EINVAL, "mtu must be between 68 and 65535");
  }
  mtu_ = arg.mtu();

  return CommandSuccess();
}
/*----------------------------------------------------------------------------------*/
std::string GtpuMtuCheck::GetDesc() const {
  return bess::utils::Format("mtu %u", mtu_.load(std::memory_order_relaxed));
}
/*----------------------------------------------------------------------------------*/
ADD_MODULE(GtpuMtuCheck, "gtpu_mtu_check",
           "drops downlink packets too big for N3 and sends ICMP fragmentation "
           "needed")
