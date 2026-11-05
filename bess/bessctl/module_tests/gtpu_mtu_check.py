# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Intel Corporation

# GtpuMtuCheck: downlink packets too big for N3 once encapsulated, and the
# ICMP fragmentation needed it sends for them.

import struct

from test_utils import *

N6 = "192.168.250.3"
UE = "10.250.0.1"
DN = "10.0.0.9"

# a 1500-byte N3 less 44 bytes of outer IPv4, UDP, GTP-U and PSC
MTU = 1456

# BESS default batch size
BATCH_SIZE = 64

FITS, ICMP, DF_DROP, DF_DROP_NO_ICMP, NO_DF_OVERSIZE = range(5)
GATES = [FITS, ICMP, DF_DROP, DF_DROP_NO_ICMP, NO_DF_OVERSIZE]

ETH = scapy.Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
ETH_LEN = len(bytes(ETH))

# the action farLookup writes for a downlink forward, and for an uplink one
DOWNLINK = [{"name": "action", "size": 1, "value_int": 0}]
UPLINK = [{"name": "action", "size": 1, "value_int": 1}]


def packet(ip_len, df=True, src=DN, l4=None):
    """A frame carrying an IPv4 packet of `ip_len` bytes from `src` to the UE."""
    ip = scapy.IP(src=src, dst=UE, flags="DF" if df else 0)
    if l4 is None:
        l4 = scapy.UDP(sport=53, dport=40001)
    hdr = ip / l4
    return bytes(ETH / hdr / (b"y" * (ip_len - len(bytes(hdr)))))


def ones_complement_sum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


class GtpuMtuCheckTest(BessModuleTestCase):
    def check(self, pkts, attrs=DOWNLINK, rate=0, burst=0, mtu=MTU, batched=False):
        """What GtpuMtuCheck sends out of each gate for `pkts`, as bytes. With
        `batched`, a Buffer in front gives it them in one ProcessBatch call."""
        meta = SetMetadata(attrs=attrs)
        check = GtpuMtuCheck(mtu=mtu, icmp_src=N6, icmp_rate=rate, icmp_burst=burst)
        self.bess.connect_modules(meta.name, check.name, 0, 0)

        first = meta
        if batched:
            first = Buffer()
            self.bess.connect_modules(first.name, meta.name, 0, 0)

        out = self.run_pipeline(first, check, 0, pkts, GATES, proto=bytes)
        self.assertEqual(sum(len(out[g]) for g in GATES if g != ICMP),
                         len(pkts), "a packet was lost or duplicated")
        return check, out

    def test_df_set_over_the_mtu_is_dropped_with_an_icmp(self):
        pkt = packet(MTU + 1)
        _, out = self.check([pkt])
        self.assertEqual(out[DF_DROP], [pkt])
        self.assertEqual(len(out[ICMP]), 1)

        frame = out[ICMP][0]
        ip = scapy.IP(frame[ETH_LEN:])
        self.assertEqual((ip.src, ip.dst), (N6, DN))
        self.assertEqual((ip.proto, ip.ttl, ip.flags), (1, 64, 0))
        self.assertEqual(ip.len, len(frame) - ETH_LEN)
        self.assertEqual(ones_complement_sum(frame[ETH_LEN : ETH_LEN + 20]), 0xFFFF,
                         "bad IPv4 checksum")

        icmp = frame[ETH_LEN + 20 :]
        itype, code, _, unused, mtu = struct.unpack("!BBHHH", icmp[:8])
        self.assertEqual((itype, code, unused, mtu), (3, 4, 0, MTU))
        self.assertEqual(ones_complement_sum(icmp), 0xFFFF, "bad ICMP checksum")

        # the original header and payload, up to a 576-byte datagram
        quote = icmp[8:]
        self.assertEqual(len(frame) - ETH_LEN, 576)
        self.assertEqual(quote, pkt[ETH_LEN : ETH_LEN + len(quote)])

    def test_a_short_original_is_quoted_whole(self):
        pkt = packet(100)
        _, out = self.check([pkt], mtu=80)
        frame = out[ICMP][0]
        self.assertEqual(scapy.IP(frame[ETH_LEN:]).len, 20 + 8 + 100)
        self.assertEqual(frame[ETH_LEN + 28 :], pkt[ETH_LEN:])

    def test_df_clear_over_the_mtu_is_forwarded_unchanged(self):
        pkt = packet(MTU + 1, df=False)
        _, out = self.check([pkt])
        self.assertEqual(out[NO_DF_OVERSIZE], [pkt])
        self.assertEqual(out[ICMP], [])

    def test_at_and_under_the_mtu_are_untouched(self):
        pkts = [packet(MTU), packet(MTU - 1), packet(64)]
        _, out = self.check(pkts)
        self.assertEqual(out[FITS], pkts)

    def test_only_downlink_forwards_are_checked(self):
        pkt = packet(MTU + 100)
        _, out = self.check([pkt], attrs=UPLINK)
        self.assertEqual(out[FITS], [pkt])

    def test_the_rate_limit_holds_over_a_burst(self):
        # one batch, so the whole burst falls well inside the 1 s interval
        pkts = [packet(MTU + 1)] * BATCH_SIZE
        _, out = self.check(pkts, rate=1, burst=5, batched=True)
        self.assertEqual(len(out[ICMP]), 5)
        self.assertEqual(len(out[DF_DROP]), 5)
        self.assertEqual(len(out[DF_DROP_NO_ICMP]), BATCH_SIZE - 5)

    def test_no_icmp_about_an_icmp_error_or_from_a_multicast_source(self):
        error = packet(MTU + 1, l4=scapy.ICMP(type=3, code=1))
        mcast = packet(MTU + 1, src="224.0.0.9")
        _, out = self.check([error, mcast])
        self.assertEqual(out[DF_DROP_NO_ICMP], [error, mcast])
        self.assertEqual(out[ICMP], [])

    def test_set_mtu_moves_the_limit(self):
        pkt = packet(MTU + 1)
        check, out = self.check([pkt])
        self.assertEqual(out[DF_DROP], [pkt])

        check.set_mtu(mtu=MTU + 1)
        meta = SetMetadata(attrs=DOWNLINK)
        self.bess.connect_modules(meta.name, check.name, 0, 0)
        out = self.run_pipeline(meta, check, 0, [pkt], GATES, proto=bytes)
        self.assertEqual(out[FITS], [pkt])


suite = unittest.TestLoader().loadTestsFromTestCase(GtpuMtuCheckTest)
results = unittest.TextTestRunner(verbosity=2).run(suite)

if results.failures or results.errors:
    sys.exit(1)
