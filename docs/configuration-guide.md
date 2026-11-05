<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2022-present Open Networking Foundation
-->

# Configuration Guide

## PFCP Agent

This document focuses on frequently used configurations.

Please refer to [upf.jsonc](../conf/upf.jsonc) file for the full list of configurable parameters.

### Common configurations

These are configurations commonly shared between P4-UPF and BESS-UPF.

| Config | Default value | Mandatory | Comments |
| ------ | ------------- | --------- | -------- |
| `log_level` | info | No | |
| `hostname` | - | No | Used to get local IP address and local NodeID in PFCP messages |
| `http_port` | 8080 | No | |
| `max_req_retries` | 5 | No | Max retries for sending PFCP message towards SMF/SPGW-C |
| `resp_timeout` | 2s | No | Period to wait for a response from SMF/SPGW-C |
| `enable_end_marker` | false | No | |
| `enable_gtpu_path_monitoring` | false | No | |
| `cpiface.enable_ue_ip_alloc` | false | No | Whether to enable UPF-based UE IP allocation |
| `cpiface.ue_ip_pool` | - | Yes for P4-UPF or when `enable_ue_ip_alloc` is set | IP pool from which we allocate UE IP address |
| `cpiface.dnn` | - | No | Data Network Name to use during PFCP Association |

### BESS-UPF specific configurations

| Config | Default value | Mandatory | Comments |
| ------ | ------------- | --------- | -------- |
| `measure_upf` | false | No | Enable per port metrics |
| `measure_flow` | false | No | Enable per flow metrics |
| `access.ifname` | - | Yes | Access-facing network interface name |
| `core.ifname` | - | Yes | Core-facing network interface name |
| `enable_notify_bess` | false | No | Whether to enable Notify feature for DDNs |
| `mtu_check` | true | No | Drop downlink packets with DF set that would exceed the N3 MTU once encapsulated, and send their source ICMP fragmentation needed (`bessctl show module mtuCheck` counts each outcome) |
| `n3_mtu` | access interface MTU | No | N3 MTU for `mtu_check`; by default the access interface's MTU (af_packet) or the access port's MTU (DPDK) |
| `mtu_check_icmp_rate` | 1000 | No | ICMPs per second `mtu_check` may send |
| `mtu_check_icmp_burst` | 50 | No | ICMPs `mtu_check` may send back to back before the rate applies |
