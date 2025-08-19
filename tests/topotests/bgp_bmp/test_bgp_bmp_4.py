#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright 2025 6WIND S.A.
#

"""
test_bgp_bmp.py_4: Test BGP BMP Scalability

    +------+            +------+               +------+
    |      |            |      |               |      |
    | BMP1 |------+-----|  R1  |---------------|  R2  |
    |      |      |     |      |               |      |
    +------+      |     +--+---+               +------+
                  |        |
    +------+      |     +--+---+
    |      |      |     |      |
    | BMP2 |------+     |  R3  |
    |      |            |      |
    +------+            +------+

Setup two routers R1 and R2 with one link configured with IPv4 and
IPv6 addresses.
Configure BGP in R1 and R2 to exchange prefixes from
the latter to the first router.
Setup a link between R1 and the BMP server, activate the BMP feature in R1
and ensure the monitored BGP sessions logs are well present on the BMP server.
"""

from functools import partial
from time import sleep

import json
import os
import pytest
import sys

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join("../"))
sys.path.append(os.path.join("../lib/"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.bgp import verify_bgp_convergence_from_running_config
from lib.bgp import bgp_configure_prefixes
from .bgpbmp import (
    bmp_check_for_prefixes,
    bmp_check_for_peer_message,
    bmp_display_seq,
    bmp_get_seq,
    bmp_update_seq,
    bmp_reset_seq,
    BMPSequenceContext,
)
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]

PRE_POLICY = "pre-policy"
POST_POLICY = "post-policy"
LOC_RIB = "loc-rib"

UPDATE_EXPECTED_JSON = False
DEBUG_PCAP = False

# Create a global BMP sequence context for this test module
bmp_seq_context = BMPSequenceContext()

SEQ_BACKUP = 0

def build_topo(tgen):
    tgen.add_router("r1multibmp")
    tgen.add_router("r2")
    tgen.add_router("r3multibmp")  # CPE behind r1

    tgen.add_bmp_server("bmp1import", ip="192.0.2.10", defaultRoute="via 192.0.2.1", use_nc=True)
    tgen.add_bmp_server(
        "bmp2import", ip="192.0.2.20", defaultRoute="via 192.0.2.1", port=1790, use_nc=True
    )

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1multibmp"])
    switch.add_link(tgen.gears["bmp1import"])
    switch.add_link(tgen.gears["bmp2import"])

    tgen.add_link(tgen.gears["r1multibmp"], tgen.gears["r2"], "r1multibmp-eth1", "r2-eth0")
    tgen.add_link(tgen.gears["r1multibmp"], tgen.gears["r3multibmp"], "r1multibmp-eth2", "r3multibmp-eth0")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    tgen.net["r1multibmp"].cmd(
        """
ip link add vrf1 type vrf table 10
ip link set vrf1 up
ip link set r1multibmp-eth2 master vrf1
        """
    )
    tgen.net["r3multibmp"].cmd(
        """
ip link add r3-loop1 type dummy
ip link set r3-loop1 up
        """
    )
    tgen.net["r2"].cmd(
        """
ip link add r2-loop1 type dummy
ip link set r2-loop1 up
        """
    )

    for rname, router in tgen.routers().items():
        logger.info("Loading router %s" % rname)
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [(TopoRouter.RD_ZEBRA, None), (TopoRouter.RD_BGP, "-M bmp"), (TopoRouter.RD_SHARP, None)],
        )

    tgen.start_router()

    logger.info("starting BMP servers")
    for bmp_name, server in tgen.get_bmp_servers().items():
        server.start()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_convergence():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    result = verify_bgp_convergence_from_running_config(tgen, dut="r1multibmp")
    assert result is True, "BGP is not converging"


def test_bmp_session_to_bmp_collectors_up():
    """
    Assert the logging of the bmp server.
    """
    tgen = get_topogen()

    def check_for_bmp_session_up(bmpserver):
        output = tgen.net["r1multibmp"].cmd(f"vtysh -c 'show bmp' | grep {bmpserver}")
        if 'Up' not in output:
            return False
        return True

    test_func = partial(check_for_bmp_session_up, "192.0.2.10")
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert success, "The BMP server 1 is not logging"

    test_func = partial(check_for_bmp_session_up, "192.0.2.20")
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert success, "The BMP server 2 is not logging"



def test_bmp_bgp_send_updates():
    """
    Add/withdraw bgp unicast prefixes and check the bmp logs.
    """
    tgen = get_topogen()
    logger.info("*** Add redistribute sharp on r2 ***")
    tgen.gears["r2"].vtysh_cmd(
        """
        configure terminal
        router bgp 65502
        address-family ipv4 unicast
         redistribute sharp
        exit-address-family
        address-family ipv6 unicast
         redistribute sharp
        exit-address-family
        """
    )
    
    logger.info("*** Configuring r2-loop1 interface from r2 ***")
    tgen.gears["r2"].vtysh_cmd(
        """
        configure terminal
        interface r2-loop1
         ip address 172.31.2.2/24
         ipv6 address 172:31:2::2/64
        """
    )

    logger.info("*** Sending a lot of prefixes from r2 ***")
    tgen.gears["r2"].vtysh_cmd(
        """
        sharp install routes 1.1.1.1 nexthop 172.31.2.100 100000
        """
    )
#        sharp install routes 1.1.1.1 nexthop 172.31.0.100 1000000
#        sharp install routes 1:1::1:1 nexthop 172:31::100 1000000
    logger.info("*** Sending a lot of prefixes from r3multibmp ***")
    tgen.gears["r3multibmp"].vtysh_cmd(
        """
        sharp install routes 2.2.2.2 nexthop 172.31.1.100 100000
        """
    )
#        sharp install routes 2.2.2.2 nexthop 172.31.1.100 1000000
#        sharp install routes 2:2::2:2 nexthop 172:31:1::100 1000000


def test_r1multibmp_monitor_bmp_queue_while_failover():
    """
    Check BMP client queues are emptied during sync with 2 collectors,
    When one of the collector fails
    """
    tgen = get_topogen()

    logger.info("*** Dump BMP information r1multibmp before BMP collector disconnect ***")
    output = tgen.gears["r1multibmp"].vtysh_cmd("show bmp queue detail")
    logger.info(output)
    logger.info(f"*** Stopping BMP1 collector: pid {tgen.gears['bmp1import'].pid_value} ***")
    tgen.gears["bmp1import"].stop()
    sleep(1)
    logger.info("*** Dump BMP information r1multibmp after BMP collector disconnected ***")
    output = tgen.gears["r1multibmp"].vtysh_cmd("show bmp queue detail")
    logger.info(output)


    def check_for_bmp_queue_empty():
        output = tgen.net["r1multibmp"].cmd(f"vtysh -c 'show bmp queue' | grep 'Count updlist'")
        if 'Count updlist 0, updhash 0, loc updlist 0, loc updhash 0' not in output:
            return False
        return True

    test_func = partial(check_for_bmp_queue_empty)
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert success, "The BMP queues are not empty"

def test_r1multibmp_monitor_bmp_queue_while_collector_reconnect():
    """
    Check BMP client queues are emptied after BMP collector reconnects
    """
    tgen = get_topogen()

    logger.info("*** restarting BMP servers 1 ***")
    tgen.gears["bmp1import"].start()
    sleep(1)
    logger.info("*** Dump BMP information r1multibmp after BMP collector disconnected ***")
    output = tgen.gears["r1multibmp"].vtysh_cmd("show bmp")
    logger.info(output)
    def check_for_bmp_queue_empty():
        output = tgen.net["r1multibmp"].cmd(f"vtysh -c 'show bmp queue' | grep 'Count updlist'")
        if 'Count updlist 0, updhash 0, loc updlist 0, loc updhash 0' not in output:
            return False
        return True

    test_func = partial(check_for_bmp_queue_empty)
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert success, "The BMP queues are not empty"

    logger.info("*** Dump BMP information r1multibmp after BMP collector disconnected ***")
    output = tgen.gears["r1multibmp"].vtysh_cmd("show bmp queue detail")
    logger.info(output)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
