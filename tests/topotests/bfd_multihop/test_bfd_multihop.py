#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bfd_multihop.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2024 6WIND
#

"""
test_bfd_multihop.py:
Test the FRR BFD daemon multi hop.
Test the FRR BFD daemon multi hop with static routing
Test the FRR BFD daemon auto hop with static routing
"""

import os
import sys
import json
from functools import partial
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bfdd, pytest.mark.bgpd]


def setup_module(mod):
    "Sets up the pytest environment"
    topodef = {
        "s1": ("r1", "r2"),
        "s2": ("r1", "r3"),
        "s3": ("r2", "r4"),
        "s4": ("r3", "r4"),
    }
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    logger.info("r1, configuring rp_filter on r1-eth1")
    topotest.sysctl_assure(router_list["r1"], "net.ipv4.conf.r1-eth1.rp_filter", 1)
    logger.info("r1, filtering traffic from 2001:db8:1::1 on r1-eth1")
    tgen.net["r1"].cmd(
        "ip6tables -A INPUT -i r1-eth1 --protocol udp --destination 2001:db8:1::1 -j DROP"
    )

    for rname, router in router_list.items():
        daemon_file = "{}/{}/bfdd.conf".format(CWD, rname)
        if os.path.isfile(daemon_file):
            router.load_config(TopoRouter.RD_BFD, daemon_file)

        daemon_file = "{}/{}/zebra.conf".format(CWD, rname)
        if os.path.isfile(daemon_file):
            router.load_config(TopoRouter.RD_ZEBRA, daemon_file)

        daemon_file = "{}/{}/staticd.conf".format(CWD, rname)
        if os.path.isfile(daemon_file):
            router.load_config(TopoRouter.RD_STATIC, daemon_file)

    # Initialize all routers.
    tgen.start_router()


def router_check_bfd_peers_count(router, cmd, count):
    "Check that show bfd peers json is empty"
    output = json.loads(router.vtysh_cmd(cmd))
    if len(output) == count:
        return None
    return len(output)


def expect_no_bfd_configuration(router):
    "Check that show bfd peers json is empty"

    logger.info("{}, waiting BFD state is empty".format(router))
    tgen = get_topogen()
    test_func = partial(
        router_check_bfd_peers_count,
        tgen.gears[router],
        "show bfd peers json",
        0,
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assertmsg = '"{}" BFD configuration failure'.format(router)
    assert result is None, assertmsg


def expect_bfd_configuration(router, peer_down=None, static=False):
    "Load JSON file and compare with 'show bfd peer json'"
    logger.info("waiting BFD configuration on router {}".format(router))
    tgen = get_topogen()
    bfd_config = json.loads(open("{}/{}/bfd-peers.json".format(CWD, router)).read())
    if peer_down:
        new_bfd_config = []
        for bfd_peer in bfd_config:
            for pdown in peer_down:
                if bfd_peer["peer"] == pdown:
                    bfd_peer.pop("status")
                    bfd_peer.pop("remote-diagnostic")
                    bfd_peer.pop("remote-receive-interval")
                    bfd_peer.pop("remote-transmit-interval")
                    bfd_peer["diagnostic"] = "control detection time expired"
            new_bfd_config.append(bfd_peer)
        bfd_config = new_bfd_config

    if static:
        new_bfd_config = []
        for bfd_peer in bfd_config:
            bfd_peer["type"] = "dynamic"
            bfd_peer["minimum-ttl"] = 2
            new_bfd_config.append(bfd_peer)
        bfd_config = new_bfd_config

    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears[router],
        "show bfd peers json",
        bfd_config,
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assertmsg = '"{}" BFD configuration failure'.format(router)
    assert result is None, assertmsg


def test_bfd_control_plane_init():
    "Wait for BFD to converge"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("test BFD configuration and state")
    expect_bfd_configuration("r1")
    expect_bfd_configuration("r4")


def change_routing(secondary=False):
    """
    Change configuration on r4 and r3 to forward traffic to 192.168.1.0/24
    and traffic to 2001:db8:1::/64
    """
    tgen = get_topogen()
    if secondary:
        logger.info("r4, delete static route for 192.168.1.0/24 traffic to r2")
        router = tgen.gears["r4"]
        router.vtysh_cmd("configure terminal\nno ip route 192.168.1.0/24 192.168.3.2\n")
        logger.info("r4, delete static route for 2001:db8:1::/64 traffic to r2")
        router.vtysh_cmd(
            "configure terminal\nno ipv6 route 2001:db8:1::/64 2001:db8:3::2\n"
        )

        logger.info("r4, create a static route to forward 192.168.1.0/24 traffic to r3")
        router.vtysh_cmd("configure terminal\nip route 192.168.1.0/24 192.168.4.3\n")
        logger.info(
            "r4, create a static route to forward 2001:db8::1::/64 traffic to r3"
        )
        router.vtysh_cmd(
            "configure terminal\nipv6 route 2001:db8:1::/64 2001:db8:4::3\n"
        )

        logger.info("r3, create a static route to forward 192.168.1.0/24 traffic to r1")
        router = tgen.gears["r3"]
        router.vtysh_cmd("configure terminal\nip route 192.168.1.0/24 192.168.2.1\n")
        logger.info(
            "r3, create a static route to forward 2001:db8:1::/64 traffic to r1"
        )
        router.vtysh_cmd(
            "configure terminal\nipv6 route 2001:db8:1::/64 2001:db8:2::1\n"
        )
    else:
        logger.info("r3, delete static route for 192.168.1.0/24 traffic to r1")
        router = tgen.gears["r3"]
        router.vtysh_cmd("configure terminal\nno ip route 192.168.1.0/24 192.168.2.1\n")
        logger.info("r3, delete static route for 2001:db8:1::/64 traffic to r1")
        router.vtysh_cmd(
            "configure terminal\nno ipv6 route 2001:db8:1::/64 2001:db8:2::1\n"
        )

        router = tgen.gears["r4"]
        logger.info("r4, delete static route for 192.168.1.0/24 traffic to r3")
        router.vtysh_cmd("configure terminal\nno ip route 192.168.1.0/24 192.168.4.3\n")
        logger.info("r4, delete static route for 2001:db8::1::/64 traffic to r3")
        router.vtysh_cmd(
            "configure terminal\nno ipv6 route 2001:db8:1::/64 2001:db8:4::3\n"
        )

        logger.info("r4, create static route to forward 192.168.1.0/24 traffic to r2")
        router.vtysh_cmd("configure terminal\nip route 192.168.1.0/24 192.168.3.2\n")
        logger.info("r4, create static route to forward 2001:db8:1::/64 traffic to r2")
        router.vtysh_cmd(
            "configure terminal\nipv6 route 2001:db8:1::/64 2001:db8:3::2\n"
        )


def expect_default_ip_route(router, iptype, down=False):
    tgen = get_topogen()
    if iptype == "ip":
        route = "0.0.0.0/0"
        filename = "route_default_down" if down else "route_default"
    else:
        route = "0::/0"
        filename = "route_ipv6_default_down" if down else "route_ipv6_default"

    ip_routes_dump = json.loads(
        open("{}/{}/{}.json".format(CWD, router, filename)).read()
    )
    logger.info(
        "waiting route {} to be present in {}, using {}.json".format(
            route, router, filename
        )
    )

    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears[router],
        "show {} route {} json".format(iptype, route),
        ip_routes_dump,
    )
    rv, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assertmsg = '"{}" convergence failure'.format(router)
    assert result is None, assertmsg
    if down:
        dump = tgen.gears[router].vtysh_cmd(
            "show {} route {} json".format(iptype, route), isjson=True
        )
        assert len(dump) == 1, "{}, number of route entries differ expected 1 ".format(
            router
        )


def test_bfd_control_plane_use_secondary_path():
    "Configure setup to forward BFD packet from primary link to the secondary link"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    change_routing(secondary=True)

    logger.info("test BFD configuration and state when half BFD sessions is down")
    expect_bfd_configuration("r1", peer_down=["192.168.3.4", "2001:db8:3::4"])
    expect_bfd_configuration("r4", peer_down=["192.168.1.1", "2001:db8:1::1"])

    logger.info("r1, unconfiguring rp_filter on r1-eth1")
    router_list = tgen.routers()
    topotest.sysctl_assure(router_list["r1"], "net.ipv4.conf.r1-eth1.rp_filter", 0)
    logger.info("r1, unfiltering traffic from 2001:db8:1::1 on r1-eth1")
    tgen.net["r1"].cmd(
        "ip6tables -D INPUT -i r1-eth1 --protocol udp --destination 2001:db8:1::1 -j DROP"
    )

    logger.info("test BFD configuration and state")
    expect_bfd_configuration("r1")
    expect_bfd_configuration("r4")


def test_bfd_control_plane_reuse_primary_path():
    "Configure setup to re-forward BFD packet to primary link only"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    change_routing(secondary=False)

    logger.info("r1, configuring rp_filter on r1-eth1")
    router_list = tgen.routers()
    topotest.sysctl_assure(router_list["r1"], "net.ipv4.conf.r1-eth1.rp_filter", 1)
    logger.info("r1, filtering traffic from 2001:db8:1::1 on r1-eth1")
    tgen.net["r1"].cmd(
        "ip6tables -A INPUT -i r1-eth1 --protocol udp --destination 2001:db8:1::1 -j DROP"
    )

    logger.info("test BFD configuration and state")
    expect_bfd_configuration("r1")
    expect_bfd_configuration("r4")


def test_static_bfd_multihop_init():
    "Delete BFD config, and use static BFD routes"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]
    logger.info("r1, deleting BFD peers")
    router.vtysh_cmd(
        """
        configure terminal\n
        bfd\n
        no peer 192.168.3.4 multihop local-address 192.168.1.1\n
        no peer 192.168.4.4 multihop local-address 192.168.2.1\n
        no peer 2001:db8:3::4 multihop local-address 2001:db8:1::1\n
        no peer 2001:db8:4::4 multihop local-address 2001:db8:2::1\n
        """
    )
    logger.info("r1, using static bfd multihop routes instead")
    router.vtysh_cmd(
        """
        configure terminal\n
        ip route 0.0.0.0/0 192.168.3.4 bfd multi-hop\n
        ip route 0.0.0.0/0 192.168.4.4 10 bfd multi-hop\n
        ipv6 route 0::0/0 2001:db8:3::4 bfd multi-hop\n
        ipv6 route 0::0/0 2001:db8:4::4 10 bfd multi-hop\n
        """
    )
    logger.info("test BFD configuration and state")
    expect_bfd_configuration("r1", static=True)
    expect_bfd_configuration("r4")
    logger.info("test default route state")
    expect_default_ip_route("r1", "ip")
    expect_default_ip_route("r1", "ipv6")


def test_static_bfd_multihop_use_secondary_path():
    "Configure setup to forward BFD packet from primary link to the secondary link"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        "Check that using seconday path triggers multi-hop BFD sessions to go down"
    )
    change_routing(secondary=True)
    logger.info("test BFD configuration and state when half BFD sessions is down")
    expect_bfd_configuration(
        "r1", static=True, peer_down=["192.168.3.4", "2001:db8:3::4"]
    )
    expect_bfd_configuration("r4", peer_down=["192.168.1.1", "2001:db8:1::1"])
    logger.info("test default route state when half BFD sessions is down")
    expect_default_ip_route("r1", "ip", down=True)
    expect_default_ip_route("r1", "ipv6", down=True)


def test_static_bfd_multihop_reuse_primary_path():
    "Configure setup to re-forward BFD packet to primary link only"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        "Check that re-using the primary path triggers multi-hop BFD sessions to go up"
    )
    change_routing(secondary=False)
    logger.info("test BFD configuration and state")
    expect_bfd_configuration("r1", static=True)
    expect_bfd_configuration("r4")
    logger.info("test default route state")
    expect_default_ip_route("r1", "ip")
    expect_default_ip_route("r1", "ipv6")


def test_static_bfd_autohop_init():
    "Delete static BFD config, and re add static BFD config in auto mode"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]
    logger.info("r1, deleting BFD peers")
    router.vtysh_cmd(
        """
        configure terminal\n
        bfd\n
        no ip route 0.0.0.0/0 192.168.3.4 bfd multi-hop\n
        no ip route 0.0.0.0/0 192.168.4.4 10 bfd multi-hop\n
        no ipv6 route 0::0/0 2001:db8:3::4 bfd multi-hop\n
        no ipv6 route 0::0/0 2001:db8:4::4 10 bfd multi-hop\n
        """
    )
    expect_no_bfd_configuration("r1")

    logger.info("r1, using static bfd autohop routes instead")
    router.vtysh_cmd(
        """
        configure terminal\n
        ip route 0.0.0.0/0 192.168.3.4 bfd auto-hop\n
        ip route 0.0.0.0/0 192.168.4.4 10 bfd auto-hop\n
        ipv6 route 0::0/0 2001:db8:3::4 bfd auto-hop\n
        ipv6 route 0::0/0 2001:db8:4::4 10 bfd auto-hop\n
        """
    )
    logger.info("test BFD configuration and state")
    expect_bfd_configuration("r1", static=True)
    expect_bfd_configuration("r4")
    logger.info("test default route state")
    expect_default_ip_route("r1", "ip")
    expect_default_ip_route("r1", "ipv6")


def test_static_bfd_autohop_use_secondary_path():
    "Configure setup to forward BFD packet from primary link to the secondary link"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        "Check that using the secondary path triggers auto-hop BFD sessions to go up"
    )
    change_routing(secondary=True)
    logger.info("test BFD configuration and state when half BFD sessions is down")
    expect_bfd_configuration(
        "r1", static=True, peer_down=["192.168.3.4", "2001:db8:3::4"]
    )
    expect_bfd_configuration("r4", peer_down=["192.168.1.1", "2001:db8:1::1"])
    logger.info("test default route state when half BFD sessions is down")
    expect_default_ip_route("r1", "ip", down=True)
    expect_default_ip_route("r1", "ipv6", down=True)


def test_static_bfd_autohop_reuse_primary_path():
    "Configure setup to re-forward BFD packet to primary link only"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        "Check that re-using the primary path triggers auto-hop BFD sessions to go up"
    )
    change_routing(secondary=False)
    logger.info("test BFD configuration and state")
    expect_bfd_configuration("r1", static=True)
    expect_bfd_configuration("r4")
    logger.info("test default route state")
    expect_default_ip_route("r1", "ip")
    expect_default_ip_route("r1", "ipv6")


def test_static_bfd_autohop_with_interface_init():
    "Delete static BFD config, and re add static BFD config in auto mode with interfaces"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]
    logger.info("r1, deleting BFD peers")
    router.vtysh_cmd(
        """
        configure terminal\n
        bfd\n
        no ip route 0.0.0.0/0 192.168.3.4 bfd auto-hop\n
        no ip route 0.0.0.0/0 192.168.4.4 10 bfd auto-hop\n
        no ipv6 route 0::0/0 2001:db8:3::4 bfd auto-hop\n
        no ipv6 route 0::0/0 2001:db8:4::4 10 bfd auto-hop\n
        """
    )
    expect_no_bfd_configuration("r1")

    logger.info("r1, using static bfd autohop with interface routes instead")
    router.vtysh_cmd(
        """
        configure terminal\n
        ip route 0.0.0.0/0 192.168.3.4 r1-eth0 bfd auto-hop\n
        ip route 0.0.0.0/0 192.168.4.4 r1-eth1 10 bfd auto-hop\n
        ipv6 route 0::0/0 2001:db8:3::4 r1-eth0 bfd auto-hop\n
        ipv6 route 0::0/0 2001:db8:4::4 r1-eth1 10 bfd auto-hop\n
        """
    )
    logger.info("test BFD configuration and state")
    expect_bfd_configuration("r1", static=True)
    expect_bfd_configuration("r4")
    logger.info("test default route state")
    expect_default_ip_route("r1", "ip")
    expect_default_ip_route("r1", "ipv6")


def test_static_bfd_autohop_with_interface_use_secondary_path():
    "Configure setup to forward BFD packet from primary link to the secondary link"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        "Check that using the secondary path triggers auto-hop BFD sessions to go up"
    )
    change_routing(secondary=True)
    logger.info("test BFD configuration and state when half BFD sessions is down")
    expect_bfd_configuration(
        "r1", static=True, peer_down=["192.168.3.4", "2001:db8:3::4"]
    )
    expect_bfd_configuration("r4", peer_down=["192.168.1.1", "2001:db8:1::1"])
    logger.info("test default route state when half BFD sessions is down")
    expect_default_ip_route("r1", "ip", down=True)
    expect_default_ip_route("r1", "ipv6", down=True)


def test_static_bfd_autohop_with_interface_reuse_primary_path():
    "Configure setup to re-forward BFD packet to primary link only"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        "Check that re-using the primary path triggers auto-hop BFD sessions to go up"
    )
    change_routing(secondary=False)
    logger.info("test BFD configuration and state")
    expect_bfd_configuration("r1", static=True)
    expect_bfd_configuration("r4")
    logger.info("test default route state")
    expect_default_ip_route("r1", "ip")
    expect_default_ip_route("r1", "ipv6")


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
