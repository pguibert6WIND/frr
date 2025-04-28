# SPDX-License-Identifier: ISC
#
# Copyright (c) 2025 by 6WIND
#

from functools import partial
from lib import topotest
from lib.bgp import verify_bgp_rib

from lib.topolog import logger


def evpn_ping_router(
    pingrouter,
    dst_router,
    ipv4_address=None,
    ipv6_address=None,
    source_vrf=None,
    source_vrf_netns_mode=False,
    dst_vrf=None,
):
    """
    internal function to check ping between r1 and r2
    """
    # Check IPv4 and IPv6 connectivity between r1 and r2 ( routing vxlan evpn)
    vrf_name_source = source_vrf if source_vrf else "default"
    vrf_name_dst = dst_vrf if dst_vrf else "default"
    if ipv4_address:
        logger.info(
            f"Check Ping IPv4 from R1({vrf_name_source}) to R2({vrf_name_source}, {ipv4_address})"
        )
        cmd = f"ping {ipv4_address} -f -c 1000"
        if source_vrf and source_vrf_netns_mode:
            output = pingrouter.run(f"ip netns exec {source_vrf} {cmd}")
        elif source_vrf:
            output = pingrouter.run(f"{cmd} -I {source_vrf}")
        else:
            output = pingrouter.run(f"{cmd}")
        logger.info(output)
        if "1000 packets transmitted, 1000 received" not in output:
            assertmsg = f"expected ping IPv4 from {pingrouter.name}({vrf_name_source}) to {dst_router.name}({vrf_name_dst}, {ipv4_address}) should be ok"
            assert 0, assertmsg
        else:
            logger.info(
                f"Check Ping IPv4 from {pingrouter.name}({vrf_name_source}) to {dst_router.name}({vrf_name_dst}, {ipv4_address}) OK"
            )

    if ipv6_address:
        logger.info(
            f"Check Ping IPv6 from  {pingrouter.name}({vrf_name_source}) to {dst_router.name}({vrf_name_dst}, {ipv6_address})"
        )
        cmd = f"ping {ipv6_address} -f -c 1000"
        if source_vrf and source_vrf_netns_mode:
            output = pingrouter.run(f"ip netns exec {source_vrf} {cmd}")
        elif source_vrf:
            output = pingrouter.run(f"{cmd} -I {source_vrf}")
        else:
            output = pingrouter.run(f"{cmd}")
        logger.info(output)
        if "1000 packets transmitted, 1000 received" not in output:
            assert (
                0
            ), f"expected ping IPv6 from {pingrouter.name}({vrf_name_source} to {dst_router.name}({vrf_name_dst}, {ipv6_address}) should be ok"
        else:
            logger.info(
                f"Check Ping IPv6 from {pingrouter.name}({vrf_name_source}) to {dst_router.name}({vrf_name_dst}, {ipv6_address}) OK"
            )


def evpn_print_nexthop_rmac(tgen, router):
    output = router.vtysh_cmd("show evpn next-hops vni all", isjson=False)
    logger.info("==== result from {} show evpn next-hops vni all".format(router.name))
    logger.info(output)
    output = router.vtysh_cmd("show evpn rmac vni all", isjson=False)
    logger.info("==== result from {}: show evpn rmac vni all".format(router.name))
    logger.info(output)


def evpn_check_nexthop(
    router, vni, ipv4, ipv6, prefix_ipv4, prefix_ipv6, expected_paths=1
):
    # Check IPv4
    expected = {
        "ip": ipv4,
        "refCount": 1,
        "prefixList": [{"prefix": prefix_ipv4, "pathCount": expected_paths}],
    }
    test_func = partial(
        topotest.router_json_cmp,
        router,
        f"show evpn next-hops vni {vni} ip {ipv4} json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "evpn ipv4 next-hops check failed"

    # Check IPv6
    expected = {
        "ip": ipv6,
        "refCount": 1,
        "prefixList": [{"prefix": prefix_ipv6, "pathCount": expected_paths}],
    }
    test_func = partial(
        topotest.router_json_cmp,
        router,
        f"show evpn next-hops vni {vni} ip {ipv6} json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "evpn ipv6 next-hops check failed"


def evpn_check_contexts(router, vni, ipv4=None, ipv6=None):
    """
    Check EVPN nexthops and RMAC number  are correctly configured
    """
    if ipv4 and ipv6:
        expected = {
            vni: {
                "numNextHops": 2,
                ipv4: {
                    "nexthopIp": ipv4,
                },
                ipv6: {
                    "nexthopIp": ipv6,
                },
            }
        }
    elif ipv4:
        expected = {
            vni: {
                "numNextHops": 1,
                ipv4: {
                    "nexthopIp": ipv4,
                },
            }
        }
    elif ipv6:
        expected = {
            vni: {
                "numNextHops": 1,
                ipv6: {
                    "nexthopIp": ipv6,
                },
            }
        }
    else:
        return

    result = topotest.router_json_cmp(
        router, "show evpn next-hops vni all json", expected
    )
    assert result is None, "evpn next-hops check failed"

    expected = {vni: {"numRmacs": 1}}
    result = topotest.router_json_cmp(router, "show evpn rmac vni all json", expected)
    assert result is None, f"evpn rmac number check failed"


def evpn_check_routes(tgen, router, family, vrf, routes, expected=True):
    rib_routes = {
        "r1": {
            "static_routes": [
                {
                    "vrf": vrf,
                    "network": routes,
                }
            ]
        }
    }
    result = verify_bgp_rib(tgen, family, router, rib_routes, expected=expected)

    if expected:
        assert result is True, "expect routes {} present".format(routes)
    else:
        assert result is not True, "expect routes {} not present".format(routes)


def evpn_check_rmac_present(router, vni, numRmacs=1, all=False):
    """
    Check that the RMAC is present on R2
    """
    output = router.vtysh_cmd(f"show evpn rmac vni {vni}", isjson=False)
    logger.info(f"==== result from show evpn rmac vni {vni}")
    logger.info(output)

    if all:
        param = "all"
        expected = {vni: {"numRmacs": numRmacs}}
    else:
        param = vni
        expected = {"numRmacs": numRmacs}

    test_func = partial(
        topotest.router_json_cmp,
        router,
        f"show evpn rmac vni {param} json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "evpn rmac is missing on router"
