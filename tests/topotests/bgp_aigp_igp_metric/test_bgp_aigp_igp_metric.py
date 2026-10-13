#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026 by 6WIND
#

"""
r1 (AS 65001) ---------------- r2 (AS 65001) ---------------- r3 (AS 65002)
lo 10.0.0.1    OSPF cost 10     lo 10.0.0.2       eBGP, AIGP enabled

r2 and r3 belong to the same AIGP administrative domain. r2 originates the
AIGP attribute towards r3 in its outbound route-map (RFC 7311 section
3.4.1) with "set aigp-metric igp-metric", and r3 receives:

  prefix          origin on r2              AIGP
  172.16.1.1/32   iBGP from r1              10
  10.0.0.1/32     redistribute ospf         10
  172.16.2.2/32   network, r2 loopback      0

The route from r1 is iBGP-learned with an empty AS_PATH, and r2 sets
itself as the nexthop: the AIGP metric is the OSPF distance from r2 to
its nexthop 10.0.0.1. For the route redistributed from OSPF, the AIGP
metric is the OSPF metric of the route. For the network on the loopback,
the AIGP metric is the metric of the connected route.

r1 originates 172.16.1.3/32 with an AIGP metric of 5, which r2 does not
modify. r2 changes the nexthop towards r3, and increases the AIGP metric
by its OSPF distance to the previous nexthop 10.0.0.1 (RFC 7311 section
3.4.3): r3 receives an AIGP metric of 15.

"set aigp-metric igp-metric" is displayed in the running configuration
of r2.
"""

import os
import sys
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import retry
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd, pytest.mark.ospfd]


def setup_module(mod):
    topodef = {"s1": ("r1", "r2"), "s2": ("r2", "r3")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_aigp_igp_metric():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    @retry(retry_timeout=60)
    def check_route(router, prefix, expected):
        output = router.vtysh_cmd(
            "show bgp ipv4 unicast {} json".format(prefix), isjson=True
        )
        result = topotest.json_cmp(output, expected)
        if result is not None:
            return "{}, {}, {}".format(router.name, prefix, result)
        return True

    expected = {
        "paths": [
            {
                "valid": True,
                "aigpMetric": None,
                "nexthops": [{"ip": "10.0.0.1", "metric": 10}],
            }
        ]
    }
    result = check_route(r2, "172.16.1.1/32", expected)
    assert result is True, result

    for prefix, aigp in (
        ("172.16.1.1/32", 10),
        ("10.0.0.1/32", 10),
        ("172.16.2.2/32", 0),
        ("172.16.1.3/32", 15),
    ):
        expected = {"paths": [{"valid": True, "aigpMetric": aigp}]}
        result = check_route(r3, prefix, expected)
        assert result is True, result


def test_bgp_aigp_igp_metric_running_config():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    output = tgen.gears["r2"].vtysh_cmd("show running-config")
    assert (
        " set aigp-metric igp-metric\n" in output
    ), "r2, set aigp-metric igp-metric not displayed"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
