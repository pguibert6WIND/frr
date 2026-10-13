#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026 by 6WIND
#

"""
r2 (AS 65001) ---- r1 (AS 65001) ---- r3 (AS 65001)
             iBGP                iBGP

r1 receives 172.16.0.0/24 from r2 with an AIGP metric of 10 and a MED of
100, and from r3 without the AIGP attribute and with a MED of 0. r1 has
"bgp bestpath aigp".

Without "bgp bestpath aigp-strict", the AIGP attribute is not compared,
and r1 selects the path from r3 because of its MED. With
"bgp bestpath aigp-strict", r1 selects the path from r2, which has the
AIGP attribute (RFC 7311 section 4.1). "bgp bestpath aigp-strict" is
displayed in the running configuration of r1. With
"no bgp bestpath aigp-strict", r1 selects the path from r3 again, and
"bgp bestpath aigp" is still displayed in the running configuration.
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

pytestmark = [pytest.mark.bgpd]


def setup_module(mod):
    topodef = {"s1": ("r1", "r2"), "s2": ("r1", "r3")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_aigp_strict():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    @retry(retry_timeout=60)
    def check_bestpath(nexthop, reason):
        output = r1.vtysh_cmd("show bgp ipv4 unicast 172.16.0.0/24 json", isjson=True)
        expected = {
            "paths": [
                {
                    "valid": True,
                    "nexthops": [{"ip": nexthop}],
                    "bestpath": {"overall": True, "selectionReason": reason},
                }
            ]
        }
        result = topotest.json_cmp(output, expected)
        if result is not None:
            return "r1, {}".format(result)
        return True

    result = check_bestpath("192.168.13.3", "MED")
    assert result is True, result

    r1.vtysh_cmd(
        """
    configure terminal
        router bgp
            bgp bestpath aigp-strict
    """
    )
    result = check_bestpath("192.168.12.2", "AIGP")
    assert result is True, result

    output = r1.vtysh_cmd("show running-config")
    assert (
        " bgp bestpath aigp-strict\n" in output
    ), "r1, bgp bestpath aigp-strict not displayed"

    r1.vtysh_cmd(
        """
    configure terminal
        router bgp
            no bgp bestpath aigp-strict
    """
    )
    result = check_bestpath("192.168.13.3", "MED")
    assert result is True, result

    output = r1.vtysh_cmd("show running-config")
    assert (
        " bgp bestpath aigp-strict\n" not in output
    ), "r1, bgp bestpath aigp-strict displayed"
    assert " bgp bestpath aigp\n" in output, "r1, bgp bestpath aigp not displayed"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
