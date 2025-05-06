# SPDX-License-Identifier: ISC
#
# Copyright (c) 2025 by 6WIND
#
from functools import partial

from lib import topotest


def bgp_get_established_epoch(router, peer, vrf=None):
    """
    Get the established epoch for a peer
    """
    if vrf:
        output = router.vtysh_cmd(
            f"show bgp vrf {vrf} neighbor {peer} json", isjson=True
        )
    else:
        output = router.vtysh_cmd(f"show bgp neighbor {peer} json", isjson=True)

    assert peer in output, "peer not found"
    peer_info = output[peer]
    assert "bgpState" in peer_info, "peer state not found"
    assert peer_info["bgpState"] == "Established", "peer not in Established state"
    assert "bgpTimerUpEstablishedEpoch" in peer_info, "peer epoch not found"
    return peer_info["bgpTimerUpEstablishedEpoch"]


def bgp_check_established_epoch_differ(router, peer, last_established_epoch, vrf=None):
    """
    Check that the established epoch has changed
    """
    if vrf:
        output = router.vtysh_cmd(
            f"show bgp vrf {vrf} neighbor {peer} json", isjson=True
        )
    else:
        output = router.vtysh_cmd(f"show bgp neighbor {peer} json", isjson=True)
    assert peer in output, "peer not found"
    peer_info = output[peer]
    assert "bgpState" in peer_info, "peer state not found"

    if peer_info["bgpState"] != "Established":
        return "peer not in Established state"

    assert "bgpTimerUpEstablishedEpoch" in peer_info, "peer epoch not found"

    if peer_info["bgpTimerUpEstablishedEpoch"] == last_established_epoch:
        return "peer epoch not changed"
    return None


def bgp_check_epoch_after_clear(router, peer, last_established_epoch, vrf=None):
    """
    Checking that the established epoch has changed and the peer is in Established state again after clear
    Without this, the second session is cleared as well on slower systems (like CI)
    """
    test_func = partial(
        bgp_check_established_epoch_differ,
        router,
        peer,
        last_established_epoch,
        vrf=vrf,
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert (
        result is None
    ), "Established Epoch still the same after clear bgp for peer {}".format(peer)


def bgp_check_wait_for_multipath_convergence(
    router,
    prefix_ip,
    nexthop_ip,
    vrf=None,
    expected_paths=1,
):
    """
    Wait for multipath convergence on R2
    """
    expected = {prefix_ip: [{"nexthops": [{"ip": nexthop_ip}] * expected_paths}]}
    # Using router_json_cmp instead of verify_fib_routes, because we need to check for
    # two next-hops with the same IP address.
    if vrf:
        cmd = f"show ip route vrf {vrf} {prefix_ip} json"
    else:
        cmd = f"show ip route {prefix_ip} json"
    test_func = partial(
        topotest.router_json_cmp,
        router,
        cmd,
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert (
        result is None
    ), f"R2 does not have {expected_paths} next-hops for {prefix_ip} JSON output mismatches"
