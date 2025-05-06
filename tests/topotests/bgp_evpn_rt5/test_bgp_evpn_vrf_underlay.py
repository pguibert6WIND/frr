#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_evpn_underlay_vrf.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2019 by 6WIND
#

import sys
import os

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

os.environ["VRF_UNDERLAY"] = "vrf-evpn"

with open(f"{CWD}/bgp_evpn.py") as f:
    code = f.read()
    exec(code)
