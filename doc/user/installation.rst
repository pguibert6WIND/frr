.. _installation:

************
Installation
************

.. index:: How to install FRR
.. index:: Installation
.. index:: Installing FRR
.. index:: Building the system
.. index:: Making FRR

Several distributions provide packages for FRR. Check your distribution's
repositories to find out if a suitable version is available.

FRR depends on various libraries depending on your operating system.

After installing these dependencies, change to the frr source directory and
issue the following commands:

::

  $ ./bootstrap.sh
  $ ./configure
  $ make
  $ make install


.. _configure-the-software:

Configure the Software
======================


.. _the-configure-script:

The Configure Script
--------------------

.. index:: Configuration options

.. index:: Options for configuring

.. index:: Build options

.. index:: Distribution configuration

.. index:: Options to `./configure`

FRR has an excellent configure script which automatically detects most
host configurations.  There are several additional configure options to
customize the build to include or exclude specific features and dependencies.

.. program:: configure

.. option:: --disable-zebra

   Do not build zebra daemon.

.. option:: --disable-ripd

   Do not build ripd.

.. option:: --disable-ripngd

   Do not build ripngd.

.. option:: --disable-ospfd

   Do not build ospfd.

.. option:: --disable-ospf6d

   Do not build ospf6d.

.. option:: --disable-bgpd

   Do not build bgpd.

.. option:: --disable-bgp-announce

   Make *bgpd* which does not make bgp announcements at all.  This
   feature is good for using *bgpd* as a BGP announcement listener.

.. option:: --enable-datacenter

   Enable system defaults to work as if in a Data Center. See defaults.h
   for what is changed by this configure option.

.. option:: --enable-snmp

   Enable SNMP support.  By default, SNMP support is disabled.

.. option:: --disable-ospfapi

   Disable support for OSPF-API, an API to interface directly with ospfd.
   OSPF-API is enabled if --enable-opaque-lsa is set.

.. option:: --disable-ospfclient

   Disable building of the example OSPF-API client.

.. option:: --disable-ospf-ri

   Disable support for OSPF Router Information (RFC4970 & RFC5088) this
   requires support for Opaque LSAs and Traffic Engineering.

.. option:: --disable-isisd

   Do not build isisd.

.. option:: --enable-isis-topology

   Enable IS-IS topology generator.

.. option:: --enable-isis-te

   Enable Traffic Engineering Extension for ISIS (RFC5305)

.. option:: --enable-multipath <ARG>

   Enable support for Equal Cost Multipath. `ARG` is the maximum number
   of ECMP paths to allow, set to 0 to allow unlimited number of paths.

.. option:: --enable-realms

   Enable the support of Linux Realms. Convert tag values from 1-255 into a
   realm value when inserting into the Linux kernel. Then routing policy can be
   assigned to the realm. See the tc man page.

.. option:: --disable-rtadv

   Disable support IPV6 router advertisement in zebra.

.. option:: --enable-gcc-rdynamic

   Pass the ``-rdynamic`` option to the linker driver.  This is in most cases
   necessary for getting usable backtraces.  This option defaults to on if the
   compiler is detected as gcc, but giving an explicit enable/disable is
   suggested.

.. option:: --disable-backtrace

   Controls backtrace support for the crash handlers. This is autodetected by
   default. Using the switch will enforce the requested behaviour, failing with
   an error if support is requested but not available.  On BSD systems, this
   needs libexecinfo, while on glibc support for this is part of libc itself.

.. option:: --enable-dev-build

   Turn on some options for compiling FRR within a development environment in
   mind.  Specifically turn on -g3 -O0 for compiling options and add inclusion
   of grammar sandbox.

.. option:: --enable-fuzzing

   Turn on some compile options to allow you to run fuzzing tools against the
   system. This flag is intended as a developer only tool and should not be
   used for normal operations.

.. option:: --disable-snmp

   Build without SNMP support.

.. option:: --disable-vtysh

   Build without VTYSH.

.. option:: --enable-fpm

   Build with FPM module support.

.. option:: --enable-numeric-version

   Alpine Linux does not allow non-numeric characters in the version string.
   With this option, we provide a way to strip out these characters for APK dev
   package builds.

You may specify any combination of the above options to the configure
script. By default, the executables are placed in :file:`/usr/local/sbin`
and the configuration files in :file:`/usr/local/etc`. The :file:`/usr/local/`
installation prefix and other directories may be changed using the following
options to the configuration script.

.. option:: --prefix <prefix>

   Install architecture-independent files in `prefix` [/usr/local].

.. option:: --sysconfdir <dir>

   Look for configuration files in `dir` [`prefix`/etc]. Note that sample
   configuration files will be installed here.

.. option:: --localstatedir <dir>

   Configure zebra to use `dir` for local state files, such as pid files and
   unix sockets.

.. _least-privilege-support:

Least-Privilege Support
-----------------------

.. index:: FRR Least-Privileges

.. index:: FRR Privileges

Additionally, you may configure zebra to drop its elevated privileges
shortly after startup and switch to another user. The configure script will
automatically try to configure this support. There are three configure
options to control the behaviour of FRR daemons.

.. option:: --enable-user <user>

   Switch to user `user shortly after startup, and run as user `user` in normal
   operation.

.. option:: --enable-group <user>

   Switch real and effective group to `group` shortly after startup.

.. option:: --enable-vty-group <group>

   Create Unix Vty sockets (for use with vtysh) with group ownership set to
   `group`. This allows one to create a separate group which is restricted to
   accessing only the vty sockets, hence allowing one to delegate this group to
   individual users, or to run vtysh setgid to this group.

The default user and group which will be configured is 'frr' if no user or
group is specified. Note that this user or group requires write access to the
local state directory (see :option:`--localstatedir`) and requires at least
read access, and write access if you wish to allow daemons to write out their
configuration, to the configuration directory (see :option:`--sysconfdir`).

On systems which have the 'libcap' capabilities manipulation library (currently
only Linux), FRR will retain only minimal capabilities required and will only
raise these capabilities for brief periods. On systems without libcap, FRR will
run as the user specified and only raise its UID to 0 for brief periods.

.. _linux-notes:

Linux Notes
-----------

.. index:: Configuring FRR

.. index:: Building on Linux boxes

.. index:: Linux configurations

There are several options available only to GNU/Linux systems [#]_.
If you use GNU/Linux, make sure that the current kernel configuration is what
you want.  FRR will run with any kernel configuration but some recommendations
do exist.


- :makevar:`CONFIG_NETLINK`
  Kernel/User Netlink socket. This is a brand new feature which enables an
  advanced interface between the Linux kernel and zebra (:ref:`kernel-interface`).
- :makevar:`CONFIG_RTNETLINK`
  Routing messages.
  This makes it possible to receive Netlink routing messages.  If you
  specify this option, *zebra* can detect routing information
  updates directly from the kernel (:ref:`kernel-interface`).
- :makevar:`CONFIG_IP_MULTICAST`
  IP: multicasting.
  This option should be specified when you use *ripd* (:ref:`rip`) or
  *ospfd* (:ref:`ospfv2`) because these protocols use multicast.

IPv6 support has been added in GNU/Linux kernel version 2.2.  If you
try to use the FRR IPv6 feature on a GNU/Linux kernel, please
make sure the following libraries have been installed.  Please note that
these libraries will not be needed when you uses GNU C library 2.1
or upper.

- inet6-apps

  The `inet6-apps` package includes basic IPv6 related libraries such
  as `inet_ntop` and `inet_pton`.  Some basic IPv6 programs such
  as *ping*, *ftp*, and *inetd* are also
  included. The `inet-apps` can be found at
  `ftp://ftp.inner.net/pub/ipv6/ <ftp://ftp.inner.net/pub/ipv6/>`_.

- net-tools

  The `net-tools` package provides an IPv6 enabled interface and routing
  utility.  It contains *ifconfig*, *route*, *netstat*, and other tools.
  `net-tools` may be found at http://www.tazenda.demon.co.uk/phil/net-tools/.


Linux sysctl settings and kernel modules
````````````````````````````````````````

There are several kernel parameters that impact overall operation of FRR when
using Linux as a router. Generally these parameters should be set in a
sysctl related configuration file, e.g., :file:`/etc/sysctl.conf` on
Ubuntu based systems and a new file
:file:`/etc/sysctl.d/90-routing-sysctl.conf` on Centos based systems.
Additional kernel modules are also needed to support MPLS forwarding.

:makevar:`IPv4 and IPv6 forwarding`
   The following are set to enable IP forwarding in the kernel:

   .. code-block:: shell

      net.ipv4.conf.all.forwarding=1
      net.ipv6.conf.all.forwarding=1

:makevar:`MPLS forwarding`
   Basic MPLS kernel support was introduced 4.1, additional capability
   was introduced in 4.3 and 4.5. For some general information on Linux
   MPLS support see
   https://www.netdevconf.org/1.1/proceedings/slides/prabhu-mpls-tutorial.pdf.
   The following modules should be loaded to support MPLS forwarding,
   and are generally added to a configuration file such as
   :file:`/etc/modules-load.d/modules.conf`:

   .. code-block:: shell

      # Load MPLS Kernel Modules
      mpls_router
      mpls_iptunnel

   The following is an example to enable MPLS forwarding in the kernel:

   .. code-block:: shell

      # Enable MPLS Label processing on all interfaces
      net.mpls.conf.eth0.input=1
      net.mpls.conf.eth1.input=1
      net.mpls.conf.eth2.input=1
      net.mpls.platform_labels=100000

   Make sure to add a line equal to :file:`net.mpls.conf.<if>.input` for
   each interface *'<if>'* used with MPLS and to set labels to an
   appropriate value.

:makevar:`VRF forwarding`
   General information on Linux VRF support can be found in
   https://www.kernel.org/doc/Documentation/networking/vrf.txt. Kernel
   support for VRFs was introduced in 4.3 and improved upon through
   4.13, which is the version most used in FRR testing (as of June
   2018).  Additional background on using Linux VRFs and kernel specific
   features can be found in
   http://schd.ws/hosted_files/ossna2017/fe/vrf-tutorial-oss.pdf.

   The following impacts how BGP TCP sockets are managed across VRFs:

   .. code-block:: shell

      net.ipv4.tcp_l3mdev_accept=0

   With this setting a BGP TCP socket is opened per VRF.  This setting
   ensures that other TCP services, such as SSH, provided for non-VRF
   purposes are blocked from VRF associated Linux interfaces.

   .. code-block:: shell

      net.ipv4.tcp_l3mdev_accept=1

   With this setting a single BGP TCP socket is shared across the
   system.  This setting exposes any TCP service running on the system,
   e.g., SSH, to all VRFs.  Generally this setting is not used in
   environments where VRFs are used to support multiple administrative
   groups.

   **Important note** as of June 2018, Kernel versions 4.14-4.18 have a
   known bug where VRF-specific TCP sockets are not properly handled. When
   running these kernel versions, if unable to establish any VRF BGP
   adjacencies, either downgrade to 4.13 or set
   'net.ipv4.tcp_l3mdev_accept=1'. The fix for this issue is planned to be
   included in future kernel versions so upgrading your kernel may also
   address this issue.


.. _build-the-software:

Build the Software
==================

After configuring the software, you will need to compile it for your system.
Simply issue the command *make* in the root of the source directory and the
software will be compiled. Cliff Notes versions of different compilation
examples can be found in the Developer's Manual Appendix.  If you have *any*
problems at this stage, please send a bug report :ref:`bug-reports`.

::

  $ ./bootstrap.sh
  $ ./configure <appropriate to your system>
  $ make


Install the Software
====================

Installing the software to your system consists of copying the compiled
programs and supporting files to a standard location. After the
installation process has completed, these files have been copied
from your work directory to :file:`/usr/local/bin`, and :file:`/usr/local/etc`.

To install the FRR suite, issue the following command at your shell
prompt:::

  $ make install

FRR daemons have their own terminal interface or VTY.  After
installation, you have to setup each beast's port number to connect to
them. Please add the following entries to :file:`/etc/services`.

::

  zebrasrv      2600/tcp		  # zebra service
  zebra         2601/tcp		  # zebra vty
  ripd          2602/tcp		  # RIPd vty
  ripngd        2603/tcp		  # RIPngd vty
  ospfd         2604/tcp		  # OSPFd vty
  bgpd          2605/tcp		  # BGPd vty
  ospf6d        2606/tcp		  # OSPF6d vty
  ospfapi       2607/tcp		  # ospfapi
  isisd         2608/tcp		  # ISISd vty
  nhrpd         2610/tcp		  # nhrpd vty
  pimd          2611/tcp		  # PIMd vty


If you use a FreeBSD newer than 2.2.8, the above entries are already
added to :file:`/etc/services` so there is no need to add it. If you
specify a port number when starting the daemon, these entries may not be
needed.

You may need to make changes to the config files in
|INSTALL_PREFIX_ETC|. :ref:`config-commands`.

.. [#] GNU/Linux has very flexible kernel configuration features.
