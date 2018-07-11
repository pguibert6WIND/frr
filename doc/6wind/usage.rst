.. Copyright 2018 6WIND S.A.

=====
Usage
=====

Starting |CP-ROUTING|
=====================

``frr``
---------

**Description**

``frr`` is the startup script in charge of starting the underlying daemons of FRR.

- starts the relevant daemon with their default options

- stops the relevant daemon

By default, ``frr`` will start the following 7 routing protocol daemons: ``zebra``,
``ospf``, ``ospf6``, ``rip``, ``ripng``, ``bgp``, ``ldp``.

This script can be used, if you want to run FRR in standalone mode, that is to say,
without the cli/xms framework.
However, if you already have the cli/xms started, you should ensure that the cli/xms
configuration does not interfere with the routing protocol configuration: for instance,
the daemons should not have been launched by cli/xms.

**Synopsis**

.. code-block:: console

   /usr/bin/frr start|stop

**Parameters**

.. program:: /usr/bin/frr

.. option:: start

   Start the above mentioned daemons

.. option:: stop

   Stop the above mentioned daemons

   For more information about |frr| daemons startup, see the `online
   documentation`__.

__ https://frrouting.org/user-guide/

Configuration
=============

Prior to starting the daemons, you can provide a configuration file for each of the
associated daemons. The configuration file must be located under `/var/tmp/shells`
path. The startup procedure depicted above does not take into account vty integrated
configuration. That is to say that as many files as daemons will have to be populated.
The configuration files are the following ones:

- zebra.conf for ``zebra``

- ospfd.conf for ``ospf``

- ospf6d.conf for ``ospf6``

- ripd.conf for ``rip``

- ripng.conf for ``ripng``

- bgpd.conf for ``bgp``

- ldpd.conf for ``ldp``.

When the daemons are started, you can alter the running configuration interactively
by passing commands to the relevant daemon via CLI.
The CLI syntax and the configuration file syntax are quite similar.

Accessing the CLI for runtime configuration
-------------------------------------------

You can access each daemon's CLI for runtime configuration via ``vtysh`` program.
It allows configuring the started daemons: ``zebra``, ``ospf``, ``ospf6``, ``rip``,
``ripng``, ``bgp``, ``ldp``.

   .. code-block:: console

      $ vtysh

  .. seealso::

     For more information about the CLI modes, see the `online documentation`__.

__ https://frrouting.org/user-guide/Virtual-Terminal-Interfaces.html#Virtual-Terminal-Interface

