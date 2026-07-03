# OVSDB Models

This directory contains local OVSDB model code copied from Kube-OVN's generated model packages:

- `ovnnb`: OVN Northbound DB models for VPCs, subnets, logical ports, routes, NAT, load balancers, DHCP, and related logical topology.
- `vswitch`: local Open vSwitch DB models for bare-metal bridge, port, interface, and `Open_vSwitch.external_ids` state.

Netloom keeps these models in-tree so OVN and local OVS state can use typed libovsdb cache/transaction code without relying on a `go.mod` replace to Kube-OVN's libovsdb fork.
