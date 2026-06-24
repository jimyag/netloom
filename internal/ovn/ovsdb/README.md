# OVN OVSDB Models

This directory contains local OVN Northbound model code copied from Kube-OVN's generated `pkg/ovsdb/ovnnb` package.

Netloom keeps these models in-tree so OVN live-state readers can use typed libovsdb cache access without relying on a `go.mod` replace to Kube-OVN's libovsdb fork.
