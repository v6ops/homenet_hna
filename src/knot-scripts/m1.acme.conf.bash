#!/bin/bash
# set up a delegation in the base homenetinfra.com zone for acme
#
# this acme is used for sub-zone registration and points to the dm
# the dm synthesizes the dynamic dns updates and responses
#
# only needs run once at setup on the MASTER NS
# run after homenetinfra zone has been set up
#
knotc zone-begin homenetinfra.com
knotc zone-set homenetinfra.com "acme.homenetinfra.com." 3600 NS dm1.homenetinfra.com.
knotc zone-commit homenetinfra.com
