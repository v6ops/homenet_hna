#!/usr/bin/bash
knotc -f zone-purge "linear.realm.piece.floor.example.com"
knotc -f zone-purge "basket.delay.need.sweet.example.com"
knotc -f zone-purge "jaguar.oak.guess.lord.example.com"
knotc -f zone-purge "device.vertex.deck.glad.example.com"
knotc -f zone-purge "fabric.shine.flip.any.example.com"

knotc conf-begin
knotc conf-unset 'zone[linear.realm.piece.floor.example.com]'
knotc conf-unset 'zone[basket.delay.need.sweet.example.com]'
knotc conf-unset 'zone[jaguar.oak.guess.lord.example.com]'
knotc conf-unset 'zone[device.vertex.deck.glad.example.com]'
knotc conf-unset 'zone[fabric.shine.flip.any.example.com]'
knotc conf-commit

knotc zone-freeze example.com
knotc zone-begin example.com
knotc zone-unset example.com linear.realm.piece.floor.example.com 3600 NS ns1.homenetinfra.com.
knotc zone-unset example.com basket.delay.need.sweet.example.com 3600 NS ns1.homenetinfra.com.
knotc zone-unset example.com jaguar.oak.guess.lord.example.com 3600 NS ns1.homenetinfra.com.
knotc zone-unset example.com device.vertex.deck.glad.example.com 3600 NS ns1.homenetinfra.com.
knotc zone-unset example.com fabric.shine.flip.any.example.com 3600 NS ns1.homenetinfra.com.
knotc zone-commit example.com
knotc zone-thaw example.com
knotc zone-sign example.com

