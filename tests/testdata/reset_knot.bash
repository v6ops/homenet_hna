#!/usr/bin/bash
knotc -f -t 30 -b zone-purge "linear.realm.piece.floor.example.com"
knotc -f -t 30 -b zone-purge "basket.delay.need.sweet.example.com"
knotc -f -t 30 -b zone-purge "jaguar.oak.guess.lord.example.com"
knotc -f -t 30 -b zone-purge "device.vertex.deck.glad.example.com"
knotc -f -t 30 -b zone-purge "fabric.shine.flip.any.example.com"

knotc -t 30 -b conf-begin
knotc -t 30 -b conf-unset 'zone[linear.realm.piece.floor.example.com]'
knotc -t 30 -b conf-unset 'zone[basket.delay.need.sweet.example.com]'
knotc -t 30 -b conf-unset 'zone[jaguar.oak.guess.lord.example.com]'
knotc -t 30 -b conf-unset 'zone[device.vertex.deck.glad.example.com]'
knotc -t 30 -b conf-unset 'zone[fabric.shine.flip.any.example.com]'
knotc -t 30 -b conf-commit

knotc -t 30 -b zone-freeze example.com
knotc -t 30 -b zone-begin example.com
knotc -t 30 -b zone-unset example.com linear.realm.piece.floor.example.com 3600 NS ns1.homenetinfra.com.
knotc -t 30 -b zone-unset example.com basket.delay.need.sweet.example.com 3600 NS ns1.homenetinfra.com.
knotc -t 30 -b zone-unset example.com jaguar.oak.guess.lord.example.com 3600 NS ns1.homenetinfra.com.
knotc -t 30 -b zone-unset example.com device.vertex.deck.glad.example.com 3600 NS ns1.homenetinfra.com.
knotc -t 30 -b zone-unset example.com fabric.shine.flip.any.example.com 3600 NS ns1.homenetinfra.com.
knotc -t 30 -b zone-commit example.com
knotc -t 30 -b zone-thaw example.com
knotc -t 30 -b zone-sign example.com

