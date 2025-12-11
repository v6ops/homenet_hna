#!/usr/bin/bash
knotc --force zone-purge 'linear.realm.piece.floor.example.com.'
knotc --force zone-purge 'basket.delay.need.sweet.example.com.'
knotc --force zone-purge 'jaguar.oak.guess.lord.example.com.'
knotc --force zone-purge 'device.vertex.deck.glad.example.com.'
knotc --force zone-purge 'fabric.shine.flip.any.example.com.'
knotc --force zone-purge 'axis.palace.cookie.labor.example.com.'
knotc --force zone-purge 'cyan.chorus.oasis.shower.example.com.'
knotc --force zone-purge 'chain.museum.letter.gentle.example.com.'
knotc --force zone-purge 'color.sphere.neon.sweet.example.com.'
knotc --force zone-purge 'poker.duty.yellow.demo.example.com.'
knotc --force zone-purge 'garage.rural.recipe.gnome.example.com.'
knotc --force zone-purge 'makeup.new.choice.cotton.example.com.'
knotc --force zone-purge 'secret.wolf.happy.tulip.example.com.'
knotc conf-begin
knotc conf-unset zone['linear.realm.piece.floor.example.com.']
knotc conf-unset zone['basket.delay.need.sweet.example.com.']
knotc conf-unset zone['jaguar.oak.guess.lord.example.com.']
knotc conf-unset zone['device.vertex.deck.glad.example.com.']
knotc conf-unset zone['fabric.shine.flip.any.example.com.']
knotc conf-unset zone['axis.palace.cookie.labor.example.com.']
knotc conf-unset zone['cyan.chorus.oasis.shower.example.com.']
knotc conf-unset zone['chain.museum.letter.gentle.example.com.']
knotc conf-unset zone['color.sphere.neon.sweet.example.com.']
knotc conf-unset zone['poker.duty.yellow.demo.example.com.']
knotc conf-unset zone['garage.rural.recipe.gnome.example.com.']
knotc conf-unset zone['makeup.new.choice.cotton.example.com.']
knotc conf-unset zone['secret.wolf.happy.tulip.example.com.']
knotc conf-unset 'zone[example.com]'
knotc conf-set 'zone[example.com]'
knotc conf-set 'zone[example.com].file' '/home/knot/zones/example.com'
knotc conf-set zone[example.com].notify ns2.homenetinfra.com.
knotc conf-set zone[example.com].acl acl_homenetinfra.com
knotc conf-set zone[example.com].dnssec-signing on
knotc conf-commit
sleep 1
knotc zone-begin example.com
knotc zone-set example.com  @ 3600 SOA  ns admin 1 86400 900 691200 3600
knotc zone-set example.com @ 600 NS ns1.homenetinfra.com.
knotc zone-set example.com @ 600 NS ns2.homenetinfra.com.
knotc zone-commit example.com
knotc zone-sign example.com
knotc zone-flush

