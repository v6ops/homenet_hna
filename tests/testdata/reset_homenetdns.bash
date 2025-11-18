#!/usr/bin/bash
knotc --force zone-purge "calm.entry.figure.flex.homenetdns.com."
knotc --force zone-purge "herb.spin.forest.rope.homenetdns.com."
knotc --force zone-purge "hide.modern.polka.saga.homenetdns.com."
knotc --force zone-purge "java.alumni.height.binary.homenetdns.com."
knotc --force zone-purge "rope.saturn.bingo.harbor.homenetdns.com."
knotc --force zone-purge "sword.chrome.notice.intro.homenetdns.com."
knotc --force zone-purge "lounge.output.forest.makeup.homenetdns.com."
knotc conf-begin
knotc --force conf-unset zone["calm.entry.figure.flex.homenetdns.com."]
knotc --force conf-unset zone["herb.spin.forest.rope.homenetdns.com."]
knotc --force conf-unset zone["hide.modern.polka.saga.homenetdns.com."]
knotc --force conf-unset zone["java.alumni.height.binary.homenetdns.com."]
knotc --force conf-unset zone["rope.saturn.bingo.harbor.homenetdns.com."]
knotc --force conf-unset zone["sword.chrome.notice.intro.homenetdns.com."]
knotc --force conf-unset zone["lounge.output.forest.makeup.homenetdns.com."]
knotc conf-commit
