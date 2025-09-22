/* this SQL should be run once at install time */
CREATE DATABASE IF NOT EXISTS dm;
use dm;

CREATE USER IF NOT EXISTS 'knot'@'localhost' IDENTIFIED BY 'Kn0tpassword!';

DROP TABLE IF EXISTS parent; /* static table created at system configuration time                                        */
CREATE TABLE parent (parent_id INT AUTO_INCREMENT,
       parent_name VARCHAR(80),     /*  the root of the name structure that is being delegated */
       dm1 INT DEFAULT 0,    /* primary DM - responsible for scheduled tasks related to the lifecycle delegation process */
       dm2 INT DEFAULT 0,    /* secondary DM - back up for scheduled tasks related to the lifecycle delegation process   */
                             /* primary and secondary DM can run odd and even time slots for simple failover             */
       ns1 INT DEFAULT 0,    /* primary NS - adds DS RR and TXT RR for ACME and DNSSEC to parent zone                    */
       ns2 INT DEFAULT 0,    /* when using catalogue zones, just used for NOTIFY in primary NS                           */ 
       ns3 INT DEFAULT 0,    /* when using catalogue zones, just used for NOTIFY in primary NS                           */ 
       PRIMARY KEY (parent_id) );

DROP TABLE IF EXISTS infra;
CREATE TABLE infra (infra_id INT AUTO_INCREMENT,
       name VARCHAR(80),     /* fqdn - used to key to parent for any name-> address translation in config */
       hostname VARCHAR(80), /* short name - used to pin functions to hosts                               */
       ipv4 VARCHAR(15) DEFAULT NULL,
       ipv6 VARCHAR(39) DEFAULT NULL,
       /* timing of lifecycle, so other programs can pick this up   */
       created    BIGINT UNSIGNED DEFAULT 0, /* initial name creation */
       assigned   BIGINT UNSIGNED DEFAULT 0, /* HNA assigned the name */ 
       delegated  BIGINT UNSIGNED DEFAULT 0, /* added NS glue */ 
       deleted    BIGINT UNSIGNED DEFAULT 0, /* infra no longer used: to be deleted */
       last_login BIGINT UNSIGNED DEFAULT 0, /* last connection authenticated via a cert */
       infra_status ENUM ('creating','created','deleting'), /* current status for state machine */
       infra_status_time   BIGINT SIGNED DEFAULT 0, /* time of last status change */
       node_type ENUM ('hna','dm','ns'), 
       PRIMARY KEY (infra_id) );

DROP TABLE IF EXISTS zone;
CREATE TABLE zone (zone_id INT AUTO_INCREMENT,
       zone_name VARCHAR(80),  /* the FQDN of the zone in ascii */
       cn VARCHAR(80),    /* the CN of the associated cert in ascii */
       parent_name VARCHAR(80),/* name of the parent zone in ascii */
                               /* not normalised to simplify queries */
       /* timing of lifecycle, so other programs can pick this up   */
       -- created    BIGINT UNSIGNED DEFAULT 0, /* initial name creation */
       -- offered    BIGINT UNSIGNED DEFAULT 0, /* initial name creation */
       -- assigned   BIGINT UNSIGNED DEFAULT 0, /* HNA assigned the name */ 
       -- delegating BIGINT UNSIGNED DEFAULT 0, /* sent AXFR  add NS glue*/ 
       -- delegated  BIGINT UNSIGNED DEFAULT 0, /* added DS glue */ 
       -- deleting   BIGINT UNSIGNED DEFAULT 0, /* zone no longer used: to be deleted */
       -- deleted   BIGINT UNSIGNED DEFAULT 0, /* infra no longer used: to be deleted */
       hna INT DEFAULT 0, /* the hna asscoiated with this zone  keyed in the infra table*/
       zone_status ENUM ('creating','created','offered','assigning','assigned','delegating','delegated','deleting'), /* current status for state machine */
       zone_status_time   BIGINT SIGNED DEFAULT 0, /* time of last status change */
       UNIQUE(zone_name),                        /* enforce zone names as unique */
       PRIMARY KEY (zone_id));

DROP TABLE IF EXISTS rr;
CREATE TABLE rr (rr_id INT AUTO_INCREMENT,
       owner VARCHAR(80),
       /* ns rr are used to add primary to DNS delegation, txt rr are added to primary zone for ACME, ds rr are added to primary zone for checking DNSSEC signing */
       type ENUM ('ns','ds','txt'),  
       rdata VARCHAR(80),
       /* timing of lifecycle, so other programs can pick this up   */
       rr_status ENUM ('creating','created','deleting'), /* current status for state machine */
       -- deleted is equivalent to not exist so no explicit state defined
       rr_status_time   BIGINT SIGNED DEFAULT 0, /* time of last status change */
       PRIMARY KEY (rr_id) );


GRANT USAGE ON *.* TO 'knot'@'localhost';
GRANT INSERT, SELECT, UPDATE, DELETE ON `dm`.* TO `knot`@`localhost` WITH GRANT OPTION;

-- our basic infra set at install time
INSERT INTO infra (`name`,`hostname`,`ipv4`,`ipv6`,`node_type`,`infra_status`) VALUES ('ns1.homenetdns.com','dm1','85.215.139.146','2a01:239:24f:f800::1','ns','created');
INSERT INTO infra (`name`,`hostname`,`ipv4`,`ipv6`,`node_type`,`infra_status`) VALUES ('ns2.homenetdns.com','dm2','212.132.88.195','2a01:239:3c7:c100::1','ns','created');
INSERT INTO infra (`name`,`hostname`,`ipv4`,`ipv6`,`node_type`,`infra_status`) VALUES ('dm1.homenetdns.com','dm2','85.215.139.146','2a01:239:24f:f800::1','dm','created');
INSERT INTO infra (`name`,`hostname`,`ipv4`,`ipv6`,`node_type`,`infra_status`) VALUES ('dm2.homenetdns.com','dm1','212.132.88.195','2a01:239:3c7:c100::1','dm','created');
INSERT INTO infra (`name`,`hostname`,`ipv4`,`ipv6`,`node_type`,`infra_status`) VALUES ('ns3.homenetdns.com','dm2','212.132.88.195','2a01:239:3c7:c100::1','ns','created');

-- homenet dns is our only parent domain at this time
INSERT INTO parent (`parent_name`,`dm1`,`dm2`,`ns1`,`ns2`,`ns3`) VALUES ('homenetdns.com',3,4,1,2,5);
INSERT INTO parent (`parent_name`,`dm1`,`dm2`,`ns1`,`ns2`,`ns3`) VALUES ('homenetdns2.com',3,4,2,5,1);

/* zone state lifecycle DM perspective */
/*******************************************************************************
*                                                                              *
*  not exist ----> creating  zone names are in DB                              *
*    |                |                                                        *
*    |             created   zones are created asynch in a batch               *
*    |            /   |                                                        *
*    | batch   T1/    |      solicit PTR query received and PTR answer sent    *
*    |          /     v                                                        *
*  deleting <----- offered   one or more zones are sent to the HNA by DM(s)    *
*    ^         T2     |                                                        *
*    |                |      client requests cert from CA via ACME DNS         *
*    |                |                                                        *
*    |                |      client receives ACME DNS challenge from CA        *
*    |                |                                                        *
*    |                v      TXT update challenge received and answered        *
*    |                |                                                        *
*    |             assigning                                                   *
*    |                |      potentially batch                                 *
*    ^         T3     v                                                        *
*    | <----<----- assigned  Glue TXT RR inserted in zone for ACME (no DNSSEC) *
*    ^                |                                                        *
*    |   any          |      client & CA complete cert asynch via ACME DNS     *
*    |   NS RR        |                                                        *
*    |   left?        |      DS or NS update add received using cert           *
*    |  n    y        v                                                        *
*    |<---------> delegating NS + Glue DS AAAA noted for add or delete         *
*    ^    |           |                                                        *
*    |    ^ NS or     |      batch                                             *
*    |    | DS Update |                                                        *
*    |    |           v                                                        *
*    L--<----<--- delegated  fully delegated zone with AXFR & glue in place    *
*       T4                                                                     *
*                                                                              *
*                  any ->                                                      *
*                   ^    |   AXFR received and reply sent                      *
*                   |    |                                                     *
*                    <---                                                      *
*                                                                              *
*                                                                              *
*******************************************************************************/


