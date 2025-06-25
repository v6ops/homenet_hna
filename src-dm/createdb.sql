/* this SQL should be run once at install time */
CREATE DATABASE IF NOT EXISTS dm;
use dm;

CREATE USER IF NOT EXISTS 'knot'@'localhost' IDENTIFIED BY 'knotpassword';
DROP TABLE IF EXISTS infra;
CREATE TABLE infra (infra_id INT AUTO_INCREMENT,name VARCHAR(80),
       ipv4 VARCHAR(15) DEFAULT NULL, ipv6 VARCHAR(39) DEFAULT NULL,
       /* timing of lifecycle, so other programs can pick this up   */
       created   BIGINT UNSIGNED DEFAULT 0, /* initial name creation */
       assigned  BIGINT UNSIGNED DEFAULT 0, /* HNA assigned the name */ 
       delegated BIGINT UNSIGNED DEFAULT 0, /* added NS glue */ 
       deleted   BIGINT UNSIGNED DEFAULT 0, /* infra no longer used: to be deleted */
       function ENUM ('hna','dm','ns'), 
       PRIMARY KEY (infra_id) );

DROP TABLE IF EXISTS zone;
CREATE TABLE zone (zone_id INT AUTO_INCREMENT,
       name VARCHAR(80),  /* the FQDN of the zone in ascii */
       cn VARCHAR(80),    /* the CN of the associated cert in ascii */
       parent VARCHAR(80),/* name of the parent zone in ascii */
       /* timing of lifecycle, so other programs can pick this up   */
       created   BIGINT UNSIGNED DEFAULT 0, /* initial name creation */
       assigned  BIGINT UNSIGNED DEFAULT 0, /* HNA assigned the name */ 
       delegated BIGINT UNSIGNED DEFAULT 0, /* added NS glue */ 
       deleted   BIGINT UNSIGNED DEFAULT 0, /* zone no longer used: to be deleted */
       hna INT DEFAULT 0,
       dm INT DEFAULT 0,
       ns1 INT DEFAULT 0,
       ns2 INT DEFAULT 0,
       ns3 INT DEFAULT 0,
       UNIQUE(name),                        /* enforce zone names as unique */
       PRIMARY KEY (zone_id));
GRANT USAGE ON *.* TO 'knot'@'localhost';
GRANT INSERT, SELECT, UPDATE, DELETE ON `dm`.* TO `knot`@`localhost` WITH GRANT OPTION

