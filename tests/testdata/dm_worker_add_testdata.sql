use test;
INSERT INTO `infra` VALUES
-- (1,'ns1.homenetinfra.com','dm1','85.215.139.146','2a01:239:24f:f800::1','created',0,'ns'),
-- (2,'ns2.homenetinfra.com','dm2','212.132.88.195','2a01:239:3c7:c100::1','created',0,'ns'),
-- (3,'dm1.homenetinfra.com','dm2','85.215.139.146','2a01:239:24f:f800::1','created',0,'dm'),
-- (4,'dm2.homenetinfra.com','dm1','212.132.88.195','2a01:239:3c7:c100::1','created',0,'dm'),
(5,'hna-linear.realm.piece.floor.example.com',NULL,NULL,'2001:1::1','creating',1020,'hna'),
(6,'hna-basket.delay.need.sweet.example.com',NULL,NULL,'2001:2::1','creating',1020,'hna'),
(7,'hna-jaguar.oak.guess.lord.example.com',NULL,NULL,'2001:3::1','creating',1020,'hna'),
(8,'hna-device.vertex.deck.glad.example.com',NULL,NULL,'2001:4::1','creating',1020,'hna');
INSERT INTO `zone` VALUES
(1,'linear.realm.piece.floor.example.com',NULL,0,'example.com',5,'delegated',1380),
(2,'basket.delay.need.sweet.example.com',NULL,0,'example.com',6,'delegated',1260),
(3,'jaguar.oak.guess.lord.example.com',NULL,0,'example.com',7,'assigned',1140),
(4,'device.vertex.deck.glad.example.com',NULL,0,'example.com',8,'offered',1020),
(5,'fabric.shine.flip.any.example.com',NULL,0,'example.com',0,'created',1020);
