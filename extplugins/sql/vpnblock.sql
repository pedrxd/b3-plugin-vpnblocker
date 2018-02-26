CREATE TABLE IF NOT EXISTS `vpnblock` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `client_id` int(10) unsigned NOT NULL
);
CREATE TABLE IF NOT EXISTS `vpnblockwaiting` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `ip` varchar(16) NOT NULL
);
