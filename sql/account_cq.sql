/*
 Navicat Premium Dump SQL

 Source Server         : MySql
 Source Server Type    : MySQL
 Source Server Version : 50724 (5.7.24)
 Source Host           : localhost:3306
 Source Schema         : account_cq

 Target Server Type    : MySQL
 Target Server Version : 50724 (5.7.24)
 File Encoding         : 65001

 Date: 25/12/2025 11:42:47
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for city_location
-- ----------------------------
DROP TABLE IF EXISTS `city_location`;
CREATE TABLE `city_location`  (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ip_from` bigint(20) NULL DEFAULT NULL,
  `ip_to` bigint(20) NULL DEFAULT NULL,
  `country_code` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `country_name` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `state` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `city` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `latitude` double(255, 9) NULL DEFAULT NULL,
  `longitude` double(255, 9) NULL DEFAULT NULL,
  `zip_code` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 1 CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of city_location
-- ----------------------------

-- ----------------------------
-- Table structure for conquer_account
-- ----------------------------
DROP TABLE IF EXISTS `conquer_account`;
CREATE TABLE `conquer_account`  (
  `Id` int(11) NOT NULL AUTO_INCREMENT,
  `UserName` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `Password` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `Salt` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `AuthorityId` int(11) NULL DEFAULT 1,
  `Flag` int(11) NULL DEFAULT 0,
  `IpAddress` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `MacAddress` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `ParentId` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `Created` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `Modified` datetime NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  `Deleted` datetime NULL DEFAULT NULL,
  PRIMARY KEY (`Id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 1000011 CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of conquer_account
-- ----------------------------
INSERT INTO `conquer_account` VALUES (1000000, '1', 'fdd4ba19984f9b32ed98c86653f595e0475209802c33063f74c5233d8af9e9a1', 'KLnSdzaibuFSGEFpAI2BjsIIA0S6WjAAF5I9', 2, 0, '127.0.0.1', '', '00000000-0000-0000-0000-000000000000', '2025-10-17 23:33:09', '2025-12-21 07:30:12', NULL);
INSERT INTO `conquer_account` VALUES (1000006, '2', 'fdd4ba19984f9b32ed98c86653f595e0475209802c33063f74c5233d8af9e9a1', 'KLnSdzaibuFSGEFpAI2BjsIIA0S6WjAAF5I9', 1, 0, '127.0.0.1', '', '00000000-0000-0000-0000-000000000000', '2025-11-01 19:00:11', '2025-11-11 18:48:52', NULL);
INSERT INTO `conquer_account` VALUES (1000007, '3', 'fdd4ba19984f9b32ed98c86653f595e0475209802c33063f74c5233d8af9e9a1', 'KLnSdzaibuFSGEFpAI2BjsIIA0S6WjAAF5I9', 1, 0, '127.0.0.1', '', '00000000-0000-0000-0000-000000000000', '2025-11-11 17:03:44', '2025-12-11 10:28:51', NULL);
INSERT INTO `conquer_account` VALUES (1000008, '4', 'fdd4ba19984f9b32ed98c86653f595e0475209802c33063f74c5233d8af9e9a1', 'KLnSdzaibuFSGEFpAI2BjsIIA0S6WjAAF5I9', 1, 0, '127.0.0.1', '', '00000000-0000-0000-0000-000000000000', '2025-11-11 23:38:36', '2025-12-11 10:28:52', NULL);
INSERT INTO `conquer_account` VALUES (1000009, '5', 'fdd4ba19984f9b32ed98c86653f595e0475209802c33063f74c5233d8af9e9a1', 'KLnSdzaibuFSGEFpAI2BjsIIA0S6WjAAF5I9', 1, 0, NULL, NULL, '00000000-0000-0000-0000-000000000000', '2025-12-11 10:28:38', '2025-12-11 10:29:00', NULL);
INSERT INTO `conquer_account` VALUES (1000010, '6', 'fdd4ba19984f9b32ed98c86653f595e0475209802c33063f74c5233d8af9e9a1', 'KLnSdzaibuFSGEFpAI2BjsIIA0S6WjAAF5I9', 1, 0, NULL, NULL, '00000000-0000-0000-0000-000000000000', '2025-12-22 12:20:10', '2025-12-22 12:23:56', NULL);

-- ----------------------------
-- Table structure for conquer_account_authority
-- ----------------------------
DROP TABLE IF EXISTS `conquer_account_authority`;
CREATE TABLE `conquer_account_authority`  (
  `Id` int(11) NOT NULL,
  `Name` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `NormalizedName` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  PRIMARY KEY (`Id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of conquer_account_authority
-- ----------------------------
INSERT INTO `conquer_account_authority` VALUES (1, 'Player', 'Player');
INSERT INTO `conquer_account_authority` VALUES (2, 'Player', 'Player');

-- ----------------------------
-- Table structure for conquer_account_login_record
-- ----------------------------
DROP TABLE IF EXISTS `conquer_account_login_record`;
CREATE TABLE `conquer_account_login_record`  (
  `Id` int(11) NOT NULL AUTO_INCREMENT,
  `AccountId` int(11) NULL DEFAULT NULL,
  `IpAddress` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `LocationId` int(11) NULL DEFAULT NULL,
  `LoginTime` datetime NULL DEFAULT NULL,
  `Success` tinyint(1) NULL DEFAULT NULL,
  PRIMARY KEY (`Id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 1 CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of conquer_account_login_record
-- ----------------------------

-- ----------------------------
-- Table structure for conquer_account_vip
-- ----------------------------
DROP TABLE IF EXISTS `conquer_account_vip`;
CREATE TABLE `conquer_account_vip`  (
  `Id` int(11) NOT NULL,
  `ConquerAccountId` int(11) NULL DEFAULT NULL,
  `VipLevel` tinyint(4) NULL DEFAULT NULL,
  `DurationMinutes` int(11) NULL DEFAULT NULL,
  `StartDate` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `EndDate` datetime NOT NULL,
  `CreationDate` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`Id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of conquer_account_vip
-- ----------------------------

-- ----------------------------
-- Table structure for realm
-- ----------------------------
DROP TABLE IF EXISTS `realm`;
CREATE TABLE `realm`  (
  `RealmID` varchar(50) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
  `RealmIdx` int(11) NOT NULL,
  `Name` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `AuthorityID` int(11) NULL DEFAULT 0,
  `GameIPAddress` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `RpcIPAddress` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `GamePort` int(11) NULL DEFAULT 0,
  `RpcPort` int(11) NULL DEFAULT 0,
  `Status` tinyint(4) NULL DEFAULT NULL,
  `Username` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `Password` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `LastPing` datetime NULL DEFAULT NULL,
  `DatabaseHost` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `DatabaseUser` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `DatabasePass` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `DatabaseSchema` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `DatabasePort` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `Active` bit(1) NULL DEFAULT b'1',
  `ProductionRealm` bit(1) NULL DEFAULT b'1',
  `Attribute` int(11) NULL DEFAULT NULL,
  `MasterRealmID` int(11) NULL DEFAULT NULL,
  `CrossPort` int(11) NULL DEFAULT NULL,
  PRIMARY KEY (`RealmID`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of realm
-- ----------------------------
INSERT INTO `realm` VALUES ('94390aa0-c75d-11ed-9586-0050560401e2', 1, 'Virgo', 6, '192.168.1.4', '127.0.0.1', 5816, 9921, 1, '2vOQ/9KufSH7WkyTDiH0F0YB887vU+NuDyp97CKAW44=', 'KSNMdd6bh56v0M7iY0OZIAiL1fAPvdrpp+rzDwlP3cg=', '2024-04-03 01:37:07', '', '', '', '', '', b'0', b'1', 1, NULL, 9857);

-- ----------------------------
-- Table structure for realm_user
-- ----------------------------
DROP TABLE IF EXISTS `realm_user`;
CREATE TABLE `realm_user`  (
  `PlayerId` int(11) NOT NULL AUTO_INCREMENT,
  `RealmId` int(11) NULL DEFAULT NULL,
  `AccountId` int(11) NULL DEFAULT NULL,
  `CreationDate` datetime NULL DEFAULT NULL,
  PRIMARY KEY (`PlayerId`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 35 CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of realm_user
-- ----------------------------
INSERT INTO `realm_user` VALUES (8, 1, 8, '2024-07-19 01:32:43');
INSERT INTO `realm_user` VALUES (9, 1, 9, '2024-07-19 01:58:06');
INSERT INTO `realm_user` VALUES (10, 1, 9, '2024-07-19 01:58:33');
INSERT INTO `realm_user` VALUES (11, 1, 9, '2024-07-19 02:01:17');
INSERT INTO `realm_user` VALUES (12, 1, 9, '2024-07-19 02:05:05');
INSERT INTO `realm_user` VALUES (13, 1, 9, '2024-07-19 02:09:44');
INSERT INTO `realm_user` VALUES (14, 1, 9, '2024-07-19 10:20:41');
INSERT INTO `realm_user` VALUES (15, 1, 10, '2024-07-19 13:24:16');
INSERT INTO `realm_user` VALUES (16, 1, 1000001, '2024-07-19 13:42:01');
INSERT INTO `realm_user` VALUES (17, 1, 1000002, '2024-07-19 14:08:07');
INSERT INTO `realm_user` VALUES (18, 1, 1000002, '2024-07-19 14:14:01');
INSERT INTO `realm_user` VALUES (19, 1, 1000003, '2025-10-18 00:03:25');
INSERT INTO `realm_user` VALUES (20, 1, 1000003, '2025-10-18 00:06:03');
INSERT INTO `realm_user` VALUES (21, 1, 1000001, '2025-10-30 03:30:12');
INSERT INTO `realm_user` VALUES (22, 1, 1000001, '2025-11-01 18:43:25');
INSERT INTO `realm_user` VALUES (23, 1, 1000004, '2025-11-01 18:44:49');
INSERT INTO `realm_user` VALUES (24, 1, 1000005, '2025-11-01 18:56:42');
INSERT INTO `realm_user` VALUES (25, 1, 1000006, '2025-11-01 19:01:04');
INSERT INTO `realm_user` VALUES (26, 1, 1000007, '2025-11-11 17:08:23');
INSERT INTO `realm_user` VALUES (27, 1, 1000007, '2025-11-11 17:12:21');
INSERT INTO `realm_user` VALUES (28, 1, 15, '2025-11-11 17:21:04');
INSERT INTO `realm_user` VALUES (29, 1, 1000007, '2025-11-11 17:26:09');
INSERT INTO `realm_user` VALUES (30, 1, 1000008, '2025-11-11 23:39:25');
INSERT INTO `realm_user` VALUES (31, 1, 1000008, '2025-11-24 05:02:37');
INSERT INTO `realm_user` VALUES (32, 1, 1000009, '2025-12-11 10:37:29');
INSERT INTO `realm_user` VALUES (33, 1, 1000010, '2025-12-22 12:24:40');
INSERT INTO `realm_user` VALUES (34, 1, 1000000, '2025-12-25 08:44:45');

SET FOREIGN_KEY_CHECKS = 1;
