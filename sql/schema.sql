CREATE DATABASE js;
USE js;
CREATE TABLE js (
  id          INT UNSIGNED  NOT NULL PRIMARY KEY
, name        VARCHAR(32)   NOT NULL UNIQUE
, type        ENUM('js','jsudf','jsagg') NOT NULL
, js           TEXT          NOT NULL
, description TEXT          NOT NULL
);
