const express = require('express');
const bodyParser = require('body-parser');
const winston = require('winston');
const server = require('http').createServer();
const rpn = express();
var cors = require('cors')

exports.setup = program => {
  // Magic Middleware Things
  rpn.use(bodyParser.json());
  rpn.use(bodyParser.urlencoded({ extended: true }));
  rpn.use(cors());

  require('./api/public').setup(program, rpn);
  require('./api/login').setup(program, rpn);
  require('./api/private').setup(program, rpn);

  require('./api/admin').setup(program, rpn);
  
  server.on('request', rpn);
  server.listen(program.port, () => {
    winston.info(`Server Booted on Port: ${program.port}`);
  });
}
