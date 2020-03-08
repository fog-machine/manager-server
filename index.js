const logger = require('./src/logger');
logger.init();
const winston = require('winston');
const Joi = require('@hapi/joi');
const fs = require('fs');
const path = require('path');

const config = JSON.parse(fs.readFileSync(process.argv[process.argv.length-1], 'utf8'));

const schema = Joi.object().keys({
  secret: Joi.string().required(),
  port: Joi.number().port().required(),
  dbPath: Joi.string().default(path.join(process.cwd(), 'rpn.db')),
  email: Joi.object().keys({
    port: Joi.number().port().default(1025),
    host: Joi.string().ip().default('127.0.0.1'),
    user: Joi.string(),
    password: Joi.string(),
    passwordResetUrl: Joi.string(),
  }),
  dynu: Joi.object().keys({
    clientId: Joi.string().required(),
    secret: Joi.string().required(),
    apiKey: Joi.string().required(),
    password: Joi.string().required()
  })
});

const { error, value } = schema.validate(config, {allowUnknown: true});
if (error) {
  console.log(error);
  process.exit(1);
}

// INIT
require('./src/email').setup(value);
require('./src/database').setup(value);
require('./src/server').setup(value);
