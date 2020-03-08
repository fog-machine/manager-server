const Joi = require('@hapi/joi');
const winston = require('winston');
const sqlite3 = require('sqlite3').verbose();
const Login = require('./login');
const adminPassword = 'theraininspain'; // TODO: You know what's wrong with this

exports.setup = (program, express) => {
  function verifyAdmin(req) {
    // Check for password in the header/body
    const token = req.body['x-admin-pass'] || req.query['x-admin-pass'] || req.headers['x-admin-pass'];
    return ((!token || token !== adminPassword)) ? false : true;
  }

  express.post('/admin/add-user', async (req, res) => {
    if (verifyAdmin(req) === false) {
      return res.status(500).json({ error: 'validation error' })
    }

    const { error, value } = Joi.object().keys({
      email: Joi.string().required(),
      password: Joi.string().required(),
      'x-admin-pass': Joi.string().required()
    }).validate(req.body);

    if (error) { return res.status(500).json({error: 'Invalid Input'}) }

    const newDB = new sqlite3.Database(program.dbPath);
    // Add the user
    const hashObj = await Login.hashPassword(req.body.password);
    newDB.run("INSERT INTO users (email, password, salt, admin) VALUES (?, ?, ?, 1);", [req.body.email, hashObj.hashPassword, hashObj.salt], function(err) {
      if (err) {
        winston.error(err.message);
        return res.redirect('/admin/piss-off');
      }

      return res.json({});
    });
  });
}