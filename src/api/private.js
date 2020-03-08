const winston = require('winston');
const Joi = require('@hapi/joi');
const Login = require('./login');
const db = require('../database').getDb();

exports.setup = (program, express) => {
  // Good for testing if tokens are valid
  express.get('/ping', (req, res) => {
    res.json({});
  });

  express.get('/account/info', (req, res) => {
    db.all(
      `SELECT * FROM users 
      LEFT JOIN user_domains on users.user_id = user_domains.user_key 
      LEFT JOIN domains on user_domains.domain_key = domains.domain_id
      LEFT JOIN servers on user_domains.server_key = servers.server_id
      WHERE users.user_id = ?`, 
    [req.userToken.userId], (err, rows) => {
      if (err || rows.length === 0) {
        return res.status(500).json({ error: 'DB Error' });
      }
      let email;
      let domains = [];
      rows.forEach(element => {
        email = element.email;

        if (element.full_domain) {
          domains.push({
            domain: element.domain,
            subdomain: element.subdomain,
            fullDomain: element.full_domain,
            active: element.is_active === 1 ? true : false,
            bindPort: element.frp_bind_port,
            rawPort: element.frp_vhost_port,
            tunnelPassword: element.frp_password,
            ip: element.ip
          });
        }
      });

      res.json({ email, domains });
    });
  });

  // express.get('/account/server-list', (req, res) => {
    // return res.status(500).json({ error: 'Not Done' });
  // });

  // express.get('/account/change-proxy-server', (req, res) => {
    // return res.status(500).json({ error: 'Not Done' });
  // });

  express.post('/account/change-password', async (req, res) => {
    const { error, value } = Joi.object().keys({
      oldPassword: Joi.string().required(),
      newPassword: Joi.string().required()
    }).validate(req.body);
    if (error) { return res.status(500).json({error: 'Invalid Input'}) }

    try { await Login.authenticateUser(req.userToken.userId, 'user_id', req.body.oldPassword); }
    catch (err) { return res.status(500).json({ error: 'Incorrect Password' }); }

    const hashObj = await Login.hashPassword(req.body.newPassword);
    db.run("UPDATE users SET password = ?, salt = ? WHERE user_id = ?;", [hashObj.hashPassword, hashObj.salt, req.userToken.userId], err => {
      if (err) {
        winston.error(err.message);
        return res.status(500).json({ error: 'DB Error' });
      }

      winston.info(`User '${req.userToken.userId}' updated password`);
      return res.json({});
    });
  });

  express.post('/account/change-email', async (req, res) => {
    const { error, value } = Joi.object().keys({
      newEmail: Joi.string().email().required(),
      password: Joi.string().required()
    }).validate(req.body);
    if (error) { return res.status(500).json({error: 'Invalid Input'}) }

    try { await Login.authenticateUser(req.userToken.userId, 'user_id', req.body.password); }
    catch (err) { return res.status(500).json({ error: 'Incorrect Password' }); }
    
    db.run("UPDATE users SET email = ? WHERE user_id = ?;", [req.body.newEmail, req.userToken.userId], err => {
      if (err) {
        winston.error(err.message);
        return res.status(500).json({ error: 'DB Error' });
      }

      winston.info(`User '${req.userToken.userId}' updated email`);
      return res.json({});
    });
  });

  express.post('/account/deactivate', (req, res) => {
    return res.status(500).json({ error: 'Not Done' });
  });
}