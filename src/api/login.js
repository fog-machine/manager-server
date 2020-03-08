const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const Buffer = require('buffer').Buffer;
const db = require('../database').getDb();
const email = require('../email');

// Crypto Config
const hashConfig = {
  hashBytes: 32,
  saltBytes: 16,
  iterations: 15000,
  encoding: 'base64'
};

exports.hashPassword = password => {
  return new Promise((resolve, reject) => {
    crypto.randomBytes(hashConfig.saltBytes, (err, salt) => {
      if (err) { return reject('Failed to hash password'); }
      crypto.pbkdf2(password, salt, hashConfig.iterations, hashConfig.hashBytes, 'sha512', (err, hash) => {
        if (err) { return reject('Failed to hash password'); }
        resolve({ salt, hashPassword: Buffer.from(hash).toString('hex') });
      });
    });
  });
}

exports.setup = (program, express) => {
  express.post('/change-password-request', (req, res) => {
    if (!req.body.email) { return res.status(500).json({ error: 'Invalid Parameters' }); }

    if (!program.email) { return res.status(500).json({ error: 'Email not configured for this server' }); }

    db.get(`SELECT * FROM users WHERE email = ?`, [req.body.email], (err, row) => {
      if (err || !row) { return res.status(500).json({ error: 'Invalid Parameters' }); }
      
      // token uses a unique key of 'reset' so it cannot be used for general auth
      const token = jwt.sign({ reset: row.user_id }, program.secret, { expiresIn: '1h' });
      console.log(token);

      // Email the user the token
      const url = program.email.passwordResetUrl.replace('__TOKEN__', token);
      const msg = `A password reset has been requested for your account.  You can reset your password here: ${url}`;
      const msgHtml = `<p>A password reset has been requested for your account.  You can reset your password here: <a href="${url}">${url}</a></p>`

      // Replace email after testing
      email.sendMessage(row.email, 'Password Reset', msg, msgHtml);
      res.json({});
    });
  });

  express.post('/change-password', (req, res) => {
    if (!req.body.token || !req.body.newPassword || !req.body.email) { return res.status(500).json({ error: 'Invalid Parameters' }); }

    // Check token
    jwt.verify(req.body.token, program.secret, async (err, decoded) => {
      if (err || !decoded.reset) { return res.status(500).json({ error: 'Token Error' }); }

      // Hash password and update user array
      const hashObj = await this.hashPassword(req.body.newPassword);
      db.run("UPDATE users SET password = ?, salt = ? WHERE user_id = ? AND email = ?;", [hashObj.hashPassword, hashObj.salt, decoded.reset, req.body.email], err => {
        if (err) {
          winston.error(err.message);
          return res.status(500).json({ error: 'Unknown Error' });
        }

        return res.json({});
      });
    });
  });

  // Failed Login Attempt
  express.get('/login-failed', (req, res) => {
    // Wait before sending the response
    setTimeout(() => { res.status(401).json({ error: 'Try Again' }); }, 800);
  });

  express.get('/access-denied', (req, res) => {
    res.status(403).json({ error: 'Access Denied' });
  });

  exports.authenticateUser = (lookup, field, password) => {
    return new Promise((resolve, reject) => {
      if (field !== 'email' && field !== 'user_id') { reject('Authentication Error'); }

      db.get(`SELECT * FROM users WHERE ${field} = ?`, [lookup], (err, row) => {
        if (err || !row) {
          return reject('Authentication Error');
        }
        crypto.pbkdf2(password, row.salt, hashConfig.iterations, hashConfig.hashBytes, 'sha512', (err, verifyHash) => {
          if (err) { reject('Authentication Error'); }
          if (Buffer.from(verifyHash).toString('hex') !== row.password) {
            return reject('Authentication Error');
          }

          resolve({ userId: row.user_id });
        });
      });
    });
  }

  // Authenticate User
  express.post('/login', async (req, res) => {
    if (!req.body.email || !req.body.password) {
      return res.redirect('/login-failed');
    }

    try {
      const userObj = await this.authenticateUser(req.body.email, 'email', req.body.password); 
      res.json({ token: jwt.sign(userObj, program.secret) });
    }
    catch (err) {
      return res.redirect('/login-failed'); 
    }
  });

  // Middleware that checks for token
  express.use((req, res, next) => {
    // check header or url parameters or post parameters for token
    const token = req.body.token || req.query.token || req.headers['x-access-token'];
    if (!token) { return res.redirect('/access-denied'); }

    // verifies secret and checks exp
    jwt.verify(token, program.secret, (err, decoded) => {
      // verify token contains a userId
      if (err || !decoded.userId) { return res.redirect('/access-denied'); }

      req.userToken = decoded;
      next();
    });
  });
}
