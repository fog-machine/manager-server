const Joi = require('@hapi/joi');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const winston = require('winston');
const nanoid = require('nanoid');

const db = require('../database').getDb();
const Login = require('./login');

exports.setup = (program, express) => {
  express.use((req, res, next) => {
    db.get(`SELECT * FROM users WHERE user_id = ? AND admin = 1`, [req.userToken.userId], (err, row) => {
      if(err || !row) {
        return res.status(403).json({ error: 'Access Denied' });
      }
      next();
    });
  });

  express.get('/admin/ping', (req, res) => {
    res.json({});
  });

  // get system status
  express.get('/admin/status/all', async (req, res) => {
    try {
      const serverRegionRows = await db.allAsync('SELECT * FROM server_regions');
      const domainRows = await db.allAsync('SELECT * FROM domains');;
      const accountTierRows = await db.allAsync('SELECT * FROM account_tiers');
      const domainsToTiersRows = await db.allAsync('SELECT * FROM domains_to_tiers');
      const serverRows = await db.allAsync('SELECT * FROM servers');
      const serversToTiersRows = await db.allAsync('SELECT * FROM servers_to_tiers');
      const serversToDomainsRows = await db.allAsync('SELECT * FROM domains_to_servers');


      const rT = { serverRegions: {}, tiers: {}, domains: {}, servers: {} };
      serverRegionRows.forEach((el, i) => { rT.serverRegions[i] = el; });
      domainRows.forEach((el, i) => {
        rT.domains[el.domain_id] = el;
        rT.domains[el.domain_id].tier_keys = [];
        rT.domains[el.domain_id].server_keys = [];
      });
      accountTierRows.forEach((el, i) => {
        rT.tiers[el.account_tier_id] = el;
        rT.tiers[el.account_tier_id].domain_keys = [];
        rT.tiers[el.account_tier_id].server_keys = [];
      });

      domainsToTiersRows.forEach((el, i) => {
        rT.tiers[el.tier_key].domain_keys.push(el.domain_key);
        rT.domains[el.domain_key].tier_keys.push(el.tier_key);
      });

      serverRows.forEach((el, i) => {
        rT.servers[el.server_id] = el;
        rT.servers[el.server_id].tier_keys = [];
        rT.servers[el.server_id].domain_keys = [];
      });

      serversToTiersRows.forEach((el, i) => {
        rT.tiers[el.tier_key].server_keys.push(el.server_key);
        rT.servers[el.server_key].tier_keys.push(el.tier_key);
      });

      serversToDomainsRows.forEach((el, i) => {
        rT.domains[el.domain_key].server_keys.push(el.server_key);
        rT.servers[el.server_key].domain_keys.push(el.domain_key);
      });

      res.json(rT);
    }catch (err) {
      console.log(err);
      return res.status(500).json({ error: 'DB error' });
    }
  });

  express.get('/admin/status/server-regions', (req, res) => {
    db.all('SELECT * FROM server_regions', (err, rows) => {
      if (err) { return res.status(500).json({ error: 'DB error' }); }
      res.json(rows);
    });
  });

  express.get('/admin/status/tiers', (req, res) => {
    db.all('SELECT * FROM account_tiers', (err, rows) => {
      if (err) { return res.status(500).json({ error: 'DB error' }); }
      res.json(rows);
    });
  });

  express.get('/admin/status/domains', (req, res) => {
    db.all('SELECT * FROM domains', (err, rows) => {
      if (err) { return res.status(500).json({ error: 'DB error' }); }
      res.json(rows);
    });
  });

  // Add Server Region
  express.post('/admin/server-regions/add', (req, res) => {
    // Verify Params
    const { error, value } = Joi.object().keys({
      regionCode: Joi.string().required(),
      regionName: Joi.string().required()
    }).validate(req.body);

    if (error) { return res.status(500).json({ error: 'Invalid Input' }) }

    db.run('INSERT INTO server_regions (region_code, region_name) VALUES (?, ?)', [req.body.regionCode, req.body.regionName], function(err) {
      if (err) { return res.status(500).json({ error: 'DB insert failed. Possibly due to duplicate names or codes' }); }
      res.json({ server_region_id: this.lastID });
    });
  });

  express.post('/admin/server-regions/delete', (req, res) => {
    // Verify Params
    const { error, value } = Joi.object().keys({
      regionCode: Joi.string().required()
    }).validate(req.body);

    if (error) { return res.status(500).json({ error: 'Invalid Input' }) }

    db.run('DELETE FROM server_regions WHERE region_code = ?', [req.body.regionCode], function(err) {
      if (err) { return res.status(500).json({ error: 'DB delete failed' }); }
      res.json({ });
    });
  });

  // Add Server Region
  express.post('/admin/tiers/add', (req, res) => {
    // Verify Params
    const { error, value } = Joi.object().keys({
      price: Joi.number().integer().greater(-1).required(),
      name: Joi.string().required(),
      isPublic: Joi.bool().required(),
      requiresInvite: Joi.bool().required()
    }).validate(req.body);

    if (error) { return res.status(500).json({ error: 'Invalid Input' }) }

    db.run('INSERT INTO account_tiers (price, name, is_public, requires_invite) VALUES (?, ?, ?, ?)', [req.body.price, req.body.name, (req.body.isPublic === true ? 1 : 0), (req.body.requiresInvite === true ? 1 : 0)], function(err) {
      console.log(err)
      if (err) { return res.status(500).json({ error: 'DB insert failed. Possibly due to duplicate names' }); }
      res.json({ account_tier_id: this.lastID });
    });
  });

  express.post('/admin/tiers/disable', (req, res) => {
    // TODO: Disables a tier so users can no longer sign up with it
  });

  express.post('/admin/tiers/delete', (req, res) => {
    // Verify Params
    const { error, value } = Joi.object().keys({
      tierId: Joi.string().required()
    }).validate(req.body);

    if (error) { return res.status(500).json({ error: 'Invalid Input' }) }

    db.run('DELETE FROM account_tiers WHERE account_tier_id = ?', [req.body.tierId], err => {
      if (err) { return res.status(500).json({ error: 'DB delete failed' }); }
      res.json({ });
    });
  });

  // Add Server Region
  express.post('/admin/domains/add', (req, res) => {
    // Verify Params
    const { error, value } = Joi.object().keys({
      domain: Joi.string().required(),
      restrictedSubdomains: Joi.array().items(Joi.string()).required(),
      restrictedSubdomainPrefix: Joi.string().allow("").optional()
    }).validate(req.body);

    if (error) { return res.status(500).json({ error: 'Invalid Input' }) }

    const resSubPrefix = req.body.restrictedSubdomainPrefix ? req.body.restrictedSubdomainPrefix : null;
    db.run('INSERT INTO domains (domain, restricted_subdomains, restricted_subdomain_prefix) VALUES (?, ?, ?)', [req.body.domain, JSON.stringify(req.body.restrictedSubdomains), resSubPrefix], function(err) {
      if (err) { return res.status(500).json({ error: 'DB insert failed. Possibly due to duplicate names' }); }
      res.json({ domain_id: this.lastID });
    });
  });

  express.post('/admin/domains/delete', (req, res) => {
    // Verify Params
    const { error, value } = Joi.object().keys({
      domainId: Joi.string().required()
    }).validate(req.body);

    if (error) { return res.status(500).json({ error: 'Invalid Input' }) }

    // TODO: Delete all domains-to-servers table entries

    db.run('DELETE FROM domains WHERE domain_id = ?', [req.body.domainId], err => {
      if (err) { return res.status(500).json({ error: 'DB delete failed' }); }
      
      
      res.json({ });
    });
  });

  express.post('/admin/domains-tiers/connect', (req, res) => {
    const { error, value } = Joi.object().keys({
      domainId: Joi.string().required(),
      tierId: Joi.string().required()
    }).validate(req.body);

    if (error) { return res.status(500).json({ error: 'Invalid Input' }) }

    db.run('INSERT INTO domains_to_tiers (domain_key, tier_key) VALUES (?, ?)', [req.body.domainId, req.body.tierId], (err) => {
      if (err) { return res.status(500).json({ error: 'DB insert failed. Possibly due to duplicate names' }); }
      res.json({ });
    });
  });

  express.post('/admin/domains-tiers/disconnect', (req, res) => {
    const { error, value } = Joi.object().keys({
      domainId: Joi.string().required(),
      tierId: Joi.string().required()
    }).validate(req.body);

    if (error) { return res.status(500).json({ error: 'Invalid Input' }) }

    db.run('DELETE FROM domains_to_tiers WHERE domain_key = ? AND tier_key = ?', [req.body.domainId, req.body.tierId], err => {
      if (err) { return res.status(500).json({ error: 'DB delete failed' }); }
      res.json({ });
    });
  });

  // Add Server
  express.post('/admin/servers/add', async (req, res) => {
    const { error, value } = Joi.object().keys({
      ip: Joi.string().ip().required(),
      regionKey: Joi.number().integer().required(),
      apiEndpoint: Joi.string().required(),
      apiKey: Joi.string().required(),
      serverName: Joi.string().required()
    }).validate(req.body);

    if (error) { return res.status(500).json({ error: 'Invalid Input' }); }

    // call server
    try {
      const serverJwt = jwt.sign({}, req.body.apiKey);
      // get domain list from server
      const serverData = await axios.get('https://' + req.body.apiEndpoint, { headers: { 'x-access-token': serverJwt } });
      const supportedDomains = await db.allAsync('SELECT * FROM domains');

      const addTheseDomainConnections = [];
      supportedDomains.forEach(el => {
        if (serverData.data.domains.indexOf(el.domain) > -1) {
          addTheseDomainConnections.push(el.domain_id);
        }
      });

      if (addTheseDomainConnections.length === 0) { return res.status(500).json({ error: 'Server Does Not Have Any Registered Domains' }); }
      const serverId = await db.runAsync('INSERT INTO servers (ip, server_name, api_endpoint, api_security_key, region_key) values (?, ?, ?, ?, ?)', [req.body.ip, req.body.serverName, req.body.apiEndpoint, req.body.apiKey, req.body.regionKey]);
      for (let i = 0; i < addTheseDomainConnections.length; i++) {
        await db.runAsync('INSERT INTO domains_to_servers (domain_key, server_key) values (?, ?)', [addTheseDomainConnections[i], serverId.lastID]);
      }

      res.json({ server_id: serverId.lastID });
    } catch (err) {
      winston.error('Failed to add server');
      console.log(err);
      res.status(500).json({ error: 'Failed to add server'})
    }
  });

  express.post('/admin/servers/delete', async (req, res) => {
    const { error, value } = Joi.object().keys({
      serverId: Joi.string().required()
    }).validate(req.body);

    if (error) { return res.status(500).json({ error: 'Invalid Input' }); }

    const tempDB = require('../database').getFreshSql(program.dbPath);
    try {
      await tempDB.runAsync('BEGIN');
      await tempDB.runAsync('DELETE FROM domains_to_servers WHERE server_key = ?', [req.body.serverId]);
      await tempDB.runAsync('DELETE FROM servers_to_tiers WHERE server_key = ?', [req.body.serverId]);
      await tempDB.runAsync('DELETE FROM servers WHERE server_id = ?', [req.body.serverId]);
      await tempDB.runAsync('COMMIT');
      res.json({});
    } catch (err) {
      await tempDB.runAsync('ROLLBACK');
      winston.error('Failed to delete server');
      console.log(err);
      res.status(500).json({ error: 'Failed to delete server. Are users still connected to that server?'});
    }
    tempDB.close();
  });

  express.post('/admin/servers/get-data', async (req, res) => {
    const { error, value } = Joi.object().keys({
      serverId: Joi.string().required()
    }).validate(req.body);

    if (error) { return res.status(500).json({ error: 'Invalid Input' }); }

    try {
      const serverRow = await db.getAsync('SELECT * FROM servers WHERE server_id = ?', [req.body.serverId]);
      if (!serverRow) { return res.status(500).json({ error: 'Server ID is not in DB' }); }
      const serverJwt = jwt.sign({}, serverRow.api_security_key);
      const serverData = await axios.get(`https://${serverRow.api_endpoint}/connections/info`, { headers: { 'x-access-token': serverJwt } });
      res.send(serverData.data);
    } catch(err) {
      winston.error('Failed to call server');
      console.log(err);
      res.status(500).json({ error: 'Failed to get server data'});
    }
  });

  express.post('/admin/servers-tiers/connect', (req, res) => {
    const { error, value } = Joi.object().keys({
      serverId: Joi.string().required(),
      tierId: Joi.string().required()
    }).validate(req.body);

    if (error) { return res.status(500).json({ error: 'Invalid Input' }) }

    db.run('INSERT INTO servers_to_tiers (tier_key, server_key) VALUES (?, ?)', [req.body.tierId, req.body.serverId], (err) => {
      if (err) { return res.status(500).json({ error: 'DB insert failed. Possibly due to duplicate names' }); }
      res.json({ });
    });
  });

  express.post('/admin/servers-tiers/disconnect', (req, res) => {
    const { error, value } = Joi.object().keys({
      serverId: Joi.string().required(),
      tierId: Joi.string().required()
    }).validate(req.body);

    if (error) { return res.status(500).json({ error: 'Invalid Input' }) }

    db.run('DELETE FROM servers_to_tiers WHERE server_key = ? AND tier_key = ?', [req.body.serverId, req.body.tierId], err => {
      if (err) { return res.status(500).json({ error: 'DB delete failed' }); }
      res.json({ });
    });
  });

  express.get('/admin/status/users', async (req, res) => {
    db.all(
      `SELECT * FROM users
      LEFT JOIN user_domains on users.user_id = user_domains.user_key
      LEFT JOIN domains on user_domains.domain_key = domains.domain_id`,
    (err, rows) => {
      if (err) { return res.status(500).json({ error: 'DB error' }); }
      const rT = {};
      rows.forEach(el => {
        if (!(el.user_id in rT) ) {
          rT[el.user_id] = { email: el.email, phone: el.phone, admin: el.admin, created: el.created, user_id: el.user_id };
          rT[el.user_id].domains = [];
        }

        if (el.user_domain_id) {
          rT[el.user_id].domains.push({
            user_domain_id: el.user_domain_id,
            domain: el.domain,
            subdomain: el.subdomain,
            full_domain: el.full_domain,
            is_active: el.is_active
          });
        }
      });
      res.json(rT);
    });
  });

  express.post('/admin/users/add', async (req, res) => {
    const { error, value } = Joi.object().keys({
      email: Joi.string().email().required(),
      password: Joi.string().required()
    }).validate(req.body);

    if (error) { return res.status(500).json({ error: 'Invalid Input' }); }

    try {
      const randomString = nanoid(28);
      const hashObj = await Login.hashPassword(req.body.password);
      await db.runAsync('INSERT INTO users (email, password, salt, default_frp_password) VALUES (?, ?, ?, ?);', [req.body.email, hashObj.hashPassword, hashObj.salt, randomString]);
      res.json({});
    } catch (err) {
      winston.error('Failed to add user');
      console.log(err);
      res.status(500).json({ error: 'Failed to add user. Maybe due to duplicate email'})
    }
  });

  express.post('/admin/users/delete', async (req, res) => {
    // Verify Params
    const { error, value } = Joi.object().keys({
      userId: Joi.string().required()
    }).validate(req.body);

    if (error) { return res.status(500).json({ error: 'Invalid Input' }) }

    db.run('DELETE FROM users WHERE user_id = ?', [req.body.userId], err => {
      if (err) { return res.status(500).json({ error: 'DB delete failed' }); }
      res.json({ });
    });
  });

  express.post('/admin/users/connections/add', async (req, res) => {
    const { error, value } = Joi.object().keys({
      email: Joi.string().email().required(),
      tierKey: Joi.number().integer().required(),
      tierPrice: Joi.number().integer().greater(-1).required(),

      domainKey: Joi.number().integer().required(),
      subdomain: Joi.string().pattern(/^([a-zA-Z0-9][a-zA-Z0-9-_]*[a-zA-Z0-9])+$/).required(),
      serverKey: Joi.string().required()
    }).validate(req.body);

    if (error) { return res.status(500).json({ error: 'Invalid Input' }); }

    const tempDB = require('../database').getFreshSql(program.dbPath);
    try {
      await tempDB.runAsync('BEGIN');
      const userInfo = await tempDB.getAsync('SELECT * FROM users WHERE email = ?', [req.body.email]);
      const domainInfo = await tempDB.getAsync('SELECT * FROM domains WHERE domain_id = ?', [req.body.domainKey]);
      const serverInfo = await tempDB.getAsync('SELECT * FROM servers WHERE server_id = ?', [req.body.serverKey]);

      // make sure server matches domain and tier
      const checkServerTier = await tempDB.getAsync('SELECT * FROM servers_to_tiers WHERE server_key = ? AND tier_key = ?', [req.body.serverKey, req.body.tierKey]);
      const checkDomainTier = await tempDB.getAsync('SELECT * FROM domains_to_tiers WHERE domain_key = ? AND tier_key = ?', [req.body.domainKey, req.body.tierKey]);

      if (!userInfo || !checkDomainTier || !checkServerTier) {
        throw new Error('Failed to that server or domain is allowed for given tier');
      } 

      // add items to DB
      const newRecord = await tempDB.runAsync(
        'INSERT INTO user_domains (user_key, server_key, tier_key, full_domain, subdomain, domain_key, charge_this, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [userInfo.user_id, req.body.serverKey, req.body.tierKey, `${req.body.subdomain}.${domainInfo.domain}`, req.body.subdomain, domainInfo.domain_id, req.body.tierPrice, 1]
      );

      // switch DNS record to selected server
      const ax1 = await axios.get(`https://api.dynu.com/nic/update?hostname=${domainInfo.domain}&alias=${req.body.subdomain}&myip=${serverInfo.ip}&password=${program.dynu.password}`)
      if (ax1.data === 'badauth') {
        // Add record and try again
        const axRecord = await axios.get(`https://api.dynu.com/v2/dns/getroot/${domainInfo.domain}`, { headers: { 'API-Key': program.dynu.apiKey } })
        await axios({
          method: 'post',
          url: `https://api.dynu.com/v2/dns/${axRecord.data.id}/record`, 
          headers: { 'accept': 'application/json', 'API-Key': program.dynu.apiKey },
          responseType: 'json',
          data: {
            "nodeName": req.body.subdomain,
            "recordType": "A",
            "ttl": 120,
            "state": true,
            "group": "",
            "ipv4Address": serverInfo.ip
          }
        });
      }
      
      // Setup user on selected server
      const serverJwt = jwt.sign({}, serverInfo.api_security_key);
      const newConnection = await axios({
        method: 'post',
        url: `https://${serverInfo.api_endpoint}/connection/add`, 
        headers: { 'accept': 'application/json', 'x-access-token': serverJwt },
        responseType: 'json',
        data: {
          "subdomain": req.body.subdomain,
          "domain": domainInfo.domain,
          "userId": String(userInfo.user_id),
          "frpPassword": userInfo.default_frp_password
        }
      });

      await tempDB.runAsync('UPDATE user_domains SET frp_password = ?, frp_bind_port = ?, frp_vhost_port = ? WHERE user_domain_id = ?', [newConnection.data.rpnPassword, newConnection.data.rpnPort, newConnection.data.rawPort, newRecord.lastID]);
      await tempDB.runAsync('COMMIT');
      res.json({});
    } catch (err) {
      await tempDB.runAsync('ROLLBACK');
      winston.error('Failed to add user connection');
      console.log(err);
      res.status(500).json({ error: 'Failed to add user connection'});
    }
    tempDB.close();
  });

  // express.post('/admin/users/connections/change-server', async (req, res) => {
  //   const { error, value } = Joi.object().keys({
  //     connectionId: Joi.string().required(),
  //     serverId: Joi.string().required()
  //   }).validate(req.body);

  //   if (error) { return res.status(500).json({ error: 'Invalid Input' }); }
    
  //   try {
  //     throw new Error('Not Implemented');
  //   } catch (err) {
  //     winston.error('Failed to change domain server');
  //     console.log(err);
  //     res.status(500).json({ error: 'Failed to change domain server'});
  //   }
  // });

  express.post('/admin/users/connections/delete', async (req, res) => {
    const { error, value } = Joi.object().keys({
      connectionId: Joi.string().required()
    }).validate(req.body);

    if (error) { return res.status(500).json({ error: 'Invalid Input' }); }
    
    try {
      const serverInfo = await db.getAsync('SELECT * FROM user_domains LEFT JOIN servers on servers.server_id = user_domains.server_key WHERE user_domain_id = ?', [req.body.connectionId]);
      if (!serverInfo) { res.status(500).json({ error: 'Did not find entry in DB' }); }

      // remove user on selected server
      const serverJwt = jwt.sign({}, serverInfo.api_security_key);
      await axios({
        method: 'post',
        url: `https://${serverInfo.api_endpoint}/connection/disable`, 
        headers: { 'accept': 'application/json', 'x-access-token': serverJwt },
        responseType: 'json',
        data: {
          "fullDomain": serverInfo.full_domain
        }
      });

      // remove entry from DB
      await db.runAsync('DELETE FROM user_domains WHERE full_domain = ?', [serverInfo.full_domain]);
      res.json({});
    }catch (err) {
      winston.error('Failed to remove user connection');
      console.log(err);
      res.status(500).json({ error: 'Failed to remove user connection'});
    }
  });

  express.post('/admin/servers/refresh-domains', (req, res) => {
    // auto update the domains-to-servers table
  });

  express.post('/admin/invites/generate', async (req, res) => {
    const { error, value } = Joi.object().keys({
      quantity: Joi.number().integer().greater(0).default(1)
    }).validate(req.body);

    if (error) { return res.status(500).json({ error: 'Invalid Input' }); }
    
    const returnThese = [];
    let counter = req.body.quantity;
    while (counter > 0) {
      const newCode = `${nanoid(6)}-${nanoid(6)}-${nanoid(6)}-${nanoid(6)}-${nanoid(6)}`;
      try {
        returnThese.push(newCode);
        await db.runAsync('INSERT INTO invites (invite_code) VALUES (?)', [newCode]);
      } catch (err) {}
      counter--;
    }

    res.json(returnThese);
  });

  express.get('/admin/invites/get', async (req, res) => {
    try {
      const allInvites = await db.allAsync('SELECT * FROM invites');
      res.json(allInvites);
    } catch (err) {
      json.status(500).json({ error: 'DB Error' });
    }
  });

  
  express.get('/admin/requests/get', async (req, res) => {
    try {
      const requests = await db.allAsync('SELECT * FROM invite_requests');
      res.json(requests);
    } catch (err) {
      json.status(500).json({ error: 'DB Error' });
    }
  });

  express.post('/admin/invite/email', (req, res) => {

  });
}