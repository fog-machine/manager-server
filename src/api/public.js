const winston = require('winston');
const path = require('path');
const nanoid = require('nanoid');
const axios = require('axios');
const expressUtils = require('express');
const jwt = require('jsonwebtoken');
const Joi = require('@hapi/joi');
const Login = require('./login');
const db = require('../database').getDb();

exports.setup = (program, express) => {
  express.post('/sign-up', async (req, res) => {
    const { error, value } = Joi.object().keys({
      email: Joi.string().email().required(),
      password: Joi.string().required(),
      tierId: Joi.string().required(),

      subdomain: Joi.string().pattern(/^([a-zA-Z0-9][a-zA-Z0-9-_]*[a-zA-Z0-9])+$/).required(),
      domainKey: Joi.string().required(),
      serverRegion: Joi.string().required(),
      inviteCode: Joi.string().optional().allow(''),
    }).validate(req.body);
    if (error) { return res.status(500).json({error: 'Invalid Input'}); }

    // Check if tier is valid
    const tierInfo = await db.getAsync('SELECT * FROM account_tiers WHERE account_tier_id = ?', [req.body.tierId]);
    if (!tierInfo) { return res.status(500).json({error: 'Tier Not Valid'}); }
    if (!tierInfo.is_public || tierInfo.is_public !== 1) { return res.status(500).json({error: 'Tier Not Public'}); }

    // Check domain is allowed for tier
    const domainInfo = await db.getAsync('SELECT * FROM domains WHERE domain_id = ?', [req.body.domainKey]);
    if (!domainInfo) { return res.status(500).json({ error: 'Could not find domain'}); }
    const checkDomainTier = await db.getAsync('SELECT * FROM domains_to_tiers WHERE domain_key = ? AND tier_key = ?', [req.body.domainKey, req.body.tierId]);
    if (!checkDomainTier) { return res.status(500).json({ error: 'Domain not allowed for tier'}); }

    // validate domains are valid
    if (domainInfo.restricted_subdomains) {
      try {
        const restrictedDomains = JSON.parse(domainInfo.restricted_subdomains);
        if (restrictedDomains.includes(req.body.subdomain)) { return res.status(500).json({ error: 'Domain not allowed'}); }
      } catch (err) {
        winston.error(`Failed to parse restricted domains for domainID: ${domainInfo.domain_id}`);
      }
    }

    if (domainInfo.restricted_subdomain_prefix && req.body.subdomain.startsWith(domainInfo.restricted_subdomain_prefix)) {
      return res.status(500).json({ error: 'Domain prefix not allowed'});
    }

    const tempDB = require('../database').getFreshSql(program.dbPath);
    await tempDB.runAsync('BEGIN');

    // Check invites
    try {
      if (tierInfo.requires_invite && tierInfo.requires_invite === 1) {
        const inviteInfo = await db.getAsync('SELECT * FROM invites WHERE invite_code = ? AND email IS NULL', [req.body.inviteCode]);
        if (!inviteInfo) {
          throw new Error('Invalid Invite Code');
        }

        // Claim invite
        await tempDB.runAsync('UPDATE invites SET email = ? WHERE invite_code = ?', [req.body.email, req.body.inviteCode]);
      }
    } catch (err) {
      res.status(500).json({ error: 'Could not validate invite'});
      await tempDB.runAsync('ROLLBACK');
      tempDB.close();
      return;
    }

    // Get a random server for tier
    let randServer;
    try {
      // get all servers in tier with region code
      const servers = await db.allAsync(
        `SELECT * FROM servers
          LEFT JOIN server_regions on server_regions.server_region_id = servers.region_key
          LEFT JOIN servers_to_tiers on servers_to_tiers.server_key = servers.server_id
          WHERE servers.region_key = ?
            AND servers_to_tiers.tier_key = ?`, 
        [req.body.serverRegion, req.body.tierId]);
      if (!servers || servers.length === 0) { throw new Error('No Servers Found'); }
      // pick a random server from list
      // TODO: This could be a better algorithm
      randServer = servers[Math.floor(Math.random() * servers.length)];
    }catch (err) {
      console.log(err);
      res.status(500).json({ error: 'Could not get servers'});
      await tempDB.runAsync('ROLLBACK');
      tempDB.close();
      return;
    }

    // add user to RPN server
    let userId;
    let randomString;
    try {
      randomString = nanoid(28);
      const hashObj = await Login.hashPassword(req.body.password);
      userId = await tempDB.runAsync('INSERT INTO users (email, password, salt, default_frp_password) VALUES (?, ?, ?, ?);', [req.body.email, hashObj.hashPassword, hashObj.salt, randomString]);
    } catch (err) {
      res.status(500).json({ error: 'User already exists'});
      await tempDB.runAsync('ROLLBACK');
      tempDB.close();
      return;
    }

    // Try inserting a domain record
    // Checks if domain is taken and claims it while the process finishes
    let newDomainRecord;
    try {
      newDomainRecord = await tempDB.runAsync(
        'INSERT INTO user_domains (user_key, server_key, tier_key, full_domain, subdomain, domain_key, charge_this, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [userId.lastID, randServer.server_id, req.body.tierId, `${req.body.subdomain}.${domainInfo.domain}`, req.body.subdomain, domainInfo.domain_id, tierInfo.price, 1]
      );

    } catch (err) {
      res.status(500).json({ error: 'Domain is taken'});
      await tempDB.runAsync('ROLLBACK');
      tempDB.close();
      return;
    }

    // Update DNS records
    try {
      // switch DNS record to selected server
      const ax1 = await axios.get(`https://api.dynu.com/nic/update?hostname=${domainInfo.domain}&alias=${req.body.subdomain}&myip=${randServer.ip}&password=${program.dynu.password}`)
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
            "ipv4Address": randServer.ip
          }
        });
      }
    }catch (err) {
      console.log(err);
      res.status(500).json({ error: 'Failed to setup DNS records'});
      await tempDB.runAsync('ROLLBACK');
      tempDB.close();
      return;
    }

    let newConnection;
    try {
      // Setup user on selected server
      const serverJwt = jwt.sign({}, randServer.api_security_key);
      newConnection = await axios({
        method: 'post',
        url: `https://${randServer.api_endpoint}/connection/add`, 
        headers: { 'accept': 'application/json', 'x-access-token': serverJwt },
        responseType: 'json',
        data: {
          "subdomain": req.body.subdomain,
          "domain": domainInfo.domain,
          "userId": String(userId.lastID),
          "frpPassword": randomString
        }
      });
    } catch (err) {
      console.log(err);
      res.status(500).json({ error: 'Failed to update RPN server'});
      await tempDB.runAsync('ROLLBACK');
      tempDB.close();
      return;
    }

    // final update
    try {
      await tempDB.runAsync('UPDATE user_domains SET frp_password = ?, frp_bind_port = ?, frp_vhost_port = ? WHERE user_domain_id = ?', [newConnection.data.rpnPassword, newConnection.data.rpnPort, newConnection.data.rawPort, newDomainRecord.lastID]);
      await tempDB.runAsync('COMMIT');
    } catch (err) {
      res.status(500).json({ error: 'Final update failed'});
      await tempDB.runAsync('ROLLBACK');
      tempDB.close();
      return;
    }

    res.json({});
    tempDB.close();
  });

  // Setup Public Folder
  express.use('/public', expressUtils.static(path.join(__dirname, '../../public')));
  express.get('/', (req, res) => {res.sendFile('index.html', { root: path.join(__dirname, '../../public/') }); });

  // Check if subdomain is available
  express.post('/available/domain', async (req, res) => {
    const { error, value } = Joi.object().keys({
      fullDomain: Joi.string().required()
    }).validate(req.body);
    if (error) { return res.status(500).json({error: 'Invalid Input'}) }

    try {
      const domainCheck = await db.getAsync('SELECT * FROM user_domains WHERE full_domain = ?', [req.body.fullDomain]);
      if (!domainCheck) { throw new Error('Domain Not Found'); }
    } catch (err) {
      return res.status(500).json({ error: 'Domain Already Registered' });
    }

    res.json({});
  });

  express.post('/invite/request', async (req, res) => {
    const { error, value } = Joi.object().keys({
      email: Joi.string().email().required()
    }).validate(req.body);
    if (error) { return res.status(500).json({error: 'Invalid Input'}) }

    try {
      await db.runAsync('INSERT INTO invite_requests (email) VALUES (?)', [req.body.email]);
    } catch (err) {
      return res.status(500).json({ error: 'Email already registered' });
    }

    res.json({});
  });
}