const sqlite3 = require('sqlite3').verbose();
var db;

exports.setup = program => {
  // Add convenience functions
  sqlite3.Database.prototype.runAsync = function (sql, params) {
    return new Promise((resolve, reject) => {
      this.run(sql, params, function (err) {
        if (err) return reject(err);
        resolve(this);
      });
    });
  };

  sqlite3.Database.prototype.getAsync = function (sql,params) {
    return new Promise((resolve, reject) => {
      this.get(sql, params, function (err, row) {
        if (err) return reject(err);
        resolve(row);
      });
    });
  };

  sqlite3.Database.prototype.allAsync = function (sql,params) {
    return new Promise((resolve, reject) => {
      this.all(sql, params, function (err, rows) {
        if (err) return reject(err);
        resolve(rows);
      });
    });
  };

  sqlite3.Database.prototype.execAsync = function (sql, params) {
    return new Promise((resolve, reject) => {
      this.exec(sql, params, function (err) {
        if (err) return reject(err);
        resolve(this);
      });
    });
  };

  db = new sqlite3.Database(program.dbPath);

  db.exec(
    `PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS account_tiers (
      account_tier_id INTEGER PRIMARY KEY AUTOINCREMENT,
      price INTEGER NOT NULL,
      name VARCHAR UNIQUE NOT NULL,
      is_public INTEGER NOT NULL DEFAULT 0,
      requires_invite INTEGER NOT NULL DEFAULT 0,
      account_terminates_in_x_hours INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS users (
      user_id INTEGER PRIMARY KEY AUTOINCREMENT,
      password VARCHAR NOT NULL,
      salt VARCHAR NOT NULL,
      email VARCHAR UNIQUE NOT NULL,
      phone VARCHAR UNIQUE,

      stripe_customer_id VARCHAR,
      last_payment_date DATETIME,

      default_frp_password VARCHAR,

      admin INTEGER DEFAULT 0,

      created DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS server_regions (
      server_region_id INTEGER PRIMARY KEY AUTOINCREMENT,
      region_code VARCHAR UNIQUE NOT NULL,
      region_name VARCHAR UNIQUE NOT NULL,
      created DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS domains (
      domain_id INTEGER PRIMARY KEY AUTOINCREMENT,
      domain VARCHAR UNIQUE NOT NULL,
      restricted_subdomains VARCHAR,
      restricted_subdomain_prefix VARCHAR
    );

    CREATE TABLE IF NOT EXISTS servers (
      server_id INTEGER PRIMARY KEY AUTOINCREMENT,
      ip VARCHAR UNIQUE NOT NULL,
      server_name VARCHAR UNIQUE,
      api_endpoint VARCHAR NOT NULL,
      api_security_key VARCHAR NOT NULL,

      region_key INTEGER NOT NULL,
      disabled INTEGER DEFAULT 0,
      created DATETIME DEFAULT CURRENT_TIMESTAMP,
      modified DATETIME,
      FOREIGN KEY (region_key) REFERENCES server_regions (server_region_id)
    );

    CREATE TABLE IF NOT EXISTS domains_to_servers (
      domain_key INTEGER NOT NULL,
      server_key INTEGER NOT NULL,
      FOREIGN KEY (domain_key) REFERENCES domains (domain_id),
      FOREIGN KEY (server_key) REFERENCES servers (server_id),
      PRIMARY KEY (domain_key, server_key)
    );

    CREATE TABLE IF NOT EXISTS domains_to_tiers (
      domain_key INTEGER NOT NULL,
      tier_key INTEGER NOT NULL,
      FOREIGN KEY (domain_key) REFERENCES domains (domain_id),
      FOREIGN KEY (tier_key) REFERENCES account_tiers (account_tier_id),
      PRIMARY KEY (domain_key, tier_key)
    );

    CREATE TABLE IF NOT EXISTS servers_to_tiers (
      server_key INTEGER NOT NULL,
      tier_key INTEGER NOT NULL,
      FOREIGN KEY (server_key) REFERENCES servers (server_id),
      FOREIGN KEY (tier_key) REFERENCES account_tiers (account_tier_id),
      PRIMARY KEY (server_key, tier_key)
    );

    CREATE TABLE IF NOT EXISTS user_domains (
      user_domain_id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_key INTEGER NOT NULL,
      server_key INTEGER,

      full_domain VARCHAR UNIQUE NOT NULL,
      subdomain VARCHAR NOT NULL,
      domain_key INTEGER NOT NULL,

      frp_password VARCHAR,
      frp_bind_port INTEGER,
      frp_vhost_port INTEGER, /* This is now the port used for minecraft, should be renamed */
      frp_process_id VARCHAR,

      is_active INTEGER NOT NULL DEFAULT 1,
      tier_key INTEGER NOT NULL,
      charge_this INTEGER NOT NULL,
    
      created DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_key) REFERENCES users (user_id),
      FOREIGN KEY (domain_key) REFERENCES domains (domain_id),
      FOREIGN KEY (server_key) REFERENCES servers (server_id),
      FOREIGN KEY (tier_key) REFERENCES account_tiers (account_tier_id)
    );
    
    CREATE TABLE IF NOT EXISTS invites (
      invite_code VARCHAR UNIQUE NOT NULL,
      tier_key INTEGER,
      email VARCHAR,

      FOREIGN KEY (tier_key) REFERENCES account_tiers (account_tier_id)
    );
    
    CREATE TABLE IF NOT EXISTS invite_requests (
      email VARCHAR UNIQUE NOT NULL
    );`
  );
}

exports.getDb = () => {
  return db;
}

exports.getFreshSql = (dbPath) => {
  return new sqlite3.Database(dbPath);
}