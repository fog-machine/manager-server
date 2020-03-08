const path = require('path');
const nanoid = require('nanoid');
const sqlite3 = require('sqlite3').verbose();
const Login = require('./src/api/login');

const db = new sqlite3.Database(path.join(process.cwd(), 'rpn.db' ));

async function runProgram() {
  // Generate a random password
  const username = 'admin';
  const password = nanoid(36);
  const hashObj = await Login.hashPassword(password);

  db.run("INSERT INTO users (email, password, salt, admin) VALUES (?, ?, ?, 1);", [username, hashObj.hashPassword, hashObj.salt], function(err) {
    if (err) { return console.log(err); }

    console.log();
    console.log("An admin user has been added to your database:");
    console.log();
    console.log(`username: ${username}`);
    console.log(`password: ${password}`);
    console.log();
  });
}

runProgram();