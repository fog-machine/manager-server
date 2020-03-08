# For Ubuntu 18.04 ONLY

tput reset

echo
echo Welcome to the RPN Server Install Script
echo
echo 'Press any key to continue'
read 

tput reset

echo
echo 'API Domain? (ex: fogmachine.io)'
echo
echo
read apiDomain

tput reset
echo
echo 'Domains this server will register wildcard SSL certificates for:'
echo $apiDomain
echo

read -r -p "Is that correct? [Y/n]" response
echo $response
if [[ $response =~ ^([nN][oO]|[nN])$ ]]; then
    exit 1
fi

# Update system
curl -sL https://deb.nodesource.com/setup_12.x | sudo -E bash -
apt update -y
apt upgrade -y
apt autoremove -y

# APT Install
apt install -y curl git nginx

# Install Node JS
apt install -y nodejs

# Clone Repo
git clone https://github.com/fog-machine/manager-server.git

# Install
cd manager-server
npm install

# Setup NGINX Config
# OR /etc/nginx/conf.d/servers.conf
echo "server {
   listen 80;
   server_name ${apiDomain} *.${apiDomain};
   rewrite     ^   https://\$host\$request_uri? permanent;
}

server {
    listen 443 ssl;
    server_name ${apiDomain} *.${apiDomain};

    ssl_certificate /etc/ssl/certs/api.pem;
    ssl_certificate_key /etc/ssl/private/api.key;

    # Turn on OCSP stapling as recommended at
    # https://community.letsencrypt.org/t/integration-guide/13123
    # requires nginx version >= 1.3.7
    ssl_stapling on;
    ssl_stapling_verify on;

    location / {
        proxy_pass http://localhost:2022;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \"upgrade\";
        proxy_set_header Host \$host;
    }
}" > /etc/nginx/sites-enabled/default

# Install pm2
cd ..
npm install -g pm2

mkdir conf
cp manager-server/config/example.json conf/config.json

# config pm2
echo "module.exports = {
  apps : [{
    name   : 'rpn-manager-server',
    script : './index.js',
    cwd    : './manager-server',
    args   : ['../conf/config.json']
  }]
}" > pm2.config.js

pm2 start pm2.config.js
pm2 startup systemd
pm2 save

# TODO: modify config file

# # Install acme.sh
# curl https://get.acme.sh | sh
# export Dynu_ClientId="XXXXXXXXX"
# export Dynu_Secret="YYYYYYYYYY"
# # Restart terminal after installing acme.sh
# tset

# # Run ACME.SH
# ./.acme.sh/acme.sh --issue --dns dns_dynu -d *.${apiDomain} -d ${apiDomain}
# # Move Certs
# ./.acme.sh/acme.sh --install-cert -d *.${apiDomain} --key-file  /etc/ssl/private/api.key  --fullchain-file /etc/ssl/certs/api.pem --reloadcmd "service nginx force-reload"

# # Restart NGINX
# service nginx restart
