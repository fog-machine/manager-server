## Fog Machine Manager Server

The manager server handles a few different tasks

* User system.  There is a simple sign up API that can be invite only
* Users can have any number of tunnels
* Admin API
* Admin API and web UI to 
* Manager server can sort servers by tiers.  

## Install

Install script is in `/bash/install.sh`

The install script has a portion at the bottom commented out.  The commented out code sets up the SSL certificates for the server using a DNS verification method.

I use DynuDNS in this script.  If you use DynyDNS as well, you can just add in your keys and it will work. If you have another DNS provider or want to install the certs manually, [check out the documentation for acme.sh to see how.](https://github.com/acmesh-official/acme.sh)

To setup a new server from scratch, follow these steps:

- ssh into server as root
- copy install script to `~/install.sh`
- `chmod 755 install.sh`
- `./install.sh`
- check that script was successful
    - `pm2 list all` and `pm2 logs` to make sure the server is running
    - check of nginx config files
    - check `crontab -l` to make sure acme.sh add a certificate renewal job


## Admin User

The install script will create an admin user for you and print the username and password out to the terminal.




## Setup Structure

The concepts (in order):

* users
* tunnels (part 1)
* domain
* tier
* domain <--> tier
* server region
* tunnel server
* tunnel server <--> region
* tunnel server <--> domain
* tunnel server <--> tier
* tunnels (part 2)
* user signup process

A manger is very flexible, but you will need to do some manual configuration.  This entire process can be done through the admin panel in the Web UI.

#### users

At the core, the management server is a user authentication and authorization system.  

#### tunnels

Users can have any number of tunnels.  A tunnel has a region, tier, and charge price attached to it

#### domain

Before you start registering users and tunnels, your need to declare what domains your manager server will be responsible for.  


* `restricted_subdomains` - a list of subdomains that cannot be claimed by a user
* `restricted_subdomain_prefix` - block registration of all domains with this prefix.  Used to block api subdomains for tunnel servers

#### tier

Tiers are how tunnels are classified.  Tiers have a few properties

* `is_public` - If set to false, users will not be able to register tunnels to this tier
* `requires_invite` - Users will need an invite code in order to register a tunnel to this tier
* `price` - Not hooked up to anything currently.  The idea is to be able to charge monthly for a tunnel. Different tiers can have different prices
* `account_terminates_in_x_hours` - Not hooked up to anything currently.  Can be used to make trial accounts with a time limit

#### domain <--> tier

A tier must be connected to a domain before a user will be able to access that tier

#### server region

## API

See the fully documented API here

## Web App

The server includes a simple webapp. 

## Configure - DNS

This project utilizes Dynu DDNS and their API to manage API records for the domains.  


## Configure - Security

This scr

## Configure - Email

## Platforms

This install script was designed to work on Ubuntu 18.04 on Digital Ocean servers.

## Setup - Admin Account

## Setup - Tiers

Tiers are an abstraction to sort subscriptions

## Setup - Tunnel Servers

You have to register a tunnel

## Setup - User Accounts

- add URLS to the DB
- Add server regions to the DB
- Add account tiers to the DB
- add servers to the DB


## TODO

This project is not done.  But it is usable. There's a lot of remove for improvements and new features

- Automated scaling. Right now new tunnel servers have to be deployed by hand. 
- Better handling of connection status.  Right now the manager server has no idea if tunnel is actively being used or not.  If it had this information, it would help with the automatic scaling feature