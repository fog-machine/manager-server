## What Is Fog Machine

Fog Machine is an open source alternative to NGROK.

While Fog Machine and NGROK are similar feature wise, Fog Machine aims to be used 

## What You Need Setup You're Own Copy of Fog Machine

- A domain
- An account [with DynuDNS](https://www.dynu.com/en-US)
- Two or more servers (preferably Digital Ocean droplets running Ubuntu 18.04)

Dynu is a DDNS provider that can be controller programmatically through their API.  The manager server uses the Dynu API to configure DNS records for the tunnel servers.  Dynu offers a free account tier and a paid tier for $10/year.  The free account is fine for testing, but for any serious deployments you should get the paid tier.

You will need to configure your domain registrar to use Dynu's name servers.  


## Setup a Tunnel Server

The tunnel server repository has a guide on deploying in the README file.  

## Setup a Manager Server

The manager server repository has a guide on deploying in the README file.  

## Connect with the client
