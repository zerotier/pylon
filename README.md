# ZeroTier Pylon

Easily tunnel traffic to and from your LAN and ZeroTier Virtual Network using an SOCKS5 proxy (includes an optional TCP relay for use behind difficult NATs)

![Build](https://github.com/zerotier/pylon/actions/workflows/build.yml/badge.svg?branch=main)

## Build

Currently you must build it and distribute it to your server manually. The build process will pull a submodule (which itself pulls submodules), build libzt there, and then link pylon against the resultant `libzt.a` static library. Requires `clang`, and `cmake` to build.

```
make
```

## Docker
We have docker images available if you prefer. 


### reflect
``` sh
docker run --init -p 9443:443 -p 19993:9993/udp zerotier/pylon:latest \
reflect
```

See below for configuring zerotier-one to use your `reflect` as a tcp-relay.

### refract

``` sh
docker run --init -e ZT_PYLON_SECRET_KEY=$(cat identity.secret) -e ZT_PYLON_WHITELISTED_PORT=4545 \
--net=host --cap-add NET_ADMIN \
zerotier/pylon refract 6ab565387a111111 --listen-addr 0.0.0.0 --listen-port 1080
```

See [Usage] for more info on the commands.

## Usage

Pylon can be run as one of two personalities that can work alone or together depending on your needs:

| Name  | What do | Is this a ZeroTier Node? |
| ------------- | ------------- | - |
| `pylon refract`  | This bridges traffic to and from your LAN | Yes |
| `pylon reflect` | This relays traffic over `TCP/443`  | No |

In many cases a single `refract` instance is enough to bridge devices onto your ZeroTier network. However, if you're behind some tricky NAT you might need to set up a `reflect` instance on a machine with a static IP for your `refract` instance to use.

### Set identity

Set environment variable to hold your ZeroTier secret identity:

```
export ZT_PYLON_SECRET_KEY=$(sudo cat identity.secret)
```

### Specify an (optional) UDP port for ZeroTier to use

By default Pylon will chose a random port to send ZeroTier traffic over, but If you need it to only send traffic over a whitelisted port you can specify one like so:
```
export ZT_PYLON_WHITELISTED_PORT=4545
```

### `refract` (SOCKS5 Proxy)

Run proxy service to listen for app traffic locally on `127.0.0.1:1080`:

```
./pylon refract b84ac5c40a2339c9 --listen-addr 0.0.0.0 --listen-port 1080
```

You can also listen on `0.0.0.0`.

### `reflect` (Dumb TCP Relay)

If you have a tricky NAT situation and can allow `TCP/443`, you can specify a relay on a machine with a static IP. To reduce latency, the tcp-relay should be as close as possible to the nodes it is serving. A datacenter in the same city or the LAN would be ideal.

```
./pylon reflect
```

Then tell your pylon instances to use that to proxy traffic:

```
./pylon refract b84ac5c40a2339c9 --listen-addr 0.0.0.0 --listen-port 1080 --relay-addr 0.0.0.0 --relay-port 443
```

Note: a `reflect` instance is just a [tcp-proxy](https://github.com/zerotier/ZeroTierOne/tree/dev/tcp-proxy) and can be used by a regular ZeroTier client just the same. Expand the following instructions for more info:

<details>
  <summary>Instructions for use with regular ZeroTier client</summary>

### Point your node at it

The default tcp relay is at `204.80.128.1/443` -an anycast address.

#### Option 1 - local.conf configuration
See [Service docs](https://github.com/zerotier/ZeroTierOne/blob/e0acccc3c918b59678033e585b31eb000c68fdf2/service/README.md) for more info on local.conf
`{ "settings": { "tcpFallbackRelay": "1.2.3.4/443", "forceTcpRelay": true  } }`

In this example, `forceTcpRelay` is enabled. This is helpful for testing or if you know you'll need tcp relay. It takes a few minutes for zerotier-one to realize it needs to relay otherwise.

#### Option 2 - redirect 204.80.128.1 to your own IP

If you are the admin of the network that is blocking ZeroTier UDP, you can transparently redirect 204.80.128.1 to one of your IP addresses. Users won't need to edit their local client configuration.

Configuring this in your Enterprise Firewall is left as an exercise to the reader.

Here is an iptables example for illustrative purposes:

``` shell
-A PREROUTING -p tcp -d 204.80.128.1 --dport 443 -j DNAT --to-destination 1.2.3.4
-A POSTROUTING -p tcp -d 1.2.3.4 --dport 443 -j SNAT --to-source 204.80.128.1
```

</details>

## Example Test

Set up remote resource:

```
mkdir serveme && cd serveme && echo "served data" > served.txt && \
python -m http.server -b 0.0.0.0 8000
```

Attempt a proxied HTTP GET:

```
curl --verbose --output output.txt 172.28.128.86:8000 --proxy socks5://127.0.0.1:1080
```

## Debugging

```
make debug|clean
```

You'll get:

```
pylon-debug
```

## Limitations

While a single Pylon instance will work for multiple networks and multiple applications simultaneously it will perform better if a new instance is started for each proxied network. The underlying [libzt]() isn't multithreaded so it is recommended that you also split your proxied traffic across multiple instances if you notice performance bottlecks. Finally, Pylon only supports IPv4 TCP but IPv6 and UDP support can be added if there is sufficient interest.

## Releasing

Releasing to Docker Hub is done from our internal CI. 
- create a tag on `main`: `git tag v0.1.7`
- push the tag: `git push --tags` This triggers the build and push to dockerhub. 
- create a Github Release through the Github ui. Select the tag you just pushed. 
