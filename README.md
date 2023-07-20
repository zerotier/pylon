# ZeroTier Pylon
Proxy layer 5 traffic from your apps to and from your ZeroTier virtual network without installing ZeroTier and without bringing up any new network interfaces.

## Usage

Set environment variable to hold your ZeroTier secret identity:

```
export ZT_PYLON_SECRET_KEY=$(sudo cat identity.secret)
```

By default Pylon will chose a random port to send ZeroTier traffic over, but If you need it to only send traffic over a whitelisted port you can specify one like so:
```
export ZT_PYLON_WHITELISTED_PORT=4545
```

Run proxy service to listen for app traffic locally on `127.0.0.1:1080`:

```
pylon b84ac5c40a2339c9 127.0.0.1 1080
```

You can also listen on `0.0.0.0`.

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

## Limitations

While a single Pylon instance will work for multiple networks and multiple applications simultaneously it will perform better if a new instance is started for each proxied network. The underlying [libzt]() isn't multithreaded so it is recommended that you also split your proxied traffic across multiple instances if you notice performance bottlecks. Finally, Pylon only supports IPv4 TCP but IPv6 and UDP support can be added if there is sufficient interest.