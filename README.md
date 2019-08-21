Wireguard (IK pattern) from [Noise](https://noiseprotocol.org/) protocol framework on PicoLisp.

Mimics of any script from Wireguard's [distribution.](https://git.zx2c4.com/WireGuard/tree/contrib/external-tests)

### How to repeat:
* PicoLisp installed (64bit only)
* Download Monocypher 2.0.5 and apply patch from repo (patch from author)
* Install as shared library
* test-all.l should pass tests then
* run main.l and tcpdump
* and you will see: two packets are handshake, two packets are send and receive pings, last keepalive
```
16:14:22.715850 IP 10.10.25.204.60495 > 163.172.161.0.12913: UDP, length 148
16:14:22.767553 IP 163.172.161.0.12913 > 10.10.25.204.60495: UDP, length 92
16:14:22.787473 IP 10.10.25.204.60495 > 163.172.161.0.12913: UDP, length 80
16:14:22.837615 IP 163.172.161.0.12913 > 10.10.25.204.60495: UDP, length 80
16:14:22.837830 IP 10.10.25.204.60495 > 163.172.161.0.12913: UDP, length 32
```
* if you see 'OK' then all tests passed.

---

Note: test-phase1.l is minimum required handshake on place.
