## What is this?
ADScan is a remote attack utility to be used against Domain Controllers. It implements a number of routine checks, it uses the following tools to achieve so:
- Impacket
- CrackMapExec
- Kerbrute
- ldeep
- Windapsearch

## How to use?
You can paste the function in your ```~/.zshrc``` or equivalent, you can then call it against the address of the DC like this:
```
adscan [DC_IP]
```
