# Nim-OSDiscovery
SMB-OS-Discovery implementation in Nim

## Install
```
nimble install OSDiscovery
```

## Usage
```Nim
import OSDiscovery
```

## Examples
Run SMB OS Discovery on the target and print the results:
```Nim
import OSDiscovery

let info = runOSDiscovery("10.0.0.69") ## Run the discovery

$info ## Prints the information
```

## Wireshark
SMBv1 --> OS version:

![SMBv1](https://user-images.githubusercontent.com/69467775/112345256-8c99b500-8ccd-11eb-9f4f-7a7b03e1b812.png)

SMBv2 --> Domain & Computer name (NetBIOS & DNS):

![SMBv2](https://user-images.githubusercontent.com/69467775/112346161-5b6db480-8cce-11eb-9ca1-e41b21775fa6.png)


## Support
#### Only supports Windows OS discovery
