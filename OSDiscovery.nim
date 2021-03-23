#[
    SMB OS Discovery
]#
import modules/[SMBv1, SMBv2, HelpUtil, NTLM], net, strutils

type
    TARGET_INFO* = object
        os_version*: string
        netBios_domain*: string
        netBios_computer*: string
        dns_domain*: string
        dns_computer*: string

proc parseTargetInfo(target_info: seq[string]): TARGET_INFO =
    ## NetBIOS Domain Name
    let 
        domain_len = target_info[2..3].seqHexToNumber()
        domain_offset = 4 + domain_len
    result.netBios_domain = target_info[4..domain_offset - 1].join("").parseHexStr()
    
    ## NetBIOS Computer Name
    let
        computer_len = target_info[domain_offset+2..domain_offset+3].seqHexToNumber()
        computer_offset = domain_offset + 4 + computer_len
    result.netBios_computer = target_info[domain_offset + 4..computer_offset - 1].join("").parseHexStr()
    
    ## DNS Domain Name
    let
        dns_domain_len = target_info[computer_offset+2..computer_offset+3].seqHexToNumber()
        dns_domain_offset = computer_offset + 4 + dns_domain_len
    result.dns_domain = target_info[computer_offset + 4..dns_domain_offset - 1].join("").parseHexStr()

    ## DNS Computer Name
    let
        dns_computer_len = target_info[dns_domain_offset+2..dns_domain_offset+3].seqHexToNumber()
        dns_computer_offset = dns_domain_offset + 4 + dns_computer_len
    result.dns_computer = target_info[dns_domain_offset + 4..dns_computer_offset - 1].join("").parseHexStr()

proc `$`(info: TARGET_INFO): string =
    echo "OS"

#[
    Run OS discovery
    Return object with the following information:
        netBios_domain      -> NetBIOS domain name
        netBios_computer    -> NetBIOS computer name
        dns_domain          -> DNS domain name
        dns_computer        -> DNS computer name
]#
proc runOSDiscovery*(target: string): TARGET_INFO =
    let socket = newSocket()
    var recvClient: seq[string]

    ## Connect
    socket.connect(target, 445.Port)

    ## SMBv1 Init negotiate
    socket.send(getSMBv1NegoPacket())
    recvClient = socket.recvPacket(1024, 100)

    ## Check Signing
    signing = checkSigning recvClient

    ## SMBv2 negotiate
    socket.send(getSMBv2NegoPacket())
    recvClient = socket.recvPacket(1024, 100)

    ## SMBv2NTLM negotiate
    socket.send(getSMBv2NTLMNego(signing))
    recvClient = socket.recvPacket(1024, 100)
    
    socket.close()

    let endRecv = recvClient.len-1
    var 
        blob_length_hex = recvClient[74..75]
        blob_length = blob_length_hex.seqHexToNumber
        security_blob = recvClient[recvClient.len-blob_length..endRecv]

        NTLMSSP = security_blob[31..security_blob.len-1]
        NTLMSSP_byte = NTLMSSP[..55]

        ntlmssp_struct = parseNTLMSSP(NTLMSSP_byte)
        
        endNTLMSSP = NTLMSSP.len - 1
        
        target_info_len = ntlmssp_struct.target_info_length[0].int
        target_info_byte = NTLMSSP[NTLMSSP.len-target_info_len..endNTLMSSP]

    return parseTargetInfo(target_info_byte)

when isMainModule:
    let target_info = runOSDiscovery("10.0.0.22")
    echo target_info.dns_computer