#[
    SMB OS Discovery
]#
import net, strutils, terminal
import OSDiscovery/[SMBv1, SMBv2, HelpUtil, NTLM]

#[
    Object for the target information
]#
type
    TARGET_INFO* = object
        os_version*: string
        netBios_domain*: string
        netBios_computer*: string
        dns_domain*: string
        dns_computer*: string

#[
    Parse the target info response packet
]#
proc parseTargetInfo(target_info: seq[string], ntlmssp_struct: NTLMSSP_STRUCT): TARGET_INFO =
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

    ## OS version (SMBv1 get more accurate version later)
    let 
        major_version = ntlmssp_struct.major_version[0].int
        minor_version = ntlmssp_struct.minor_version[0].int
        build_number = ntlmssp_struct.build_number.byteArrayToNumber()
    result.os_version = "$1.$2 (Build $3)" % [$major_version, $minor_version, $build_number]

#[
    Print nice and all
]#
proc `$`*(info: TARGET_INFO) =
    stdout.write("OS Version --> "); stdout.styledWrite(fgCyan, info.os_version); stdout.write("\n")
    stdout.write("NetBIOS Domain Name --> "); stdout.styledWrite(fgCyan, info.netBios_domain); stdout.write("\n")
    stdout.write("NetBIOS Computer Name --> "); stdout.styledWrite(fgCyan, info.netBios_computer); stdout.write("\n")
    stdout.write("DNS Domain Name --> "); stdout.styledWrite(fgCyan, info.dns_domain); stdout.write("\n")
    stdout.write("DNS Computer Name --> "); stdout.styledWrite(fgCyan, info.dns_computer); stdout.write("\n")

#[
    Discover OS version using SMBv1
]#
proc SMBv1Discovery(target: string, info: var TARGET_INFO, timeout: int) = 
    let socket = newSocket()
    var recvClient: seq[string]

    ## Connect
    socket.connect(target, 445.Port)

    ## SMBv1 Init negotiate
    socket.send(getSMBv1NegoPacket("SMB1"))
    recvClient = socket.recvPacket(1024, timeout)

    ## Check Signing
    signing = checkSigning recvClient

    ## SMBv1NTLM negotiate
    socket.send(getSMBv1NTLMNego(signing))
    recvClient = socket.recvPacket(1024, timeout)
    
    ## Parse Windows version from the response
    let win_ver = parseWindowsVersion(recvClient)

    info.os_version = win_ver

    socket.close()

#[
    Discover host information using SMBv2
]#
proc SMBv2Discovery(target: string, info: var TARGET_INFO, timeout: int) = 
    let socket = newSocket()
    var recvClient: seq[string]

    ## Connect
    socket.connect(target, 445.Port)

    ## SMBv1 Init negotiate
    socket.send(getSMBv1NegoPacket("SMB2.1"))
    recvClient = socket.recvPacket(1024, timeout)

    ## Check Signing
    signing = checkSigning recvClient

    ## SMBv2 negotiate
    socket.send(getSMBv2NegoPacket())
    recvClient = socket.recvPacket(1024, timeout)

    ## SMBv2NTLM negotiate
    socket.send(getSMBv2NTLMNego(signing))
    recvClient = socket.recvPacket(1024, timeout)
    
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

    info = parseTargetInfo(target_info_byte, ntlmssp_struct)

#[
    Run OS discovery (SMBv2, SMBv1)
    Return object with the following information:
        os_version          -> OS Version
        netBios_domain      -> NetBIOS domain name
        netBios_computer    -> NetBIOS computer name
        dns_domain          -> DNS domain name
        dns_computer        -> DNS computer name
]#
proc runOSDiscovery*(target: string, timeout=500): TARGET_INFO =
    var info: TARGET_INFO

    ## SMBv2
    SMBv2Discovery(target, info, timeout)
    
    ## SMBv1
    SMBv1Discovery(target, info, timeout)

    return info

when isMainModule:
    let targetInfo = runOSDiscovery("10.0.0.22")
    $targetInfo