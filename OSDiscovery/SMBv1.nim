#[
    SMBv1 Negotiate
]#

import tables, os, strutils, sequtils, algorithm
import HelpUtil, NTLM

proc NewPacketSMBHeader(command, flags1, flags2, treeID, processID, userID: seq[byte]): OrderedTable[string, seq[byte]] =
    
    var SMBHeader = initOrderedTable[string, seq[byte]]() # $SMBHeader = New-Object System.Collections.Specialized.OrderedDictionary
    let process = processID[0..1] # $ProcessID = $ProcessID[0,1]

    SMBHeader.add("Protocol", @[0xff.byte,0x53.byte,0x4d.byte,0x42.byte])# $SMBHeader.Add("Protocol",[Byte[]](0xff,0x53,0x4d,0x42))
    SMBHeader.add("Command", command)# $SMBHeader.Add("Command",$Command)
    SMBHeader.add("ErrorClass", @[0x00.byte])# $SMBHeader.Add("ErrorClass",[Byte[]](0x00))
    SMBHeader.add("Reserved", @[0x00.byte])# $SMBHeader.Add("Reserved",[Byte[]](0x00))
    SMBHeader.add("ErrorCode", @[0x00.byte, 0x00.byte])# $SMBHeader.Add("ErrorCode",[Byte[]](0x00,0x00))
    SMBHeader.add("Flags", flags1)# $SMBHeader.Add("Flags",$Flags)
    SMBHeader.add("Flags2", flags2)# $SMBHeader.Add("Flags2",$Flags2)
    SMBHeader.add("ProcessIDHigh", @[0x00.byte,0x00.byte])# $SMBHeader.Add("ProcessIDHigh",[Byte[]](0x00,0x00))
    SMBHeader.add("Signature", @[0x00.byte ,0x00.byte ,0x00.byte ,0x00.byte ,0x00.byte ,0x00.byte ,0x00.byte,0x00.byte])# $SMBHeader.Add("Signature",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    SMBHeader.add("Reserved2", @[0x00.byte,0x00.byte])# $SMBHeader.Add("Reserved2",[Byte[]](0x00,0x00))
    SMBHeader.add("TreeID", treeID)# $SMBHeader.Add("TreeID",$TreeID)
    SMBHeader.add("ProcessID",process)# $SMBHeader.Add("ProcessID",$ProcessID)
    SMBHeader.add("UserID",userID)# $SMBHeader.Add("UserID",$UserID)
    SMBHeader.add("MultiplexID", @[0x00.byte,0x00.byte])# $SMBHeader.Add("MultiplexID",[Byte[]](0x00,0x00))
    return SMBHeader

proc NewPacketSMBNegotiateProtocolRequest(version: string): OrderedTable[string, seq[byte]] =
    var byte_count: seq[byte]
    if version == "SMB1":
        byte_count = @[0x0c.byte, 0x00.byte]
    else:
        byte_count = @[0x22.byte, 0x00.byte]
    
    var SMBNegotiateProtocolRequest = initOrderedTable[string, seq[byte]]() # $SMBNegotiateProtocolRequest = New-Object System.Collections.Specialized.OrderedDictionary

    SMBNegotiateProtocolRequest.add("WordCount", @[0x00.byte]) #$SMBNegotiateProtocolRequest.Add("WordCount",[Byte[]](0x00))
    SMBNegotiateProtocolRequest.add("ByteCount", byte_count) #     $SMBNegotiateProtocolRequest.Add("ByteCount",$byte_count)
    SMBNegotiateProtocolRequest.add("RequestedDialects_Dialect_BufferFormat", @[0x02.byte]) #     $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_BufferFormat",[Byte[]](0x02))
    SMBNegotiateProtocolRequest.add("RequestedDialects_Dialect_Name",@[0x4e.byte,0x54.byte,0x20.byte,0x4c.byte,0x4d.byte,0x20.byte,0x30.byte,0x2e.byte,0x31.byte,0x32.byte,0x00.byte]) # $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_Name",[Byte[]](0x4e,0x54,0x20,0x4c,0x4d,0x20,0x30,0x2e,0x31,0x32,0x00))

    if version != "SMB1":
        SMBNegotiateProtocolRequest.add("RequestedDialects_Dialect_BufferFormat2",@[0x02.byte]) #  $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_BufferFormat2",[Byte[]](0x02))
        SMBNegotiateProtocolRequest.add("RequestedDialects_Dialect_Name2",@[0x53.byte,0x4d.byte,0x42.byte,0x20.byte,0x32.byte,0x2e.byte,0x30.byte,0x30.byte,0x32.byte,0x00.byte]) # $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_Name2",[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x30,0x30,0x32,0x00))
        SMBNegotiateProtocolRequest.add("RequestedDialects_Dialect_BufferFormat3",@[0x02.byte]) # $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_BufferFormat3",[Byte[]](0x02))
        SMBNegotiateProtocolRequest.add("RequestedDialects_Dialect_Name3",@[0x53.byte,0x4d.byte,0x42.byte,0x20.byte,0x32.byte,0x2e.byte,0x3f.byte,0x3f.byte,0x3f.byte,0x00.byte]) # $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_Name3",[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x3f,0x3f,0x3f,0x00))

    return SMBNegotiateProtocolRequest

proc NewPacketNetBIOSSessionService(headerLength, dataLength: int): OrderedTable[string, seq[byte]] =
    var NetBIOSSessionService = initOrderedTable[string, seq[byte]]() # $NetBIOSSessionService = New-Object System.Collections.Specialized.OrderedDictionary

    let temp = (headerLength + dataLength).toHex()
    var length: seq[byte]
    length.add(0x00.byte)
    length.add(0x00.byte)
    length.add((temp.split("00").join().hexToPSShellcode()).parseHexInt().byte)
    NetBIOSSessionService.add("MessageType", @[0x00.byte])
    NetBIOSSessionService.add("Length", length)
    return NetBIOSSessionService

proc NewPacketSMBSessionSetupAndXRequest(SecurityBlob: seq[byte]): OrderedTable[string, seq[byte]] =
    
    let byte_count = getBytes(SecurityBlob.len)[..1] # [Byte[]]$byte_count = [System.BitConverter]::GetBytes($SecurityBlob.Length)[0,1]
    let security_blob_length = getBytes(SecurityBlob.len+5)[..1] # [Byte[]]$security_blob_length = [System.BitConverter]::GetBytes($SecurityBlob.Length + 5)[0,1]

    var SMBSessionSetupAndXRequest = initOrderedTable[string, seq[byte]]() # $SMBSessionSetupAndXRequest = New-Object System.Collections.Specialized.OrderedDictionary

    SMBSessionSetupAndXRequest.add("WordCount", @[0x0c.byte]) # $SMBSessionSetupAndXRequest.Add("WordCount",[Byte[]](0x0c))
    SMBSessionSetupAndXRequest.add("AndXCommand", @[0xff.byte]) # $SMBSessionSetupAndXRequest.Add("AndXCommand",[Byte[]](0xff))
    SMBSessionSetupAndXRequest.add("Reserved", @[0x00.byte]) # $SMBSessionSetupAndXRequest.Add("Reserved",[Byte[]](0x00))
    SMBSessionSetupAndXRequest.add("AndXOffset", @[0x00.byte, 0x00.byte]) # $SMBSessionSetupAndXRequest.Add("AndXOffset",[Byte[]](0x00,0x00))
    SMBSessionSetupAndXRequest.add("MaxBuffer", @[0xff.byte, 0xff.byte]) # $SMBSessionSetupAndXRequest.Add("MaxBuffer",[Byte[]](0xff,0xff))
    SMBSessionSetupAndXRequest.add("MaxMpxCount", @[0x02.byte, 0x00.byte]) # $SMBSessionSetupAndXRequest.Add("MaxMpxCount",[Byte[]](0x02,0x00))
    SMBSessionSetupAndXRequest.add("VCNumber", @[0x01.byte, 0x00.byte]) # $SMBSessionSetupAndXRequest.Add("VCNumber",[Byte[]](0x01,0x00))
    SMBSessionSetupAndXRequest.add("SessionKey", @[0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte]) # $SMBSessionSetupAndXRequest.Add("SessionKey",[Byte[]](0x00,0x00,0x00,0x00))
    SMBSessionSetupAndXRequest.add("SecurityBlobLength", byte_count) # $SMBSessionSetupAndXRequest.Add("SecurityBlobLength",$byte_count)
    SMBSessionSetupAndXRequest.add("Reserved2", @[0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte]) # $SMBSessionSetupAndXRequest.Add("Reserved2",[Byte[]](0x00,0x00,0x00,0x00))
    SMBSessionSetupAndXRequest.add("Capabilities", @[0x44.byte, 0x00.byte, 0x00.byte, 0x80.byte]) # $SMBSessionSetupAndXRequest.Add("Capabilities",[Byte[]](0x44,0x00,0x00,0x80))
    SMBSessionSetupAndXRequest.add("ByteCount", security_blob_length) # $SMBSessionSetupAndXRequest.Add("ByteCount",$security_blob_length)
    SMBSessionSetupAndXRequest.add("SecurityBlob", SecurityBlob) # $SMBSessionSetupAndXRequest.Add("SecurityBlob",$SecurityBlob)
    SMBSessionSetupAndXRequest.add("NativeOS", @[0x00.byte, 0x00.byte, 0x00.byte]) # $SMBSessionSetupAndXRequest.Add("NativeOS",[Byte[]](0x00,0x00,0x00))
    SMBSessionSetupAndXRequest.add("NativeLANManage", @[0x00.byte, 0x00.byte]) # $SMBSessionSetupAndXRequest.Add("NativeLANManage",[Byte[]](0x00,0x00))

    return SMBSessionSetupAndXRequest

proc convertToByteArray(tab: OrderedTable): seq[byte] =
    for v in tab.values:
        result.add(v)

proc getSMBv1NegoPacket*(version: string): string =
    let process_ID = getCurrentProcessId().toHex().split("00").join()
    var reversing = (process_ID.hexToPSShellcode().split(","))

    let rev = reversed(reversing[..(reversing.len() - 1)])
    var revBytes: seq[byte]
    for b in rev:
        revBytes.add((b.parseHexInt()).byte)

    let 
        smbHeader = convertToByteArray NewPacketSMBHeader(@[0x72.byte], @[0x18.byte], @[0x01.byte,0x48.byte], @[0xff.byte,0xff.byte], revBytes, @[0x00.byte,0x00.byte])
        smbData = convertToByteArray NewPacketSMBNegotiateProtocolRequest(version)
        netBiosSession = convertToByteArray NewPacketNetBIOSSessionService(smbHeader.len(), smbData.len())
        fullPacket = concat(netBiosSession, smbHeader, smbData)
    
    var strPacket: string
    for p in fullPacket:
        strPacket &= p.toHex()
    return (strPacket).parseHexStr()

proc getSMBv1NTLMNego*(signing: bool): string =
    var negotiate_flags: seq[byte]
    if signing:
        negotiate_flags = @[0x15.byte,0x82.byte,0x08.byte,0xa0.byte] # Signing true
    else:
        negotiate_flags = @[0x05.byte,0x82.byte,0x08.byte,0xa0.byte] # Signing false

    var packet_SMB_header = NewPacketSMBHeader(@[0x73.byte], @[0x18.byte], @[0x07.byte, 0xc8.byte], @[0xff.byte, 0xff.byte], process_ID, @[0x00.byte, 0x00.byte])
    if signing:
        packet_SMB_header["Flags2"] = @[0x05.byte,0x48.byte] # Signing true

    let
        smb1Header = convertToByteArray packet_SMB_header
        NTLMSSPnegotiate = convertToByteArray NewPacketNTLMSSPNegotiate(negotiate_flags, @[])
        smb1Data = convertToByteArray NewPacketSMBSessionSetupAndXRequest(NTLMSSPnegotiate)
        netBiosSession = convertToByteArray NewPacketNetBIOSSessionService(smb1Header.len(), smb1Data.len())
        fullPacket = concat(netBiosSession, smb1Header, smb1Data)
    
    return buildPacket(fullPacket)

