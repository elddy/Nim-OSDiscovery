#[
    SMBv2 Negotiate
]#

import HelpUtil
import tables, strutils, sequtils, NTLM, nativesockets, random

randomize()

proc NewPacketSMB2Header*(command: seq[byte], creditRequest: seq[byte], signing: bool, messageID: seq[byte], processID, treeID, sessionID: seq[byte]): OrderedTable[string, seq[byte]] =
    var flags: seq[byte]
    if signing:
        flags = @[0x08.byte,0x00.byte,0x00.byte,0x00.byte]
    else:
        flags = @[0x00.byte,0x00.byte,0x00.byte,0x00.byte]
    
    let message_ID = messageID.concat(@[0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x00.byte])
    
    var process_ID = processID
    process_ID = processID.concat(@[0x00.byte,0x00.byte])

    var SMB2Header = initOrderedTable[string, seq[byte]]() # $SMB2Header = New-Object System.Collections.Specialized.OrderedDictionary

    SMB2Header.add("ProtocolID", @[0xfe.byte,0x53.byte,0x4d.byte,0x42.byte]) # $SMB2Header.Add("ProtocolID",[Byte[]](0xfe,0x53,0x4d,0x42))
    SMB2Header.add("StructureSize",@[0x40.byte, 0x00.byte]) # $SMB2Header.Add("StructureSize",[Byte[]](0x40,0x00))
    SMB2Header.add("CreditCharge",@[0x01.byte,0x00.byte]) # $SMB2Header.Add("CreditCharge",[Byte[]](0x01,0x00))
    SMB2Header.add("ChannelSequence",@[0x00.byte,0x00.byte]) # $SMB2Header.Add("ChannelSequence",[Byte[]](0x00,0x00))
    SMB2Header.add("Reserved",@[0x00.byte,0x00.byte]) # $SMB2Header.Add("Reserved",[Byte[]](0x00,0x00))
    SMB2Header.add("Command", command) # $SMB2Header.Add("Command",$Command)
    SMB2Header.add("CreditRequest", creditRequest) # $SMB2Header.Add("CreditRequest",$CreditRequest)
    SMB2Header.add("Flags", flags) # $SMB2Header.Add("Flags",$flags)
    SMB2Header.add("NextCommand",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte]) # $SMB2Header.Add("NextCommand",[Byte[]](0x00,0x00,0x00,0x00))
    SMB2Header.add("MessageID", message_ID) # $SMB2Header.Add("MessageID",$message_ID)
    SMB2Header.add("ProcessID", process_ID) # $SMB2Header.Add("ProcessID",$ProcessID)
    SMB2Header.add("TreeID", treeID) # $SMB2Header.Add("TreeID",$TreeID)
    SMB2Header.add("SessionID", sessionID) # $SMB2Header.Add("SessionID",$SessionID)
    SMB2Header.add("Signature", @[0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte]) # $SMB2Header.Add("Signature",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    return SMB2Header

proc NewPacketSMB2NegotiateProtocolRequest*(): OrderedTable[string, seq[byte]] =

    var SMB2NegotiateProtocolRequest = initOrderedTable[string, seq[byte]]() # $SMB2NegotiateProtocolRequest = New-Object System.Collections.Specialized.OrderedDictionary
    SMB2NegotiateProtocolRequest.add("StructureSize",@[0x24.byte,0x00.byte])  
    SMB2NegotiateProtocolRequest.add("DialectCount",@[0x02.byte,0x00.byte])
    SMB2NegotiateProtocolRequest.add("SecurityMode",@[0x01.byte,0x00.byte])
    SMB2NegotiateProtocolRequest.add("Reserved",@[0x00.byte,0x00.byte])
    SMB2NegotiateProtocolRequest.add("Capabilities",@[0x40.byte,0x00.byte,0x00.byte,0x00.byte])
    SMB2NegotiateProtocolRequest.add("ClientGUID",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte])
    SMB2NegotiateProtocolRequest.add("NegotiateContextOffset",@[0x00.byte,0x00.byte,0x00.byte,0x00.byte])
    SMB2NegotiateProtocolRequest.add("NegotiateContextCount",@[0x00.byte,0x00.byte])
    SMB2NegotiateProtocolRequest.add("Reserved2",@[0x00.byte,0x00.byte])
    SMB2NegotiateProtocolRequest.add("Dialect",@[0x02.byte,0x02.byte])
    SMB2NegotiateProtocolRequest.add("Dialect2",@[0x10.byte,0x02.byte])
    return SMB2NegotiateProtocolRequest

proc NewPacketNetBIOSSessionService*(headerLength, dataLength: int): OrderedTable[string, seq[byte]] =
    var NetBIOSSessionService = initOrderedTable[string, seq[byte]]() # $NetBIOSSessionService = New-Object System.Collections.Specialized.OrderedDictionary

    var length: seq[byte]
    if (headerLength + dataLength).toHex().hexToNormalHex().hexToByteArray().len == 1:
        length.add(0x00.byte)    
    length.add(0x00.byte)
    length = length.concat((headerLength + dataLength).toHex().hexToNormalHex().hexToByteArray())
    NetBIOSSessionService.add("MessageType", @[0x00.byte])
    NetBIOSSessionService.add("Length", length)
    return NetBIOSSessionService

proc getSMBv2NegoPacket*(): string =
    let 
        smb2Header = convertToByteArray NewPacketSMB2Header(@[0x00.byte,0x00.byte], @[0x00.byte,0x00.byte], false, @[messageID.byte], process_ID, tree_ID, session_ID)
        smb2Data = convertToByteArray NewPacketSMB2NegotiateProtocolRequest()
        netBiosSession = convertToByteArray NewPacketNetBIOSSessionService(smb2Header.len(), smb2Data.len())
        fullPacket = concat(netBiosSession, smb2Header, smb2Data)
    
    return buildPacket(fullPacket)

proc getSMBv2NTLMNego*(signing: bool): string =
    inc messageID
         
    var negotiate_flags: seq[byte]
    if signing:
        negotiate_flags = @[0x15.byte,0x82.byte,0x08.byte,0xa0.byte] # Signing true
    else:
        negotiate_flags = @[0x05.byte,0x80.byte,0x08.byte,0xa0.byte] # Signing false
    
    let
        smb2Header = convertToByteArray NewPacketSMB2Header(@[0x01.byte,0x00.byte], @[0x1f.byte,0x00.byte], false, @[messageID.byte], process_ID, tree_ID, session_ID)
        NTLMSSPnegotiate = convertToByteArray NewPacketNTLMSSPNegotiate(negotiate_flags, @[])
        smb2Data = convertToByteArray NewPacketSMB2SessionSetupRequest(NTLMSSPnegotiate)
        netBiosSession = convertToByteArray NewPacketNetBIOSSessionService(smb2Header.len(), smb2Data.len())
        fullPacket = concat(netBiosSession, smb2Header, smb2Data)
    
    return buildPacket(fullPacket)