#[
    HelpUtil
]#

import tables, strutils, regex, sequtils, algorithm, net, terminal, os

type
    STATUS* = enum
        Error, Success, Info

proc checkSigning*(data: seq[string]): bool =
    if data[70] == "03":
        result = true 

proc checkDialect*(data: seq[string]): string =
    if data[4..7] == @["FF", "53", "4D", "42"]:
        result = "SMB1"
    else:
        result = "SMB2"

proc hexToNormalHexArray*(hex: string): seq[string] =
    var a = findAndCaptureAll(hex, re"..")
    for b in a:
        if b != "00":
            result.add(b)

proc getBytes*(val: int): seq[byte] =
    var hexed = val.toHex().hexToNormalHexArray()
    if hexed.len == 0:
        hexed = @["00"]
    if hexed.len > 1:
        result.add(hexed[1].parseHexInt().byte)
    result.add(hexed[0].parseHexInt().byte)
    if result.len() < 2:
        result.add(0x00.byte)
    result.concat(@[0x00.byte,0x00.byte])

proc hexToPSShellcode*(hex: string): string =
    var a = findAndCaptureAll(hex, re"..")
    result = "0x" & a.join(",0x")

proc convertToByteArray*(tab: OrderedTable): seq[byte] =
    for v in tab.values:
        result.add(v)

proc GetUInt16DataLength*(start: int, data: seq[byte]): int =
    let data_length = ($(data[start])).parseInt()

    return data_length

proc unicodeGetBytes*(str: string): seq[byte] =
    for i in str.toHex().hexToPSShellcode().split(","):
        result.add(i.parseHexInt().byte)
        result.add(0x00.byte)

proc stringToByteArray*(str: string): seq[byte] =
    for i in str.toHex().hexToPSShellcode().split(","):
        result.add(i.parseHexInt().byte)

proc hexToByteArray*(str: string): seq[byte] =
    for i in str.hexToPSShellcode().split(","):
        result.add(i.parseHexInt().byte)

proc hexToNormalHex*(hex: string): string =
    var a = findAndCaptureAll(hex, re"..")
    for b in a:
        if b != "00":
            result.add(b)

proc pidToByteArray*(pid: int): seq[byte] =
    result = pid.toHex().hexToNormalHex().hexToByteArray().reversed()

proc byteArrayToString*(arr: seq[byte]): string =
    for i in arr:
        result.add(i.toHex().hexToNormalHex())

proc getStatusPending*(Status: seq[string]): bool =
    if Status == @["03", "01", "00", "00"]:
        result = true

proc recvPacket*(socket: Socket, bufSize, timeout = 500): seq[string] =
    var buf: string
    try:
        while socket.recv(buf, 1, timeout) > 0:
            result.add(buf.toHex())
    except:
        discard

proc recvPacketForNTLM*(socket: Socket, bufSize, timeout = 500): string =
    var buf: string
    try:
        while socket.recv(buf, 1, timeout) > 0:
            result.add(buf)
    except:
        discard

proc buildPacket*(bytePacket: seq[byte]): string =
    for b in bytePacket:
        result &= b.toHex()
    result.parseHexStr()

proc seqHexToNumber*(res: seq[string]): int =
    var temp = res
    temp.reverse
    result = temp.join("").parseHexInt()

proc byteArrayToNumber*(res: openArray[byte]): int =
    var temp: seq[byte]
    for b in res:
        temp.add(b)
    reverse(temp)
    return temp.byteArrayToString().parseHexInt()

#[
    Globals
]#
var 
    session_ID*: seq[byte] = @[0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte,0x00.byte]
    process_ID*: seq[byte] = pidToByteArray(getCurrentProcessId())
    tree_ID*: seq[byte] = @[0x00.byte,0x00.byte,0x00.byte,0x00.byte]
    signing*: bool
    messageID* = 1

#[
    Parse Windows version from response
]#
proc parseWindowsVersion*(response: seq[string]): string =
    var data = response.join("").parseHexStr().split('\0').join("")
    result &= "Windows"
    result &= data.split("Windows")[1]
    result &= " (Windows"
    result &= data.split("Windows")[2]
    result &= ")"

#[
    Prints nice and all
]#
proc printC*(stat: STATUS, text: string) = 
    case stat
    of Error:
        stdout.styledWrite(fgRed, "[-] ")
    of Success:
        stdout.styledWrite(fgGreen, "[+] ")
    of Info:
        stdout.styledWrite(fgYellow, "[*] ")
    echo text
