"""

Packet handling functionality for Empire.

Defines packet types, builds tasking packets and parses result packets.

Packet format:

RC4s = RC4 encrypted with the shared staging key
HMACs = SHA1 HMAC using the shared staging key
AESc = AES encrypted using the client's session key
HMACc = first 10 bytes of a SHA256 HMAC using the client's session key

    Routing Packet:
    +---------+-------------------+--------------------------+
    | RC4 IV  | RC4s(RoutingData) | AESc(client packet data) | ...
    +---------+-------------------+--------------------------+
    |    4    |         16        |        RC4 length        |
    +---------+-------------------+--------------------------+

    RC4s(RoutingData):
    +-----------+------+------+-------+--------+
    | SessionID | Lang | Meta | Extra | Length |
    +-----------+------+------+-------+--------+
    |    8      |  1   |  1   |   2   |    4   |
    +-----------+------+------+-------+--------+

    SessionID = the sessionID that the packet is bound for
    Lang = indicates the language used
    Meta = indicates staging req/tasking req/result post/etc.
    Extra = reserved for future expansion


    AESc(client data)
    +--------+-----------------+-------+
    | AES IV | Enc Packet Data | HMACc |
    +--------+-----------------+-------+
    |   16   |   % 16 bytes    |  10   |
    +--------+-----------------+-------+

    Client data decrypted:
    +------+--------+--------------------+----------+---------+-----------+
    | Type | Length | total # of packets | packet # | task ID | task data |
    +------+--------+--------------------+--------------------+-----------+
    |  2   |   4    |         2          |    2     |    2    | <Length>  |
    +------+--------+--------------------+----------+---------+-----------+

    type = packet type
    total # of packets = number of total packets in the transmission
    Packet # = where the packet fits in the transmission
    Task ID = links the tasking to results for deconflict on server side


    Client *_SAVE packets have the sub format:

            [15 chars] - save prefix
            [5 chars]  - extension
            [X...]     - tasking data

"""

import base64
import logging
import os
import struct
import sys

from . import encryption

log = logging.getLogger(__name__)


# 0         -> error
# 1-99      -> standard functionality
# 100-199   -> dynamic functionality
# 200-299   -> SMB functionality

PACKET_NAMES = {
    # Agent Commands
    "ERROR": 0,
    "TASK_SYSINFO": 1,
    "TASK_EXIT": 2,
    # Comm Channel
    "TASK_SET_DELAY": 10,
    "TASK_GET_DELAY": 12,
    "TASK_SET_SERVERS": 13,
    "TASK_ADD_SERVERS": 14,
    "TASK_UPDATE_PROFILE": 20,
    "TASK_SET_KILLDATE": 30,
    "TASK_GET_KILLDATE": 31,
    "TASK_SET_WORKING_HOURS": 32,
    "TASK_GET_WORKING_HOURS": 33,
    "TASK_SET_PROXY": 34,
    # Empire Commands
    "TASK_SHELL": 40,
    "TASK_DOWNLOAD": 41,
    "TASK_UPLOAD": 42,
    "TASK_DIR_LIST": 43,
    "TASK_CSHARP": 44,  # todo: move to 116/117
    "TASK_GETJOBS": 50,
    "TASK_STOPJOB": 51,
    "TASK_SOCKS": 60,
    "TASK_SOCKS_DATA": 61,
    "TASK_SMB_SERVER": 70,
    # Agent Module Commands
    "TASK_CMD_WAIT": 100,
    "TASK_CMD_WAIT_SAVE": 101,
    "TASK_CMD_JOB": 110,
    "TASK_CMD_JOB_SAVE": 111,
    "TASK_POWERSHELL_CMD_JOB": 112,
    "TASK_POWERSHELL_CMD_JOB_SAVE": 113,
    "TASK_PYTHON_CMD_JOB": 114,
    "TASK_PYTHON_CMD_JOB_SAVE": 115,
    "TASK_CSHARP_CMD_JOB": 116,
    "TASK_CSHARP_CMD_JOB_SAVE": 117,
    "TASK_POWERSHELL_CMD_WAIT": 118,
    "TASK_POWERSHELL_CMD_WAIT_SAVE": 119,
    # Module/Script Imports
    "TASK_SCRIPT_IMPORT": 120,
    "TASK_SCRIPT_COMMAND": 121,
    "TASK_IMPORT_MODULE": 122,
    "TASK_VIEW_MODULE": 123,
    "TASK_REMOVE_MODULE": 124,
    # Listener Options
    "TASK_SWITCH_LISTENER": 130,
    "TASK_UPDATE_LISTENERNAME": 131,
}

# build a lookup table for IDS
PACKET_IDS = {}
for name, ID in list(PACKET_NAMES.items()):
    PACKET_IDS[ID] = name

LANGUAGE = {
    "NONE": 0,
    "POWERSHELL": 1,
    "PYTHON": 2,
    "CSHARP": 3,
}
LANGUAGE_IDS = {}
for name, ID in list(LANGUAGE.items()):
    LANGUAGE_IDS[ID] = name

META = {
    "NONE": 0,
    "STAGE0": 1,
    "STAGE1": 2,
    "STAGE2": 3,
    "TASKING_REQUEST": 4,
    "RESULT_POST": 5,
    "SERVER_RESPONSE": 6,
}
META_IDS = {}
for name, ID in list(META.items()):
    META_IDS[ID] = name

ADDITIONAL = {}
ADDITIONAL_IDS = {}
for name, ID in list(ADDITIONAL.items()):
    ADDITIONAL_IDS[ID] = name


def build_task_packet(taskName, data, resultID):
    """
    Build a task packet for an agent.

        [2 bytes] - type
        [2 bytes] - total # of packets
        [2 bytes] - packet #
        [2 bytes] - task/result ID
        [4 bytes] - length
        [X...]    - result data

        +------+--------------------+----------+---------+--------+-----------+
        | Type | total # of packets | packet # | task ID | Length | task data |
        +------+--------------------+--------------------+--------+-----------+
        |  2   |         2          |    2     |    2    |   4    | <Length>  |
        +------+--------------------+----------+---------+--------+-----------+
    """

    taskType = struct.pack("=H", PACKET_NAMES[taskName])
    totalPacket = struct.pack("=H", 1)
    packetNum = struct.pack("=H", 1)
    resultID = struct.pack("=H", resultID)
    length = struct.pack("=L", len(data.encode("UTF-8")))
    return taskType + totalPacket + packetNum + resultID + length + data.encode("UTF-8")


def parse_result_packet(packet, offset=0):
    """
    Parse a result packet-

        [2 bytes] - type
        [2 bytes] - total # of packets
        [2 bytes] - packet #
        [2 bytes] - task/result ID
        [4 bytes] - length
        [X...]    - result data

        +------+--------------------+----------+---------+--------+-----------+
        | Type | total # of packets | packet # | task ID | Length | task data |
        +------+--------------------+--------------------+--------+-----------+
        |  2   |         2          |    2     |    2    |   4    | <Length>  |
        +------+--------------------+----------+---------+--------+-----------+

    Returns a tuple with (responseName, length, data, remainingData)

    Returns a tuple with (responseName, totalPackets, packetNum, taskID, length, data, remainingData)
    """

    try:
        responseID = struct.unpack("=H", packet[0 + offset : 2 + offset])[0]
        totalPacket = struct.unpack("=H", packet[2 + offset : 4 + offset])[0]
        packetNum = struct.unpack("=H", packet[4 + offset : 6 + offset])[0]
        taskID = struct.unpack("=H", packet[6 + offset : 8 + offset])[0]
        length = struct.unpack("=L", packet[8 + offset : 12 + offset])[0]
        if length != "0":
            data = base64.b64decode(packet[12 + offset : 12 + offset + length])
        else:
            data = None
        remainingData = packet[12 + offset + length :]

        # todo: agent returns resultpacket in big endian instead of little for type 44 with outpipe in powershell.
        # This should be fixed and removed at some point.
        if responseID == 10240:  # noqa: PLR2004
            responseID = int.from_bytes(
                packet[0 + offset : 2 + offset], byteorder="big"
            )
            totalPacket = int.from_bytes(
                packet[2 + offset : 4 + offset], byteorder="big"
            )
            packetNum = int.from_bytes(packet[4 + offset : 6 + offset], byteorder="big")
            taskID = int.from_bytes(packet[6 + offset : 8 + offset], byteorder="big")
            length = int.from_bytes(packet[8 + offset : 12 + offset], byteorder="big")
        return (
            PACKET_IDS[responseID],
            totalPacket,
            packetNum,
            taskID,
            length,
            data,
            remainingData,
        )

    except Exception as e:
        message = f"parse_result_packet(): exception: {e}"
        log.error(message, exc_info=True)
        return (None, None, None, None, None, None, None)


def parse_result_packets(packets):
    """
    Parse a blob of one or more result packets
    """

    resultPackets = []

    # parse the first result packet
    (
        responseName,
        totalPacket,
        packetNum,
        taskID,
        length,
        data,
        remainingData,
    ) = parse_result_packet(packets)

    if responseName and responseName != "":
        resultPackets.append(
            (responseName, totalPacket, packetNum, taskID, length, data)
        )

    # iterate 12 (size of packet header) + length of the decoded
    offset = 12 + length
    while remainingData and remainingData != "":
        # parse any additional result packets
        # (responseName, length, data, remainingData) = parse_result_packet(packets, offset=offset)
        (
            responseName,
            totalPacket,
            packetNum,
            taskID,
            length,
            data,
            remainingData,
        ) = parse_result_packet(packets, offset=offset)
        if responseName and responseName != "":
            resultPackets.append(
                (responseName, totalPacket, packetNum, taskID, length, data)
            )
        offset += 12 + length

    return resultPackets


def parse_routing_packet(stagingKey, data):
    """
    Decodes the rc4 "routing packet" and parses raw agent data into:

        {sessionID : (language, meta, additional, [encData]), ...}


    Routing packet format:

        +---------+-------------------+--------------------------+
        | RC4 IV  | RC4s(RoutingData) | AESc(client packet data) | ...
        +---------+-------------------+--------------------------+
        |    4    |         16        |        RC4 length        |
        +---------+-------------------+--------------------------+

        RC4s(RoutingData):
        +-----------+------+------+-------+--------+
        | SessionID | Lang | Meta | Extra | Length |
        +-----------+------+------+-------+--------+
        |    8      |  1   |  1   |   2   |    4   |
        +-----------+------+------+-------+--------+

    """

    if not data:
        message = "parse_agent_data() data is None"
        log.warning(message)
        return None

    results = {}
    offset = 0

    # ensure we have at least the 20 bytes for a routing packet
    if len(data) < 20:  # noqa: PLR2004
        message = f"parse_agent_data() data length incorrect: {len(data)}"
        log.warning(message)
        return None

    while True:
        if len(data) - offset < 20:  # noqa: PLR2004
            break

        RC4IV = data[0 + offset : 4 + offset]
        RC4data = data[4 + offset : 20 + offset]

        routingPacket = encryption.rc4(RC4IV + stagingKey.encode("UTF-8"), RC4data)
        try:
            sessionID = routingPacket[0:8].decode("UTF-8")
        except Exception:
            sessionID = routingPacket[0:8].decode("latin-1")

        # B == 1 byte unsigned char, H == 2 byte unsigned short, L == 4 byte unsigned long
        (language, meta, additional, length) = struct.unpack("=BBHL", routingPacket[8:])
        if length < 0:
            message = "parse_agent_data(): length in decoded rc4 packet is < 0"
            log.warning(message)
            encData = None
        else:
            encData = data[(20 + offset) : (20 + offset + length)]

        results[sessionID] = (
            LANGUAGE_IDS.get(language, "NONE"),
            META_IDS.get(meta, "NONE"),
            ADDITIONAL_IDS.get(additional, "NONE"),
            encData,
        )

        # check if we're at the end of the packet processing
        remainingData = data[20 + offset + length :]
        if not remainingData or remainingData == "":
            break

        offset += 20 + length
    return results


def build_routing_packet(  # noqa: PLR0913
    stagingKey, sessionID, language, meta="NONE", additional="NONE", encData=""
):
    """
    Takes the specified parameters for an RC4 "routing packet" and builds/returns
    an HMAC'ed RC4 "routing packet".

    packet format:

        Routing Packet:
        +---------+-------------------+--------------------------+
        | RC4 IV  | RC4s(RoutingData) | AESc(client packet data) | ...
        +---------+-------------------+--------------------------+
        |    4    |         16        |        RC4 length        |
        +---------+-------------------+--------------------------+

        RC4s(RoutingData):
        +-----------+------+------+-------+--------+
        | SessionID | Lang | Meta | Extra | Length |
        +-----------+------+------+-------+--------+
        |    8      |  1   |  1   |   2   |    4   |
        +-----------+------+------+-------+--------+

    """
    # binary pack all of the pcassed config values as unsigned numbers
    #   B == 1 byte unsigned char, H == 2 byte unsigned short, L == 4 byte unsigned long
    sessionID = sessionID.encode("UTF-8")
    data = sessionID + struct.pack(
        "=BBHL",
        LANGUAGE.get(language.upper(), 0),
        META.get(meta.upper(), 0),
        ADDITIONAL.get(additional.upper(), 0),
        len(encData),
    )
    RC4IV = os.urandom(4)
    stagingKey = stagingKey.encode("UTF-8")
    key = RC4IV + stagingKey
    rc4EncData = encryption.rc4(key, data)
    # return an rc4 encyption of the routing packet, append an HMAC of the packet, then the actual encrypted data
    if isinstance(encData, str) and sys.version[0] != "2":
        encData = encData.encode("Latin-1")

    return RC4IV + rc4EncData + encData


def resolve_id(PacketID):
    """
    Resolve a packet ID to its key.
    """
    try:
        return PACKET_IDS[int(PacketID)]
    except Exception:
        return PACKET_IDS[0]
