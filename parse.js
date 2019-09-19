const fs = require("fs");

const checkMagicNumber = buffer => {
  const magicNumber = "d4c3b2a1";
  // assert that the magic number matches the correct file type bytes
  if (buffer.compare(Buffer.from(magicNumber, "hex")) !== 0) {
    console.error("File type is not correct!");
    process.exit(1);
  }
};

const bufferToMac = buffer => {
  return buffer.toString("hex").replace(/(.{2})/g, "$1:");
};

const bufferToEthertype = buffer => {
  if (buffer.compare(Buffer.from("0800", "hex")) === 0) return "IPv4";
  if (buffer.compare(Buffer.from("0806", "hex")) === 0) return "ARP";
  if (buffer.compare(Buffer.from("86DD", "hex")) === 0) return "IPv6";
  if (buffer.compare(Buffer.from("8100", "hex")) === 0) return "IEEE 802.1Q";
};

const getHeaderValue = (type, headerBuffer, byteLength) => {
  switch (type) {
    case "magicNumber":
      return checkMagicNumber(headerBuffer);
    case "le":
      return headerBuffer.readIntLE(0, byteLength);
    case "be":
      return headerBuffer.readIntBE(0, byteLength);
    case "mac":
      return bufferToMac(headerBuffer);
    case "ethertype":
      return bufferToEthertype(headerBuffer);
    default:
      return headerBuffer;
  }
};

const parseHeadersFromBuffer = (buffer, headerSeparations, offset = 0) => {
  const parsedHeaders = {};

  for (const [headerKey, { type, separators }] of Object.entries(
    headerSeparations
  )) {
    const bufferStart = offset + separators[0];
    const bufferEnd = offset + separators[1];
    const headerBuffer = buffer.slice(bufferStart, bufferEnd);
    const byteLength = separators[1] - separators[0];

    parsedHeaders[headerKey] = getHeaderValue(type, headerBuffer, byteLength);
    // the magic number shouldn't be converted to an int, we can just make sure the bytes are correct
  }
  return parsedHeaders;
};

// Ensure file is passed as input
if (!process.argv[2]) {
  console.error("No file specified as argument");
  process.exit(1);
}

/**
 *  Global header format according to pcap-savefile. Each row is 4 bytes, the boxes
 *  in the split rows are two bytes each.
 *            +------------------------------+
 *            |        Magic number          |
 *            +--------------+---------------+
 *            |Major version | Minor version |
 *            +--------------+---------------+
 *            |      Time zone offset        |
 *            +------------------------------+
 *            |     Time stamp accuracy      |
 *            +------------------------------+
 *            |       Snapshot length        |
 *            +------------------------------+
 *            |   Link-layer header type     |
 *            +------------------------------+
 *
 * */
const globalHeaderSeparations = {
  magicNumber: { type: "magic", separators: [0, 4] },
  majorVersion: { type: "le", separators: [4, 6] },
  minorVersion: { type: "le", separators: [6, 8] },
  timeZoneOffset: { type: "le", separators: [8, 12] },
  timeStampAccuracy: { type: "le", separators: [12, 16] },
  snapshotLength: { type: "le", separators: [16, 20] },
  linkLayerHeaderType: { type: "le", separators: [20, 24] }
};

/* *  Packet header format according to pcap-savefile. Each row is 4 bytes
 *              +----------------------------------------------+
 *              |          Time stamp, seconds value           |
 *              +----------------------------------------------+
 *              |Time stamp, microseconds or nanoseconds value |
 *              +----------------------------------------------+
 *              |       Length of captured packet data         |
 *              +----------------------------------------------+
 *              |   Un-truncated length of the packet data     |
 *              +----------------------------------------------+
 * */
const packetHeaderSeparations = {
  timeStampSeconds: { type: "le", separators: [0, 4] },
  timeStampMicro: { type: "le", separators: [4, 8] },
  capturedLength: { type: "le", separators: [8, 12] },
  untruncatedlength: { type: "le", separators: [12, 16] }
};

const ethernetSeparations = {
  macDestination: { type: "mac", separators: [0, 6] },
  macSource: { type: "mac", separators: [6, 12] },
  ethertype: { type: "ethertype", separators: [12, 14] }
};

const getPackets = buffer => {
  const globalHeaderLength = 24;
  const packetHeaderLength = 16;

  let position = globalHeaderLength;

  const packets = [];

  while (position < buffer.length) {
    const packetHeader = parseHeadersFromBuffer(
      buffer,
      packetHeaderSeparations,
      position
    );

    if (packetHeader.capturedLength !== packetHeader.untruncatedlength) {
      console.error(
        `Packet Length ${packetHeader.capturedLength} is not the same as the untruncated length ${packetHeader.untruncatedlength}`
      );
      process.exit(1);
    }

    const packetBodyStart = position + packetHeaderLength;
    position += packetHeaderLength + packetHeader.capturedLength;
    packets.push(buffer.slice(packetBodyStart, position));
  }

  return packets;
};

// Parse file
fs.readFile(process.argv[2], (err, buffer) => {
  if (err) throw err;
  const globalHeader = parseHeadersFromBuffer(buffer, globalHeaderSeparations);

  if (globalHeader.linkLayerHeaderType === 1) {
    console.log("Ethernet Link Layer Header Type detected");
  }

  const packets = getPackets(buffer);

  const ethHeaders = packets.map(packet =>
    parseHeadersFromBuffer(packet, ethernetSeparations)
  );

  if (
    ethHeaders.every(header => header.etherType === ethHeaders[0].etherType)
  ) {
    console.log("All IP datagrams have the same format");
  } else {
    console.error("All IP datagrams do not have the same format! Exiting.");
    process.exit(1);
  }

  if (
    ethHeaders.every(
      header => header.macDestination === ethHeaders[0].macDestination
    ) &&
    ethHeaders.every(header => header.macSource === ethHeaders[0].macSource)
  ) {
    console.log(
      "All IP datagrams have the same source and destination MAC addresses"
    );
    console.log(`Source MAC: ${ethHeaders[0].macSource}`);
    console.log(`Destination MAC: ${ethHeaders[0].macDestination}`);
  }

  console.log(`${packets.length} packets parsed`);
});
