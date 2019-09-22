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
  return buffer
    .toString("hex")
    .replace(/(.{2})/g, "$1:")
    .slice(0, -1);
};

const bufferToEthertype = buffer => {
  if (buffer.compare(Buffer.from("0800", "hex")) === 0) return "IPv4";
  if (buffer.compare(Buffer.from("0806", "hex")) === 0) return "ARP";
  if (buffer.compare(Buffer.from("86DD", "hex")) === 0) return "IPv6";
  if (buffer.compare(Buffer.from("8100", "hex")) === 0) return "IEEE 802.1Q";
};

const bufferToIp = buffer => {
  let i = 0;
  const splitBuffers = [];
  while (i < 4) {
    splitBuffers.push(buffer.slice(i, i + 1));
    i += 1;
  }
  const ipNums = splitBuffers.map(buf => buf.readUInt8());
  return ipNums.join(".");
};

function readBit(fullBuffer, bytePosition, bit) {
  return (fullBuffer[bytePosition] >> bit) % 2;
}

const getBits = (buffer, bytePosition) => {
  const bits = [...Array(8).keys()].map(num =>
    readBit(buffer, bytePosition, num)
  );

  return bits.reverse();
};

const splitByte = (buffer, bytePosition) => {
  const reversedBits = getBits(buffer, bytePosition);
  const bitOne = parseInt(reversedBits.slice(0, 4).join(""), 2);
  const bitTwo = parseInt(reversedBits.slice(4, 8).join(""), 2);
  return [bitOne, bitTwo];
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
    case "ip":
      return bufferToIp(headerBuffer);
    case "ube":
      return headerBuffer.readUIntBE(0, byteLength);
    case "do":
      return splitByte(headerBuffer, 0)[0] * 4;
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
  }
  return parsedHeaders;
};

// Ensure file is passed as input
if (!process.argv[2]) {
  console.error("No file specified as argument");
  process.exit(1);
}

const globalHeaderSeparations = {
  magicNumber: { type: "magic", separators: [0, 4] },
  majorVersion: { type: "le", separators: [4, 6] },
  minorVersion: { type: "le", separators: [6, 8] },
  timeZoneOffset: { type: "le", separators: [8, 12] },
  timeStampAccuracy: { type: "le", separators: [12, 16] },
  snapshotLength: { type: "le", separators: [16, 20] },
  linkLayerHeaderType: { type: "le", separators: [20, 24] }
};

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

const ipDatagramSeparations = {
  totalLength: { type: "be", separators: [2, 4] },
  protocol: { type: "be", separators: [9, 10] },
  sourceIp: { type: "ip", separators: [12, 16] },
  destinationIp: { type: "ip", separators: [16, 20] }
};

const tcpSeparations = {
  sourcePort: { type: "ube", separators: [0, 2] },
  destinationPort: { type: "ube", separators: [2, 4] },
  sequenceNumber: { type: "be", separators: [4, 8] },
  dataOffset: { type: "do", separators: [12, 13] }
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

const getIpDatagrams = packets => {
  const ethHeaders = packets.map(packet =>
    parseHeadersFromBuffer(packet, ethernetSeparations)
  );

  if (
    ethHeaders[0].ethertype &&
    ethHeaders.every(header => header.ethertype === ethHeaders[0].ethertype)
  ) {
    console.log(`${ethHeaders[0].ethertype} format found for all IP datagrams`);
  } else {
    console.error("All IP datagrams do not have the same format! Exiting.");
    process.exit(1);
  }

  const ipDatagrams = packets.map(packet => packet.slice(14));
  return ipDatagrams;
};

const getTcpInfo = ipDatagrams => {
  const IpHeaders = ipDatagrams.map(datagram =>
    parseHeadersFromBuffer(datagram, ipDatagramSeparations)
  );

  ipDatagrams.map((datagram, i) => {
    const [version, ihl] = splitByte(datagram, 0);
    if (version !== 4) {
      console.error("IPv4 header version is incorrect! Exiting now.");
      process.exit(1);
    }
    IpHeaders[i].headerLength = ihl * 4;
  });

  if (
    IpHeaders[0].protocol &&
    IpHeaders.every(header => header.protocol === IpHeaders[0].protocol)
  ) {
    console.log("Same protocol found for every packet");
  } else {
    console.error("All packets do not have the same protocol! Exiting.");
    process.exit(1);
  }

  return ipDatagrams.map((datagram, i) => {
    return datagram.slice(IpHeaders[i].headerLength, IpHeaders[i].totalLength);
  });
};

const getPayloads = tcpDatagrams => {
  const payloadWithHeaders = tcpDatagrams.map(tcpDatagram => {
    const headers = parseHeadersFromBuffer(tcpDatagram, tcpSeparations);
    headers.payload = tcpDatagram.slice(headers.dataOffset);
    return headers;
  });

  return payloadWithHeaders;
};

function removeDuplicates(myArr, prop) {
  return myArr.filter((obj, pos, arr) => {
    return arr.map(mapObj => mapObj[prop]).indexOf(obj[prop]) === pos;
  });
}

// Parse file
fs.readFile(process.argv[2], (err, buffer) => {
  if (err) throw err;
  const globalHeader = parseHeadersFromBuffer(buffer, globalHeaderSeparations);
  if (globalHeader.linkLayerHeaderType === 1) {
    console.log("Ethernet Link Layer Header Type detected");
  }
  const packets = getPackets(buffer);
  console.log(`${packets.length} packets found`);
  const ipDatagrams = getIpDatagrams(packets);
  const tcpDatagrams = getTcpInfo(ipDatagrams);
  const payloadWithHeaders = getPayloads(tcpDatagrams);

  const resPayloadsWithHeaders = payloadWithHeaders.filter(
    p => p.sourcePort === 80
  );

  const resPayloadsNoDups = removeDuplicates(
    resPayloadsWithHeaders,
    "sequenceNumber"
  );

  const resPayloadsSorted = resPayloadsNoDups.sort(
    (a, b) => a.sequenceNumber - b.sequenceNumber
  );
  const responsePayloads = resPayloadsSorted.map(p => p.payload);

  const combinedPayloads = Buffer.concat(responsePayloads);
  const httpHeaderSplit = combinedPayloads.indexOf("\r\n\r\n");
  // const httpHeader = combinedPayloads.slice(0, httpHeaderSplit);

  // account for 4 bytes for the splitting characters
  const imageBuffer = combinedPayloads.slice(httpHeaderSplit + 4);

  const imageFile = "parsed-image.jpg";
  fs.writeFile(imageFile, imageBuffer, "binary", e => {
    if (e) throw e;
    console.log(`Image written to ${imageFile}`);
  });
});
