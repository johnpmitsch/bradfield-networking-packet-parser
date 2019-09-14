var fs = require('fs');

fs.readFile('net.cap', (err, buffer) => {
  if (err) throw err;
  console.log(buffer);

  const globalHeaders = parseGlobalHeader(buffer);
  console.log(globalHeaders);

  const firstPacketHeaders = parsePacketHeader(buffer, 24);
  console.log(firstPacketHeaders);

  const secondPacketHeaders = parsePacketHeader(buffer, 118);
  console.log(secondPacketHeaders);
});


/**
 * Global header format according to pcap-savefile. Each row is 4 bytes, the boxes
 * in the split rows are two bytes each.
            +------------------------------+
            |        Magic number          |
            +--------------+---------------+
            |Major version | Minor version |
            +--------------+---------------+
            |      Time zone offset        |
            +------------------------------+
            |     Time stamp accuracy      |
            +------------------------------+
            |       Snapshot length        |
            +------------------------------+
            |   Link-layer header type     |
            +------------------------------+
**/
const parseGlobalHeader = (buffer) => {
  const headerSeparations = {
    magicNumber: [0,4],
    majorVersion: [4,6],
    minorVersion: [6,8],
    timeZoneOffset: [8,12],
    timeStampAccuracy: [12,16],
    snapshotLength: [16,20],
    linkLayerHeaderType: [20,24]
  }

  const parsedHeaders = {}

  for (const [headerKey, separators] of Object.entries(headerSeparations)) {
    let headerBuffer = buffer.slice(...separators)
    let byteLength = separators[1] - separators[0]

    // the magic number shouldn't be converted to an int, we can just make sure the bytes are correct
    if (headerKey === "magicNumber") {
      const magicNumber = "d4c3b2a1"
      // assert that the magic number matches the correct file type bytes
      if (headerBuffer.compare(Buffer.from(magicNumber, "hex")) !== 0) {
        console.log("File type is not correct!");
        process.exit(1);
      }
    } else {
      parsedHeaders[headerKey] = headerBuffer.readIntLE(0, byteLength)
    }
  }
  return parsedHeaders;
}


/**
 *
 * Packet header format according to pcap-savefile. Each row is 4 bytes
              +----------------------------------------------+
              |          Time stamp, seconds value           |
              +----------------------------------------------+
              |Time stamp, microseconds or nanoseconds value |
              +----------------------------------------------+
              |       Length of captured packet data         |
              +----------------------------------------------+
              |   Un-truncated length of the packet data     |
              +----------------------------------------------+
**/
const parsePacketHeader = (buffer, packetHeaderStart) => {
  const headerSeparators = {
    timeStampSeconds: [0,4],
    timeStampMicro: [4,8],
    length: [8,12],
    lengthUntruncated: [12,16]
  }

  const parsedHeaders = {}

  for (const [headerKey, separators] of Object.entries(headerSeparators)) {
    let bufferStart = packetHeaderStart + separators[0];
    let bufferEnd = packetHeaderStart + separators[1];
    let headerBuffer = buffer.slice(bufferStart, bufferEnd);
    let byteLength = separators[1] - separators[0];
    parsedHeaders[headerKey] = headerBuffer.readIntLE(0, byteLength)
  }

  return parsedHeaders;
}


// version is little endian

//int 2 bytes
//int 4 bytes
//long 8 bytes

// first 4 bytes is magic number
//
// method int32be, parse to size of data
//
// global header is 24 bytes
//
// each packet header is 4 bytes Uint32LE is size of packet
