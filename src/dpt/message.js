/*
    This file implements Node Discovery Protocol Version 5 as defined here:
    https://github.com/fjl/p2p-drafts/blob/master/discv5-packets.md
*/
const ip = require('ip')
const rlp = require('rlp-encoding')
const secp256k1 = require('secp256k1')
const Buffer = require('safe-buffer').Buffer
const { keccak256, int2buffer, buffer2int, assertEq } = require('../util')
const { hexToDec } = require('hex2dec')
const base64url = require('base64url')
const createDebugLogger = require('debug')

const debug = createDebugLogger('devp2p:dpt:message')

function getTimestamp () {
  return (Date.now() / 1000) | 0
}

const timestamp = {
  encode: function (value = getTimestamp() + 60) {
    const buffer = Buffer.allocUnsafe(4)
    buffer.writeUInt32BE(value)
    return buffer
  },
  decode: function (buffer) {
    if (buffer.length > 4) {
      return (hexToDec(buffer.toString('hex')) / 1000) | 0
    } else if (buffer.length < 4) {
      throw new RangeError(
        `Invalid timestamp buffer :${buffer.toString('hex')}`
      )
    }
    return buffer.readUInt32BE(0)
  }
}

const address = {
  encode: function (value) {
    if (ip.isV4Format(value)) return ip.toBuffer(value)
    if (ip.isV6Format(value)) return ip.toBuffer(value)
    throw new Error(`Invalid address: ${value}`)
  },
  decode: function (buffer) {
    if (buffer.length === 4) return ip.toString(buffer)
    if (buffer.length === 16) return ip.toString(buffer)

    const str = buffer.toString()
    if (ip.isV4Format(str) || ip.isV6Format(str)) return str

    // also can be host, but skip it right now (because need async function for resolve)
    throw new Error(`Invalid address buffer: ${buffer.toString('hex')}`)
  }
}

const port = {
  encode: function (value) {
    if (value === null) return Buffer.allocUnsafe(0)
    if (value >>> 16 > 0) throw new RangeError(`Invalid port: ${value}`)
    return Buffer.from([(value >>> 8) & 0xff, (value >>> 0) & 0xff])
  },
  decode: function (buffer) {
    if (buffer.length === 0) return null
    // if (buffer.length !== 2) throw new RangeError(`Invalid port buffer: ${buffer.toString('hex')}`)
    return buffer2int(buffer)
  }
}

const endpoint = {
  encode: function (obj) {
    return [
      address.encode(obj.address),
      port.encode(obj.udpPort),
      port.encode(obj.tcpPort)
    ]
  },
  decode: function (payload) {
    return {
      address: address.decode(payload[0]),
      udpPort: port.decode(payload[1]),
      tcpPort: port.decode(payload[2])
    }
  }
}

const extra = {
  decode: function (payload) {
    // debug(payload)
    var res
    if (typeof payload === 'object') {
      switch (payload.constructor.name) {
        case 'Buffer':
          res = payload.toString('hex')
          break
        case 'Array':
          if (payload[0].constructor.name === 'Array') {
            if (payload[0][1]) {
              if (payload[0][1].toString() === '') {
                // eth
                res = [ payload[0].map(ele => ele.toString('hex')) ]
              } else {
                // cap
                res = payload.map(x => [ x[0].toString(), hexToDec(x[1].toString('hex')) ] )
              }
            } else {
              debug(payload[0])
            }
          } else {
            res = payload.map(ele => ele.toString('hex'))
          }
          break
        default:
      }
    } else {
      res = payload
    }
    return res
  }
}

const enr = {
  encode: function (obj) {
    /*
      content   = rlp.encode([seq, k, v, ...])
      signature = sign(content)
      record    = rlp.encode([signature, seq, k, v, ...])
    */
    var content = [obj.content.seq, 'eth', [ obj.content.forkid ] , 'id', obj.content.id]
    if (obj.content.id == 'v4') {
      content = content.concat(['ip', address.encode(obj.ip), 'secp256k1', obj.secp256k1, 'udp', port.encode(obj.udp)])
    } else {
      // deal with other possible ID schemes in the future
    }
    const sighash = keccak256(rlp.encode(content))
    const sig = secp256k1.sign(sighash, obj.privateKey)
    const record = [sig.signature, ...content]
    return record
  },
  decode: function (payload) {
    if (payload.length > 300) {
      throw new RangeError(`ENR record too large. Maximum record size is 300`)
    }
    const signature = payload[0]
    const content = rlp.encode(payload.slice(1))
    const seq = payload[1]
    const pairs = payload.slice(2).reduce((acc, ele, i, arr) => {
      if (i % 2 === 0) {
        acc[ele] = arr[i+1]
      }
      return acc
    }, {})

    // confirm v4 ID scheme
    if (!pairs.id) {
      throw new Error(`Invalid ENR, no identity scheme provided`)
    }
    const id = Buffer.from(pairs.id).toString()

    if (id == 'v4') {
      debug('ENR uses v4 identity scheme. Verifying...')

      if (secp256k1.verify(keccak256(content), signature, pairs.secp256k1)) {
        debug('Verified ENR successfully. Parsing...')
        var record = {
          id: id,
          secp256k1: pairs.secp256k1.toString('hex')
        }
        pairs.ip ? Object.assign(record, {ip: address.decode(pairs.ip) }) : debug('ENR Decoding: No "ip" field found in ENR')
        pairs.udp ? Object.assign(record, {udp: port.decode(pairs.udp) }) : debug('ENR Decoding: No "udp" field found in ENR')
        pairs.tcp ? Object.assign(record, {tcp: port.decode(pairs.tcp) }) : debug('ENR Decoding: No "tcp" field found in ENR')
        pairs.cap ? Object.assign(record, {cap: extra.decode(pairs.cap) }) : debug('ENR Decoding: No "cap" field found in ENR')
        pairs.eth ? Object.assign(record, {eth: extra.decode(pairs.eth) }) : debug('ENR Decoding: No "eth" field found in ENR')

        return {
          record: record,
          pairs: pairs
        }
      }
    } else {
      throw new Error(`Unrecognized identity scheme provided: ${id}`)
    }

    return {
      record: payload,
      pairs: pairs
    }
  }
}

const ping = {
  encode: function (obj) {
    return [
      int2buffer(obj.version),
      endpoint.encode(obj.from),
      endpoint.encode(obj.to),
      timestamp.encode(obj.timestamp),
      obj.seq
    ]

    // message = _pack(CMD_PING.id, payload, self.privkey)
    // self.send(node, message)
    // # Return the msg hash, which is used as a token to identify pongs.
    //   return message[:MAC_SIZE]
  },
  decode: function (payload) {
    return {
      version: buffer2int(payload[0]),
      from: endpoint.decode(payload[1]),
      to: endpoint.decode(payload[2]),
      timestamp: timestamp.decode(payload[3]),
      seq: payload[4]
    }
  }
}

const pong = {
  encode: function (obj) {
    return [endpoint.encode(obj.to), obj.hash, timestamp.encode(obj.timestamp), obj.seq]
  },
  decode: function (payload) {
    return {
      to: endpoint.decode(payload[0]),
      hash: payload[1],
      timestamp: timestamp.decode(payload[2]),
      seq: payload[3]
    }
  }
}

const findNode = {
  encode: function (obj) {
    return [obj.id, timestamp.encode(obj.timestamp)]
  },
  decode: function (payload) {
    return {
      id: payload[0],
      timestamp: timestamp.decode(payload[1])
    }
  }
}

const neighbors = {
  encode: function (obj) {
    return [
      obj.peers.map(peer => endpoint.encode(peer).concat(peer.id)),
      timestamp.encode(obj.timestamp)
    ]
  },
  decode: function (payload) {
    return {
      peers: payload[0].map(data => {
        return { endpoint: endpoint.decode(data), id: data[3] } // hack for id
      }),
      timestamp: timestamp.decode(payload[1])
    }
  }
}

const enrRequest = {
  encode: function (obj) {
    const expiration = timestamp.encode(obj.timestamp)
    // debug(`Encoding ENR request: ${timestamp.decode(expiration)}`)
    return [expiration]
  },
  decode: function (payload) {
    const expiration = timestamp.decode(payload[0])
    // debug(`Decoding ENR request: ${expiration}`)
    return { timestamp: expiration }
  }
}

const enrResponse = {
  encode: function (obj) {
    debug(`Encoding ENR response with hash ${obj.hash.toString('hex')}:`)
    const record = enr.encode(obj.enr)
    debug(`Produced enr:${base64url(rlp.encode(record))}`)
    const res = [obj.hash, record]
    return res
  },
  decode: function (payload) {
    debug(`Decoding ENR response with hash ${payload[0].toString('hex')}`)
    return {
      hash: payload[0],
      enr: enr.decode(payload[1])
    }
  }
}

const messages = { ping, pong, findNode, neighbors, enrRequest, enrResponse }

const types = {
  byName: {
    ping: 0x01,
    pong: 0x02,
    findNode: 0x03,
    neighbors: 0x04,
    enrRequest: 0x05,
    enrResponse: 0x06
  },
  byType: {
    0x01: 'ping',
    0x02: 'pong',
    0x03: 'findNode',
    0x04: 'neighbors',
    0x05: 'enrRequest',
    0x06: 'enrResponse'
  }
}

// [0, 32) data hash
// [32, 96) signature
// 96 recoveryId
// 97 type
// [98, length) data

function encode (typename, data, privateKey) {
  const type = types.byName[typename]
  if (type === undefined) throw new Error(`Invalid typename: ${typename}`)
  const encodedMsg = messages[typename].encode(data)
  const typedata = Buffer.concat([Buffer.from([type]), rlp.encode(encodedMsg)])

  const sighash = keccak256(typedata)
  const sig = secp256k1.sign(sighash, privateKey)
  const hashdata = Buffer.concat([
    sig.signature,
    Buffer.from([sig.recovery]),
    typedata
  ])
  const hash = keccak256(hashdata)
  return Buffer.concat([hash, hashdata])
}

function decode (buffer) {
  const hash = keccak256(buffer.slice(32))
  assertEq(buffer.slice(0, 32), hash, 'Hash verification failed')

  const typedata = buffer.slice(97)
  const type = typedata[0]
  const typename = types.byType[type]
  if (typename === undefined) throw new Error(`Invalid type: ${type}`)
  const data = messages[typename].decode(rlp.decode(typedata.slice(1)))

  const sighash = keccak256(typedata)
  const signature = buffer.slice(32, 96)
  const recoverId = buffer[96]
  const publicKey = secp256k1.recover(sighash, signature, recoverId, false)

  return { typename, data, publicKey }
}

module.exports = { encode, decode }
