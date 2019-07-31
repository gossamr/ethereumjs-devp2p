const { EventEmitter } = require('events')
const dgram = require('dgram')
const ms = require('ms')
const createDebugLogger = require('debug')
const LRUCache = require('lru-cache')
const Buffer = require('safe-buffer').Buffer
const message = require('./message')
const secp256k1 = require('secp256k1')
const { keccak256, pk2id, createDeferred, v4, v5 } = require('../util')
const chalk = require('chalk')
const sleep = require('util').promisify(setTimeout);

const debug = createDebugLogger('devp2p:dpt:server')
const logPing = createDebugLogger('devp2p:dpt:server:ping')
const logNeighbors = createDebugLogger('devp2p:dpt:server:neighbors')
const logENR = createDebugLogger('devp2p:dpt:server:enr')
const logError = createDebugLogger('devp2p:dpt:server:error')
const logBond = createDebugLogger('devp2p:dpt:server:bond')

const createSocketUDP4 = dgram.createSocket.bind(null, 'udp4')


class Server extends EventEmitter {
  constructor (dpt, privateKey, options) {
    super()

    this._dpt = dpt
    this._privateKey = privateKey
    this._pubKey = secp256k1.publicKeyCreate(privateKey)
    this._enrSequence = Buffer.from('01', 'hex')

    // Main net St. Petersburg. TODO update next fork
    const forkid = (options.forkid) ? options.forkid : '668db0af'
    this._forkid = [ Buffer.from(forkid,'hex'), Buffer.from('') ]

    this._version = (options.version === '5') ? v5 : v4

    console.log(chalk.green(`Starting node discovery protocol with version ${
      this._version} at enode://${
      Buffer.from(pk2id(this._pubKey)).toString('hex')}@${
      options.endpoint.address}:${options.endpoint.udpPort}`))

    this._lastPongReceived = new LRUCache({
      maxAge: ms('1d'),
      stale: false
    })

    this._lastPingReceived = new LRUCache({
      maxAge: ms('1d'),
      stale: false
    })

    this._timeout = options.timeout || ms('10s')
    this._endpoint = options.endpoint || {
      address: '0.0.0.0',
      udpPort: null,
      tcpPort: null
    }
    this._requests = new Map()
    this._parityRequestMap = new Map()
    this._requestsCache = new LRUCache({
      max: 1000,
      maxAge: ms('1s'),
      stale: false
    })

    const createSocket = options.createSocket || createSocketUDP4
    this._socket = createSocket()
    this._socket.once('listening', () => this.emit('listening'))
    this._socket.once('close', () => this.emit('close'))
    this._socket.on('error', err => this.emit('error', err))

    this._socket.on('message', (msg, rinfo) => {
      try {
        this._handler(msg, rinfo)
      } catch (err) {
        this.emit('error', err)
      }
    })
  }

  bind (...args) {
    this._isAliveCheck()
    debug('call .bind')

    this._socket.bind(...args)
  }

  destroy (...args) {
    this._isAliveCheck()
    debug('call .destroy')

    this._socket.close(...args)
    this._socket = null
  }

  async ping (peer) {
    this._isAliveCheck()

    // prevent dupe requests within 1 sec
    const rckey = `ping:${peer.address}:${peer.udpPort}`
    const promise = this._requestsCache.get(rckey)
    if (promise !== undefined) return promise

    const hash = this._send(peer, 'ping', {
      version: this._version,
      from: this._endpoint,
      to: peer,
      seq: this._enrSequence
    })

    const deferred = createDeferred()
    const rkey = hash.toString('hex')

    this._requests.set(rkey, {
      peer,
      deferred,
      timeoutId: setTimeout(() => {
        if (this._requests.get(rkey) !== undefined) {
          logError(chalk.red(`ping timeout: ${peer.address}:${peer.udpPort} ${
            peer.id && peer.id.toString('hex')}`))
          this._requests.delete(rkey)
          deferred.reject(new Error(`Timeout error: ping ${peer.address}:${peer.udpPort}`))
        } else {
          return deferred.promise
        }
      }, this._timeout)
    })

    this._requestsCache.set(rckey, deferred.promise)
    return deferred.promise
  }

  async findneighbours (peer, id) {
    this._isAliveCheck()
    await this._ensureBond(peer)

    this._send(peer, 'findneighbours', { id })
  }

  _isAliveCheck () {
    if (this._socket === null) throw new Error('Server already destroyed')
  }

  _checkBond (peer) {
    if (peer) {
      const lprkey = `${peer.id.toString('hex')}@${peer.address}:${peer.udpPort}`
      return this._lastPongReceived.get(lprkey)
    } else {
      return false
    }
  }

  async _ensureBond (peer) {
    const lprkey = `${peer.id.toString('hex')}@${peer.address}:${peer.udpPort}`
    if (!this._lastPingReceived.get(lprkey)) {
      logBond(`Bonding with enode://${lprkey}`)
      await this.ping(peer)
      await sleep(ms('500ms')) // wait for ping back and pong process
    }
  }

  async requestENR (obj) {
    this._isAliveCheck()

    // prevent dupe requests within 1 sec
    const rckey = `enr:${obj.address}:${obj.udpPort}`
    const promise = this._requestsCache.get(rckey)
    if (promise !== undefined) return promise

    const deferred = createDeferred()

    const peer = this._dpt.getPeer(obj)
    await this._ensureBond(peer)

    if (peer === null) {
      debug(`Peer not yet bonded: enrRequest ${obj.address}:${obj.udpPort} ${
        obj.id && obj.id.toString('hex')}`)
      deferred.reject(new Error(`Peer not yet bonded: enrRequest ${obj.address}:${obj.udpPort}`))
    } else {
      const hash = this._send(peer, 'enrRequest', {}) // just send an expiration timestamp
      const rkey = hash.toString('hex')

      // reject
      this._requests.set(rkey, {
        peer,
        deferred,
        timeoutId: setTimeout(() => {
          if (this._requests.get(rkey) !== undefined) {
            logError(chalk.red(`enrRequest timeout: ${peer.address}:${peer.udpPort} ${
              peer.id && peer.id.toString('hex')}`))
            this._requests.delete(rkey)
            deferred.reject(new Error(`Timeout error: enrRequest ${
              peer.address}:${peer.udpPort}`))
          } else {
            return deferred.promise
          }
        }, this._timeout)
      })
    }

    this._requestsCache.set(rckey, deferred.promise)
    return deferred.promise
  }

  _send (peer, typename, data) {
    debug(`send ${typename} to ${peer.address}:${peer.udpPort} (peerId: ${
      peer.id && peer.id.toString('hex')})`)

    const msg = message.encode(typename, data, this._privateKey)
    // Parity hack
    // There is a bug in Parity up to at lease 1.8.10 not echoing the hash from
    // discovery spec (hash: sha3(signature || packet-type || packet-data))
    // but just hashing the RLP-encoded packet data (see discovery.rs, on_ping())
    // 2018-02-28
    if (typename === 'ping') {
      const rkeyParity = keccak256(msg.slice(98)).toString('hex')
      this._parityRequestMap.set(rkeyParity, msg.slice(0, 32).toString('hex'))
      setTimeout(() => {
        if (this._parityRequestMap.get(rkeyParity) !== undefined) {
          this._parityRequestMap.delete(rkeyParity)
        }
      }, this._timeout)
    }
    this._socket.send(msg, 0, msg.length, peer.udpPort, peer.address)
    return msg.slice(0, 32) // message id
  }

  _handler (msg, rinfo) {
    const info = message.decode(msg)
    const peerId = pk2id(info.publicKey)

    // add peer if not in our table
    const peer = this._dpt.getPeer(peerId)
    if (
      peer === null &&
      info.typename === 'ping' &&
      info.data.from.udpPort !== null
    ) {
      setTimeout(() => this.emit('peers', [info.data.from]), ms('100ms'))
    }

    const lprkey = `${peerId.toString('hex')}@${rinfo.address}:${rinfo.port}`

    switch (info.typename) {
      case 'ping':
        logPing(`received ${info.typename} from ${rinfo.address}:${rinfo.port
          } (peerId: ${peerId.toString('hex')})`)
        Object.assign(rinfo, { id: peerId, udpPort: rinfo.port })

        this._send(rinfo, 'pong', {
          to: {
            address: rinfo.address,
            udpPort: rinfo.port,
            tcpPort: info.data.from.tcpPort
          },
          hash: msg.slice(0, 32),
          seq: this._enrSequence
        })

        this._lastPingReceived.set(lprkey, true)
        break

      case 'pong':
        logPing(`received ${info.typename} from ${rinfo.address}:${rinfo.port
          } (peerId: ${peerId.toString('hex')})`)
        var rkey = info.data.hash.toString('hex')
        const rkeyParity = this._parityRequestMap.get(rkey)
        if (rkeyParity) {
          rkey = rkeyParity
          this._parityRequestMap.delete(rkeyParity)
        }
        const pongReq = this._requests.get(rkey)
        if (pongReq) {
          this._requests.delete(rkey)
          pongReq.deferred.resolve({
            id: peerId,
            address: pongReq.peer.address,
            udpPort: pongReq.peer.udpPort,
            tcpPort: pongReq.peer.tcpPort
          })
        }

        this._lastPongReceived.set(lprkey, true)

        break

      case 'findneighbours':
        this._checkBond(peer)
        logNeighbors(`received ${info.typename} from ${rinfo.address}:${
          rinfo.port} (peerId: ${peerId.toString('hex')})`)
        Object.assign(rinfo, { id: peerId, udpPort: rinfo.port })
        this._send(rinfo, 'neighbours', {
          peers: this._dpt.getClosestPeers(info.data.id)
        })
        break

      case 'neighbours':
        logNeighbors(`received ${info.typename} from ${rinfo.address}:${
          rinfo.port} (peerId: ${peerId.toString('hex')})`)
        this.emit('peers', info.data.peers.map(peer => peer.endpoint))
        this.emit('neighbors', {
          peer: {
            address: rinfo.address,
            port: rinfo.port, id: peerId
          },
          neighbors: info.data.peers
        })
        break

      case 'enrRequest':
        this._checkBond(peer)
        logENR(`received ${info.typename} from ${rinfo.address}:${rinfo.port
          } (peerId: ${peerId.toString('hex')})`)
        Object.assign(rinfo, { id: peerId, udpPort: rinfo.port })
        const resp = {
          hash: msg.slice(0, 32),
          enr: {
            privateKey: this._privateKey,
            content: {
              seq: this._enrSequence,
              id: 'v4',
              forkid: this._forkid
            },
            secp256k1: this._pubKey,
            ip: this._endpoint.address,
            udp: this._endpoint.udpPort,
          }
        }
        this._send(rinfo, 'enrResponse', resp)
        this.emit('enrRequest', {raw: msg, rinfo: rinfo, resp: resp })
        break

      case 'enrResponse':
        logENR(`received ${info.typename} from ${rinfo.address}:${rinfo.port
          } (peerId: ${peerId.toString('hex')})`)
        this.emit('enrResponse', info.data )

        var rkey = info.data.hash.toString('hex')
        const enrReq = this._requests.get(rkey)
        if (enrReq) {
          this._requests.delete(rkey)
          enrReq.deferred.resolve({
            id: peerId,
            address: enrReq.peer.address,
            udpPort: enrReq.peer.udpPort,
            tcpPort: enrReq.peer.tcpPort,
            record: info.data.enr.record
          })
        }
        break
    }
  }
}

module.exports = Server
