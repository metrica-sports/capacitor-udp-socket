import Foundation
import Capacitor
import CocoaAsyncSocket

public enum SocketsError: Error {
    case Error (String)
}

/**
 * Please read the Capacitor iOS Plugin Development Guide
 * here: https://capacitorjs.com/docs/plugins/ios
 */
@objc(UdpSocketPlugin)
public class UdpSocketPlugin: CAPPlugin {
    private var sockets: [Int: UdpSocket] = [Int: UdpSocket]()
    private var nextSocketId: Int = 0

    override public func load() {
        NotificationCenter.default.addObserver(forName: NSNotification.Name(rawValue: "capacitor-udp-forward"), object: nil, queue: nil, using: handleUdpForward )
    }

    @objc func create(_ call: CAPPluginCall) {
        let properties = call.getObject("properties")

        let socket = UdpSocket.init(id: nextSocketId, properties: properties)
        sockets[socket.socketId] = socket
        socket.onReceivedHandler = { data in
            self.notifyListeners("receive", data: data, retainUntilConsumed: false)
        }

        socket.onReceivedErrorHandler = { data in
            self.notifyListeners("receiveError", data: data, retainUntilConsumed: false)
        }

        nextSocketId+=1

        call.resolve([
            "socketId": socket.socketId,
            "ipv4": Utils.getIPv4Address() ?? "",
            "ipv6": Utils.getIPv6Address() ?? ""
        ])
    }

    @objc func update(_ call: CAPPluginCall) {
        guard let socketId = call.getInt("socketId"), let socket = sockets[socketId] else {
            call.reject("Socket not found")
            return
        }
        let properties: [String: Any] = call.getObject("properties") ?? [String: Any]()
        socket.setProperties(properties)
        call.resolve()
    }

    @objc func setPaused(_ call: CAPPluginCall) {
        guard let socketId = call.getInt("socketId"), let socket = sockets[socketId] else {
            call.reject("Socket not found")
            return
        }
        let paused = call.getBool("paused", false)
        socket.setPaused(paused)
        call.resolve()
    }

    @objc func bind(_ call: CAPPluginCall) {
        guard let socketId = call.getInt("socketId"), let socket = sockets[socketId] else {
            call.reject("Socket not found")
            return
        }
        guard let port = call.getInt("port") else {
            call.reject("Illegal port")
            return
        }
        let address = call.getString("address")
        do {
            try socket.bind(port, address: address)
            call.resolve()
        } catch let SocketsError.Error(msg) {
            call.reject(msg)
        } catch {
            call.reject("bind Error")
        }

    }

    @objc func send(_ call: CAPPluginCall) {
        guard let socketId = call.getInt("socketId"), let socket = sockets[socketId] else {
            call.reject("Socket not found")
            return
        }
        guard let port = call.getInt("port") else {
            call.reject("Illegal port")
            return
        }

        let address = call.getString("address", "")
        let dataString = call.getString("buffer", "")

        do {
            let data = Data(base64Encoded: dataString, options: .ignoreUnknownCharacters) ?? Data.init()
            try socket.send(data, address: address, port: port)
            call.resolve(["bytesSent": data.count])
        } catch let SocketsError.Error(msg) {
            call.reject(msg)
        } catch {
            call.reject("unkow error")
        }
    }

    @objc func close(_ call: CAPPluginCall) {
        guard let socketId = call.getInt("socketId"), let socket = sockets[socketId] else {
            call.reject("Socket not found")
            return
        }
        socket.closeSocket()
        sockets[socketId] = nil
        call.resolve()
    }

    @objc func closeAllSockets(_ call: CAPPluginCall) {
        for (socketId, socket) in sockets {
            socket.closeSocket()
            sockets[socketId] = nil
        }
        call.resolve([
            "success": "close all"
        ])
    }

    @objc func listV4Interfaces(_ call: CAPPluginCall) {
        call.resolve([
            "interfaces": Utils.listV4Interfaces()
        ])
    }
    
    @objc func getInfo(_ call: CAPPluginCall) {
        guard let socketId = call.getInt("socketId"), let socket = sockets[socketId] else {
            call.reject("Socket not found")
            return
        }
        call.resolve(socket.getInfo())
    }

    @objc func getSockets(_ call: CAPPluginCall) {
        var socketsInfo = [Any]()
        for (_, socket) in sockets {
            socketsInfo.append(socket.getInfo())
        }
        call.resolve(["sockets": socketsInfo])
    }

    @objc func setBroadcast(_ call: CAPPluginCall) {
        guard let socketId = call.getInt("socketId"), let socket = sockets[socketId] else {
            call.reject("Socket not found")
            return
        }
        let enabled = call.getBool("enabled", false)
        do {
            try socket.setBroadcast(enabled)
            call.resolve()
        } catch let SocketsError.Error(msg) {
            call.reject(msg)
        } catch {
            call.reject("unkow error")
        }
    }

    @objc func joinGroup(_ call: CAPPluginCall) {
        guard let socketId = call.getInt("socketId"), let socket = sockets[socketId] else {
            call.reject("Socket not found")
            return
        }
        let address = call.getString("address", "")
        let interface = call.getString("interface", "")
        do {
            try socket.joinGroup(address, interface: interface)
            call.resolve()
        } catch let SocketsError.Error(msg) {
            call.reject(msg)
        } catch {
            call.reject("unkow error")
        }
    }

    @objc func leaveGroup(_ call: CAPPluginCall) {
        guard let socketId = call.getInt("socketId"), let socket = sockets[socketId] else {
            call.reject("Socket not found")
            return
        }
        let address = call.getString("address", "")
        do {
            try socket.leaveGroup(address)
            call.resolve()
        } catch let SocketsError.Error(msg) {
            call.reject(msg)
        } catch {
            call.reject("unkow error")
        }

    }

    @objc func getJoinedGroups(_ call: CAPPluginCall) {
        guard let socketId = call.getInt("socketId"), let socket = sockets[socketId] else {
            call.reject("Socket not found")
            return
        }

        let groups = socket.multicastGroups
        let groupArray = groups.map { "\($0.address) on \($0.interface)" }
        call.resolve(["groups": groupArray])
    }
    
    @objc func setMulticastInterface(_ call: CAPPluginCall) {
        guard let socketId = call.getInt("socketId"), let socket = sockets[socketId] else {
            call.reject("Socket not found")
            return
        }
        let ifaceName = call.getString("iface", "")
        
        socket.socket?.perform {
            if socket.socket?.isIPv4() ?? false {
                // Get IPv4 address for this interface
                var ifaddrPtr: UnsafeMutablePointer<ifaddrs>?
                if getifaddrs(&ifaddrPtr) == 0, let firstAddr = ifaddrPtr {
                    var foundAddr = in_addr()
                    var cursor: UnsafeMutablePointer<ifaddrs>? = firstAddr
                    while let addr = cursor {
                        if let name = String(validatingUTF8: addr.pointee.ifa_name),
                           name == ifaceName,
                           addr.pointee.ifa_addr.pointee.sa_family == UInt8(AF_INET) {
                            
                            var sin = UnsafeRawPointer(addr.pointee.ifa_addr).assumingMemoryBound(to: sockaddr_in.self).pointee
                            foundAddr = sin.sin_addr
                            break
                        }
                        cursor = addr.pointee.ifa_next
                    }
                    freeifaddrs(firstAddr)
                    
                    // Apply interface
                    if setsockopt(socket.socket?.socket4FD() ?? 0, IPPROTO_IP, IP_MULTICAST_IF, &foundAddr, socklen_t(MemoryLayout.size(ofValue: foundAddr))) < 0 {
                        call.reject("Failed to set IPv4 multicast interface")
                        return
                    }
                } else {
                    call.reject("Unable to get interface addresses")
                    return
                }
            } else if socket.socket?.isIPv6() ?? false {
                // IPv6 uses interface index
                let ifIndex = if_nametoindex(ifaceName)
                var indexCpy = UInt32(ifIndex)
                if setsockopt(socket.socket?.socket6FD() ?? 0, IPPROTO_IPV6, IPV6_MULTICAST_IF, &indexCpy, socklen_t(MemoryLayout.size(ofValue: indexCpy))) < 0 {
                    call.reject("Failed to set IPv6 multicast interface")
                    return
                }
            }
            
            call.resolve()
        }
    }

    @objc func setMulticastTimeToLive(_ call: CAPPluginCall) {
        guard let socketId = call.getInt("socketId"), let socket = sockets[socketId] else {
            call.reject("Socket not found")
            return
        }

        guard let ttl = call.getInt("ttl") else {
            call.reject("Illegal ttl")
            return
        }

        socket.socket?.perform({ () in
            if socket.socket?.isIPv4() ?? false {
                var ttlCpy: CUnsignedChar = (ttl as NSNumber).uint8Value
                if setsockopt(socket.socket?.socket4FD() ?? 0, IPPROTO_IP, IP_MULTICAST_TTL, &ttlCpy, UInt32( MemoryLayout.size(ofValue: ttlCpy))) < 0 {
                    call.reject("ttl ipv4 error")
                }
            }
            if socket.socket?.isIPv6() ?? false {
                var ttlCpy = ttl
                if setsockopt(socket.socket?.socket6FD() ?? 0, IPPROTO_IPV6, IP_MULTICAST_TTL, &ttlCpy, UInt32( MemoryLayout.size(ofValue: ttlCpy))) < 0 {
                    call.reject("ttl ipv6 error")
                }
            }
            call.resolve()
        })
    }

    @objc func setMulticastLoopbackMode(_ call: CAPPluginCall) {
        guard let socketId = call.getInt("socketId"), let socket = sockets[socketId] else {
            call.reject("Socket not found")
            return
        }
        let enabled = call.getBool("enabled", false)

        socket.socket?.perform({ () in
            if socket.socket?.isIPv4() ?? false {
                var loop: CUnsignedChar = enabled ? 1 : 0
                if setsockopt(socket.socket?.socket4FD() ?? 0, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, UInt32( MemoryLayout.size(ofValue: loop))) < 0 {
                    call.reject("loopback ipv4 error")
                }
            }
            if socket.socket?.isIPv6() ?? false {
                var loop: Int32 = enabled ? 1 : 0
                if setsockopt(socket.socket?.socket6FD() ?? 0, IPPROTO_IPV6, IP_MULTICAST_LOOP, &loop, UInt32( MemoryLayout.size(ofValue: loop))) < 0 {
                    call.reject("loopback ipv6 error")
                }
            }
            call.resolve()
        })
    }

    private func handleUdpForward(_ notification: Notification) {
        guard let socketId = notification.userInfo?["socketId"] as? Int,
              let address: String = notification.userInfo?["address"] as? String,
              let port = notification.userInfo?["port"] as? Int,
              let socket = sockets[socketId] else {
            return
        }
        let data = notification.userInfo?["data"] as? Data ?? Data.init()

        try? socket.send(data, address: address, port: port)
    }
}
