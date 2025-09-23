package com.svend.plugins.udp.socket;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

public class Utils {

    public static NetworkInterface getNetworkInterface() {
        try {
            List<NetworkInterface> interfaces = Collections.list(NetworkInterface.getNetworkInterfaces());
            for (NetworkInterface intf : interfaces) {
                List<InetAddress> addrs = Collections.list(intf.getInetAddresses());
                if (addrs.size() < 2) continue;
                if (addrs.get(0).isLoopbackAddress()) continue;
                return intf;
            }
        } catch (Exception ignored) {} // for now eat exceptions
        return null;
    }

    public static NetworkInterface getNetworkInterfaceByHostAddress(String hostAddress) {
        if (hostAddress == null) {
            return null;
        }
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface intf = interfaces.nextElement();
                Enumeration<InetAddress> addrs = intf.getInetAddresses();
                while (addrs.hasMoreElements()) {
                  InetAddress addr = addrs.nextElement();
                  if (addr instanceof Inet4Address && !addr.isLoopbackAddress()) {
                    if(hostAddress.equals(addr.getHostAddress())){
                      return intf;
                    }
                  }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static List<String> listV4Interfaces() {
        List<String> interfaceNames = new ArrayList<String>();
        try {
            List<NetworkInterface> interfaces = Collections.list(NetworkInterface.getNetworkInterfaces());
            for (NetworkInterface intf : interfaces) {
                Enumeration<InetAddress> addrs = intf.getInetAddresses();
                while (addrs.hasMoreElements()) {
                    InetAddress addr = addrs.nextElement();
                    if (addr instanceof Inet4Address && !addr.isLoopbackAddress()) {
                        if(!interfaceNames.contains(addr.getHostAddress())){
                            interfaceNames.add(addr.getHostAddress());
                        }
                    }
                }
            }
        } catch (Exception ignored) {}
        return interfaceNames;
    }


    public static InetAddress getIPAddress(boolean useIPv4) {
        try {
            List<NetworkInterface> interfaces = Collections.list(NetworkInterface.getNetworkInterfaces());
            for (NetworkInterface intf : interfaces) {
                List<InetAddress> addrs = Collections.list(intf.getInetAddresses());
                if (addrs.size() < 2) continue;
                for (InetAddress addr : addrs) {
                    if (!addr.isLoopbackAddress()) {
                        String sAddr = addr.getHostAddress();
                        boolean isIPv4 = sAddr.indexOf(':') < 0;
                        if (useIPv4) {
                            if (isIPv4) return addr;
                        } else {
                            if (!isIPv4) {
                                return addr;
                            }
                        }
                    }
                }
            }
        } catch (Exception ignored) {} // for now eat exceptions
        return InetAddress.getLoopbackAddress();
    }
}
