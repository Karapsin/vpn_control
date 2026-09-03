package com.kardinal.vpncontrol.data;

import android.util.Log;
import java.io.Closeable;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/** A loopback-only, no-egress SOCKS5 fixture owned by the VPN application's excluded UID. */
final class AndroidSocksHttpFixture implements Closeable {
    private static final String TAG = "AndroidSocksFixture";
    private final byte[] responseToken;
    private final LinkedBlockingQueue<String> destinations = new LinkedBlockingQueue<>();
    private ServerSocket serverSocket;
    private Thread acceptThread;

    AndroidSocksHttpFixture(String responseToken) {
        this.responseToken = responseToken.getBytes(StandardCharsets.UTF_8);
    }

    void start() throws IOException {
        serverSocket = new ServerSocket(0, 16, InetAddress.getByName("127.0.0.1"));
        Log.i(TAG, "Listening on 127.0.0.1:" + serverSocket.getLocalPort());
        acceptThread = new Thread(this::acceptConnections, "android-socks-fixture");
        acceptThread.setDaemon(true);
        acceptThread.start();
    }

    int getPort() {
        if (serverSocket == null) {
            throw new IllegalStateException("fixture is not started");
        }
        return serverSocket.getLocalPort();
    }

    boolean awaitDestination(String expected, long timeout, TimeUnit unit) throws InterruptedException {
        long deadlineNanos = System.nanoTime() + unit.toNanos(timeout);
        while (System.nanoTime() < deadlineNanos) {
            String destination = destinations.poll(
                    Math.max(1, deadlineNanos - System.nanoTime()),
                    TimeUnit.NANOSECONDS);
            if (expected.equals(destination)) {
                return true;
            }
        }
        return false;
    }

    private void acceptConnections() {
        while (serverSocket != null && !serverSocket.isClosed()) {
            try {
                Socket socket = serverSocket.accept();
                Log.i(TAG, "Accepted SOCKS connection from " + socket.getRemoteSocketAddress());
                Thread client = new Thread(() -> handle(socket), "android-socks-fixture-client");
                client.setDaemon(true);
                client.start();
            } catch (SocketException error) {
                if (serverSocket != null && !serverSocket.isClosed()) {
                    throw new RuntimeException(error);
                }
            } catch (IOException error) {
                throw new RuntimeException(error);
            }
        }
    }

    private void handle(Socket socket) {
        try (Socket connection = socket) {
            connection.setSoTimeout(10_000);
            DataInputStream input = new DataInputStream(connection.getInputStream());
            OutputStream output = connection.getOutputStream();
            if (input.readUnsignedByte() != 5) {
                return;
            }
            int methodCount = input.readUnsignedByte();
            readExact(input, methodCount);
            output.write(new byte[]{5, 0});

            int version = input.readUnsignedByte();
            int command = input.readUnsignedByte();
            input.readUnsignedByte();
            int addressType = input.readUnsignedByte();
            if (version != 5 || command != 1) {
                output.write(new byte[]{5, 7, 0, 1, 0, 0, 0, 0, 0, 0});
                return;
            }
            String destination = readDestination(input, addressType);
            Log.i(TAG, "SOCKS CONNECT " + destination);
            destinations.offer(destination);
            output.write(new byte[]{5, 0, 0, 1, 127, 0, 0, 1, 0, 0});
            byte[] header = (
                    "HTTP/1.1 200 OK\r\nContent-Length: " + responseToken.length
                            + "\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n")
                    .getBytes(StandardCharsets.US_ASCII);
            output.write(header);
            output.write(responseToken);
            output.flush();
            Log.i(TAG, "Returned fixture HTTP response for " + destination);
        } catch (IOException error) {
            // Background Android services can probe the disposable SOCKS endpoint and disconnect.
            Log.i(TAG, "SOCKS connection ended: " + error.getMessage());
        }
    }

    private static String readDestination(DataInputStream input, int addressType) throws IOException {
        String host;
        if (addressType == 1) {
            host = InetAddress.getByAddress(readExact(input, 4)).getHostAddress();
        } else if (addressType == 3) {
            host = new String(readExact(input, input.readUnsignedByte()), StandardCharsets.US_ASCII);
        } else if (addressType == 4) {
            host = InetAddress.getByAddress(readExact(input, 16)).getHostAddress();
        } else {
            throw new IOException("unsupported SOCKS address type: " + addressType);
        }
        int port = input.readUnsignedShort();
        return host + ":" + port;
    }

    private static byte[] readExact(DataInputStream input, int size) throws IOException {
        byte[] bytes = new byte[size];
        input.readFully(bytes);
        return bytes;
    }

    @Override
    public void close() throws IOException {
        if (serverSocket != null) {
            serverSocket.close();
        }
        if (acceptThread != null) {
            try {
                acceptThread.join(2_000);
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
                throw new IOException("interrupted while stopping fixture", error);
            }
        }
    }
}
