/*
 * The wire protocol (message framing, CNXN/AUTH handshake) and the ADB RSA public-key encoding
 * in KeyPair.convertRsaPublicKeyToAdbFormat/SIGNATURE_PADDING are adapted from the dadb project:
 *   https://github.com/mobile-dev-inc/dadb (Copyright (c) 2021 mobile.dev inc., Apache License 2.0)
 * which in turn credits https://github.com/cgutman/AdbLib for the public-key conversion.
 *
 * This is a condensed, single-file Java port for this app's narrow use case: connect, open exactly
 * one sequential stream, read its response until the peer closes it. dadb's general-purpose
 * multi-stream demultiplexing (MessageQueue, per-stream dispatch) isn't needed here and is dropped.
 */

package dev.twaik.adbtcpip;

import android.hardware.usb.UsbConstants;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbEndpoint;
import android.hardware.usb.UsbInterface;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.Cipher;

public final class AdbProtocol {

    private AdbProtocol() {
    }

    private static final int AUTH_TYPE_TOKEN = 1;
    private static final int AUTH_TYPE_SIGNATURE = 2;
    private static final int AUTH_TYPE_RSA_PUBLIC = 3;

    private static final int CMD_AUTH = 0x48545541;
    private static final int CMD_CNXN = 0x4e584e43;
    private static final int CMD_OPEN = 0x4e45504f;
    private static final int CMD_OKAY = 0x59414b4f;
    private static final int CMD_CLSE = 0x45534c43;
    private static final int CMD_WRTE = 0x45545257;

    private static final int CONNECT_VERSION = 0x01000000;
    private static final int CONNECT_MAXDATA = 1024 * 1024;
    private static final byte[] CONNECT_PAYLOAD = nulTerminated("host::");

    private static byte[] nulTerminated(String s) {
        byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
        return Arrays.copyOf(bytes, bytes.length + 1);
    }

    /** Byte transport a Connection runs the protocol over. */
    public interface Transport extends Closeable {
        void write(byte[] data, int offset, int length) throws IOException;

        /** Blocks until exactly {@code length} bytes are read, or throws. */
        void readFully(byte[] buffer, int offset, int length) throws IOException;
    }

    /** The peer rejected our key, or never accepted it - the user needs to tap "Allow" on its screen. */
    public static final class AdbAuthException extends IOException {
        public AdbAuthException(String message) {
            super(message);
        }
    }

    // ---- message framing ----------------------------------------------------------------------

    private static final class Message {
        final int command;
        final int arg0;
        final int arg1;
        final byte[] payload;

        Message(int command, int arg0, int arg1, byte[] payload) {
            this.command = command;
            this.arg0 = arg0;
            this.arg1 = arg1;
            this.payload = payload;
        }
    }

    private static Message readMessage(Transport transport) throws IOException {
        byte[] header = new byte[24];
        transport.readFully(header, 0, 24);
        ByteBuffer buf = ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN);
        int command = buf.getInt();
        int arg0 = buf.getInt();
        int arg1 = buf.getInt();
        int payloadLength = buf.getInt();
        // checksum + magic (next two ints) aren't validated on read, matching upstream dadb.

        byte[] payload = new byte[payloadLength];
        if (payloadLength > 0) {
            transport.readFully(payload, 0, payloadLength);
        }
        return new Message(command, arg0, arg1, payload);
    }

    private static void writeMessage(Transport transport, int command, int arg0, int arg1, byte[] payload) throws IOException {
        int length = payload == null ? 0 : payload.length;
        ByteBuffer header = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        header.putInt(command);
        header.putInt(arg0);
        header.putInt(arg1);
        header.putInt(length);
        header.putInt(checksum(payload));
        header.putInt(command ^ -1);
        transport.write(header.array(), 0, 24);
        if (length > 0) {
            transport.write(payload, 0, length);
        }
    }

    private static int checksum(byte[] payload) {
        if (payload == null) return 0;
        int sum = 0;
        for (byte b : payload) {
            sum += (b & 0xFF);
        }
        return sum;
    }

    // ---- RSA key pair (adb-specific format/signing) --------------------------------------------

    public static final class KeyPair {

        private static final int KEY_LENGTH_BITS = 2048;
        private static final int KEY_LENGTH_BYTES = KEY_LENGTH_BITS / 8;
        private static final int KEY_LENGTH_WORDS = KEY_LENGTH_BYTES / 4;

        // PKCS#1 v1.5 padding + SHA-1 DigestInfo prefix, applied manually because adb signs the raw
        // 20-byte AUTH token with a plain RSA private-key op rather than a standard Signature API call.
        private static final byte[] SIGNATURE_PADDING = {
                (byte) 0x00, (byte) 0x01, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x00,
                (byte) 0x30, (byte) 0x21, (byte) 0x30, (byte) 0x09, (byte) 0x06, (byte) 0x05, (byte) 0x2b, (byte) 0x0e, (byte) 0x03, (byte) 0x02, (byte) 0x1a, (byte) 0x05, (byte) 0x00,
                (byte) 0x04, (byte) 0x14
        };

        private final PrivateKey privateKey;
        final byte[] publicKeyBytes;

        private KeyPair(PrivateKey privateKey, byte[] publicKeyBytes) {
            this.privateKey = privateKey;
            this.publicKeyBytes = publicKeyBytes;
        }

        byte[] sign(byte[] token) throws GeneralSecurityException {
            Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            cipher.update(SIGNATURE_PADDING);
            return cipher.doFinal(token);
        }

        /** Loads the persistent key pair from {@code keyDir}, generating one on first use. */
        public static KeyPair readOrGenerate(File keyDir) throws IOException, GeneralSecurityException {
            File privateKeyFile = new File(keyDir, "adbkey");
            File publicKeyFile = new File(keyDir, "adbkey.pub");
            if (!privateKeyFile.exists()) {
                generate(privateKeyFile, publicKeyFile);
            }
            PrivateKey privateKey = parsePkcs8(readAllBytes(privateKeyFile));
            byte[] publicKeyBytes = readAdbPublicKey(publicKeyFile);
            return new KeyPair(privateKey, publicKeyBytes);
        }

        private static byte[] readAllBytes(File file) throws IOException {
            try (FileInputStream in = new FileInputStream(file)) {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) >= 0) {
                    out.write(buf, 0, n);
                }
                return out.toByteArray();
            }
        }

        private static void generate(File privateKeyFile, File publicKeyFile) throws IOException, GeneralSecurityException {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(KEY_LENGTH_BITS);
            java.security.KeyPair keyPair = generator.generateKeyPair();

            File privateParent = privateKeyFile.getAbsoluteFile().getParentFile();
            if (privateParent != null) privateParent.mkdirs();
            File publicParent = publicKeyFile.getAbsoluteFile().getParentFile();
            if (publicParent != null) publicParent.mkdirs();

            try (Writer out = new FileWriter(privateKeyFile)) {
                Base64.Encoder base64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8));
                out.write("-----BEGIN PRIVATE KEY-----\n");
                out.write(base64.encodeToString(keyPair.getPrivate().getEncoded()));
                out.write("\n-----END PRIVATE KEY-----");
            }

            try (Writer out = new FileWriter(publicKeyFile)) {
                byte[] bytes = convertRsaPublicKeyToAdbFormat((RSAPublicKey) keyPair.getPublic());
                out.write(Base64.getEncoder().encodeToString(bytes));
                out.write(" adb-tcpip-app@android");
            }
        }

        private static byte[] readAdbPublicKey(File file) throws IOException {
            byte[] bytes = readAllBytes(file);
            byte[] result = Arrays.copyOf(bytes, bytes.length + 1);
            result[bytes.length] = 0;
            return result;
        }

        private static PrivateKey parsePkcs8(byte[] bytes) throws GeneralSecurityException {
            String string = new String(bytes, StandardCharsets.UTF_8)
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s+", "");
            byte[] encoded = Base64.getDecoder().decode(string);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encoded));
        }

        // https://github.com/cgutman/AdbLib/blob/d6937951eb98557c76ee2081e383d50886ce109a/src/com/cgutman/adblib/AdbCrypto.java#L83-L137
        private static byte[] convertRsaPublicKeyToAdbFormat(RSAPublicKey pubkey) {
            /*
             * ADB literally just saves the RSAPublicKey struct to a file.
             *
             * typedef struct RSAPublicKey {
             * int len; // Length of n[] in number of uint32_t
             * uint32_t n0inv;  // -1 / n[0] mod 2^32
             * uint32_t n[RSANUMWORDS]; // modulus as little endian array
             * uint32_t rr[RSANUMWORDS]; // R^2 as little endian array
             * int exponent; // 3 or 65537
             * } RSAPublicKey;
             */
            BigInteger r32 = BigInteger.ZERO.setBit(32);
            BigInteger n = pubkey.getModulus();
            BigInteger r = BigInteger.ZERO.setBit(KEY_LENGTH_WORDS * 32);
            BigInteger rr = r.modPow(BigInteger.valueOf(2), n);
            BigInteger rem = n.remainder(r32);
            BigInteger n0inv = rem.modInverse(r32);

            int[] myN = new int[KEY_LENGTH_WORDS];
            int[] myRr = new int[KEY_LENGTH_WORDS];
            for (int i = 0; i < KEY_LENGTH_WORDS; i++) {
                BigInteger[] res = rr.divideAndRemainder(r32);
                rr = res[0];
                myRr[i] = res[1].intValue();
                res = n.divideAndRemainder(r32);
                n = res[0];
                myN[i] = res[1].intValue();
            }

            ByteBuffer bbuf = ByteBuffer.allocate(524).order(ByteOrder.LITTLE_ENDIAN);
            bbuf.putInt(KEY_LENGTH_WORDS);
            bbuf.putInt(n0inv.negate().intValue());
            for (int i : myN) bbuf.putInt(i);
            for (int i : myRr) bbuf.putInt(i);
            bbuf.putInt(pubkey.getPublicExponent().intValue());
            return bbuf.array();
        }
    }

    // ---- connection + single sequential stream --------------------------------------------------

    public static final class Connection implements Closeable {

        private final Transport transport;
        private final AtomicInteger nextLocalId = new AtomicInteger(0);

        private Connection(Transport transport) {
            this.transport = transport;
        }

        public static Connection connect(Transport transport, KeyPair keyPair) throws IOException, GeneralSecurityException {
            writeMessage(transport, CMD_CNXN, CONNECT_VERSION, CONNECT_MAXDATA, CONNECT_PAYLOAD);

            Message message = readMessage(transport);

            if (message.command == CMD_AUTH) {
                if (message.arg0 != AUTH_TYPE_TOKEN) {
                    throw new IOException("Unsupported auth type: " + message.arg0);
                }
                byte[] signature = keyPair.sign(message.payload);
                writeMessage(transport, CMD_AUTH, AUTH_TYPE_SIGNATURE, 0, signature);

                message = readMessage(transport);
                if (message.command == CMD_AUTH) {
                    writeMessage(transport, CMD_AUTH, AUTH_TYPE_RSA_PUBLIC, 0, keyPair.publicKeyBytes);
                    message = readMessage(transport);
                }
            }

            if (message.command == CMD_AUTH) {
                throw new AdbAuthException("Device rejected authentication (unauthorized)");
            }
            if (message.command != CMD_CNXN) {
                throw new IOException("Connection failed: unexpected response");
            }

            return new Connection(transport);
        }

        /**
         * Opens {@code destination} as a one-shot request/response service (e.g. "tcpip:5555"),
         * acknowledges every WRTE the peer sends, and returns the concatenated payload as UTF-8
         * text once the peer closes the stream.
         */
        public String openAndRead(String destination) throws IOException {
            int localId = nextLocalId.incrementAndGet();
            writeMessage(transport, CMD_OPEN, localId, 0, nulTerminated(destination));

            Message reply = readMessage(transport);
            if (reply.command == CMD_CLSE) {
                throw new IOException("adbd refused to open stream: " + destination);
            }
            if (reply.command != CMD_OKAY) {
                throw new IOException("Unexpected response opening stream: " + destination);
            }
            int remoteId = reply.arg0;

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            while (true) {
                Message m;
                try {
                    m = readMessage(transport);
                } catch (EOFException e) {
                    // Peer closed the USB connection outright (e.g. adbd restarting in TCP mode) -
                    // treat like a clean stream close.
                    break;
                }
                if (m.command == CMD_CLSE) {
                    break;
                }
                if (m.command == CMD_WRTE) {
                    out.write(m.payload, 0, m.payload.length);
                    writeMessage(transport, CMD_OKAY, localId, remoteId, null);
                }
            }
            return out.toString("UTF-8");
        }

        @Override
        public void close() {
            try {
                transport.close();
            } catch (IOException ignore) {
            }
        }
    }

    // ---- USB transport ---------------------------------------------------------------------------

    /**
     * Implements {@link Transport} over a claimed USB bulk in/out endpoint pair, so the protocol
     * above can run directly over USB instead of a TCP socket - this is what lets this app send
     * "tcpip:&lt;port&gt;" to a device before it's ever reachable over the network.
     */
    public static final class UsbTransport implements Transport {

        private static final int USB_CLASS_ADB = 0xFF;
        private static final int USB_SUBCLASS_ADB = 0x42;
        private static final int USB_PROTOCOL_ADB = 0x01;

        private static final int MAX_CHUNK = 16 * 1024;
        private static final int WRITE_TIMEOUT_MS = 5000;
        private static final int READ_TIMEOUT_MS = 60_000;

        /** Endpoint pair of the interface a device advertises for adb, if it has one. */
        public static final class Endpoints {
            final UsbInterface usbInterface;
            final UsbEndpoint epIn;
            final UsbEndpoint epOut;

            private Endpoints(UsbInterface usbInterface, UsbEndpoint epIn, UsbEndpoint epOut) {
                this.usbInterface = usbInterface;
                this.epIn = epIn;
                this.epOut = epOut;
            }
        }

        /**
         * The adb USB interface is identified by class/subclass/protocol, the same signature the
         * desktop adb client and adbd itself use - not by vendor/product ID, which vary per device.
         */
        public static Endpoints findAdbEndpoints(UsbDevice device) {
            for (int i = 0; i < device.getInterfaceCount(); i++) {
                UsbInterface intf = device.getInterface(i);
                if (intf.getInterfaceClass() != USB_CLASS_ADB
                        || intf.getInterfaceSubclass() != USB_SUBCLASS_ADB
                        || intf.getInterfaceProtocol() != USB_PROTOCOL_ADB) {
                    continue;
                }

                UsbEndpoint epIn = null;
                UsbEndpoint epOut = null;
                for (int e = 0; e < intf.getEndpointCount(); e++) {
                    UsbEndpoint ep = intf.getEndpoint(e);
                    if (ep.getType() != UsbConstants.USB_ENDPOINT_XFER_BULK) continue;
                    if (ep.getDirection() == UsbConstants.USB_DIR_IN) epIn = ep;
                    else epOut = ep;
                }
                if (epIn != null && epOut != null) {
                    return new Endpoints(intf, epIn, epOut);
                }
            }
            return null;
        }

        private final UsbDeviceConnection connection;
        private final UsbInterface usbInterface;
        private final UsbEndpoint epIn;
        private final UsbEndpoint epOut;

        public UsbTransport(UsbDeviceConnection connection, Endpoints endpoints) throws IOException {
            this.connection = connection;
            this.usbInterface = endpoints.usbInterface;
            this.epIn = endpoints.epIn;
            this.epOut = endpoints.epOut;
            if (!connection.claimInterface(usbInterface, true)) {
                throw new IOException("Failed to claim USB interface");
            }
        }

        @Override
        public void write(byte[] data, int offset, int length) throws IOException {
            int off = offset;
            int end = offset + length;
            while (off < end) {
                int chunkLen = Math.min(end - off, MAX_CHUNK);
                writeChunk(data, off, chunkLen);
                off += chunkLen;
            }
        }

        private void writeChunk(byte[] data, int offset, int length) throws IOException {
            int off = offset;
            int end = offset + length;
            while (off < end) {
                int n = connection.bulkTransfer(epOut, data, off, end - off, WRITE_TIMEOUT_MS);
                if (n < 0) throw new IOException("USB bulk write failed");
                off += n;
            }
            // A transfer whose length is an exact multiple of the endpoint's max packet size needs
            // a trailing zero-length packet, or the receiving side keeps waiting for more.
            if (length > 0 && length % epOut.getMaxPacketSize() == 0) {
                connection.bulkTransfer(epOut, new byte[0], 0, 0, WRITE_TIMEOUT_MS);
            }
        }

        @Override
        public void readFully(byte[] buffer, int offset, int length) throws IOException {
            int off = offset;
            int end = offset + length;
            while (off < end) {
                int chunkLen = Math.min(end - off, MAX_CHUNK);
                // Generous timeout: after AUTH the target device may be waiting on its user to tap
                // "Allow USB debugging", which can take a while.
                int n = connection.bulkTransfer(epIn, buffer, off, chunkLen, READ_TIMEOUT_MS);
                if (n < 0) throw new IOException("USB bulk read failed or timed out");
                if (n == 0) throw new EOFException("USB endpoint closed");
                off += n;
            }
        }

        @Override
        public void close() {
            try {
                connection.releaseInterface(usbInterface);
            } catch (Exception ignore) {
            }
            connection.close();
        }
    }
}
