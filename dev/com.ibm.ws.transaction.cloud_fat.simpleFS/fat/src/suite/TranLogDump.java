/*******************************************************************************
 * Copyright (c) 2026 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
package suite;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Dump Transaction recovery logs to human-readable format
 */
public class TranLogDump {

    //file format constants from LogFileHeader, LogRecord

    private static final byte[] WASLOG_MAGIC = "WASLOG".getBytes();
    private static final byte[] RCRD_MAGIC = "RCRD".getBytes();
    private static final byte[] VARFIELD_MAGIC = "VARFIELD".getBytes();

    private static final int STATUS_INACTIVE = 2;
    private static final int STATUS_ACTIVE = 4;
    private static final int STATUS_KEYPOINTING = 8;

    private static final short RECORD_TYPE_NORMAL = 1;
    private static final short RECORD_TYPE_DELETED = 2;

    private static final int END_OF_SECTION = -1;

    // constants from TransactionImpl

    //common (in both tranlog and partnerlog)
    private static final int APPLID_DATA_SECTION = 253;
    private static final int EPOCH_DATA_SECTION = 254;
    private static final int SERVER_DATA_SECTION = 255;

    //tranlog sections
    private static final int TRAN_STATE_SECTION = 0;
    private static final int XARESOURCE_SECTION = 2;
    private static final int GLOBALID_SECTION = 3;
    private static final int RESOURCE_ADAPTER_SECTION = 7;
    private static final int HEURISTIC_OUTCOME_SECTION = 8;

    //partnerlog sections
    private static final int NEXT_ID_SECTION = 30; /* @MD18134A */
    private static final int LOW_WATERMARK_SECTION = 31; /* @MD18134A */
    private static final int SERVER_STATE_SECTION = 32;
    private static final int XARESOURCEDATA_SECTION = 34;
    private static final int RESOURCE_PRIORITY_SECTION = 37; /* LI3968A */

    //Transaction state names -  from TransactionState.java
    private static final Map<Integer, String> TRAN_STATE = new LinkedHashMap<>();

    static {
        TRAN_STATE.put(-1, "STATE_NONE");
        TRAN_STATE.put(0, "STATE_ACTIVE");
        TRAN_STATE.put(1, "STATE_PREPARING");
        TRAN_STATE.put(2, "STATE_PREPARED");
        TRAN_STATE.put(3, "STATE_COMMITTING");
        TRAN_STATE.put(4, "STATE_COMMITTED");
        TRAN_STATE.put(5, "STATE_ROLLING_BACK");
        TRAN_STATE.put(6, "STATE_ROLLED_BACK");
        TRAN_STATE.put(7, "STATE_HEURISTIC_ON_COMMIT");
        TRAN_STATE.put(8, "STATE_HEURISTIC_ON_ROLLBACK");
        TRAN_STATE.put(9, "STATE_LAST_PARTICIPANT");
        TRAN_STATE.put(10, "STATE_HEURISTIC_MIXED");
        TRAN_STATE.put(11, "STATE_HEURISTIC_HAZARD");
    };

    private static final String SEP = "=================================================================";
    private static final String RSEP = "------------------------------------------------------------------";

    // file-level parsing

    private static void dumpFile(Path path) throws Exception {
        System.out.println(SEP);
        System.out.println(" FILE: " + path.toAbsolutePath());
        System.out.printf(" SIZE: %,d bytes%n", Files.size(path));
        System.out.println(SEP);

        byte[] bytes = Files.readAllBytes(path); //Note that this method is intended for simple cases where it is convenient to read all bytes into a byte array. It is not intended for reading in large files.
        DataInputStream dis = wrap(bytes);

        // ------------------ processing file header

        int headerLength = dis.readInt();
        System.out.printf(" Header Length: %d%n", headerLength);

        byte[] magic = new byte[6];
        dis.readFully(magic); // This method blocks until magic.length bytes of input data are available, in which case a normal return is made.
        boolean magicOk = Arrays.equals(magic, WASLOG_MAGIC);
        System.out.printf("Magic:    %s   %s%n", new String(magic), magicOk ? "(OK)" : "*** INVALID - Not a Liberty TranLog file ***");

        if (!magicOk) {
            System.out.println("Arborting: file does not have a valid Liberty TranLog header");
            return;
        }

        int rlsVersion = dis.readInt();
        int status = dis.readInt();
        long date = dis.readLong();
        long firstSeq = dis.readLong();

        System.out.printf("RLS Version      : %d%n", rlsVersion);
        System.out.printf("Status           : %d (%s)%n", status, getStatusName(status));
        System.out.printf("Date             : %s%n", formatDate(date));
        System.out.printf("Fist seq#        : %d%n", firstSeq);

        int serverNameLen = dis.readInt();
        byte[] serverNameBytes = new byte[serverNameLen];
        dis.readFully(serverNameBytes);
        String serverName = new String(serverNameBytes);

        int serviceNameLen = dis.readInt();
        byte[] serviceNameBytes = new byte[serviceNameLen];
        dis.readFully(serviceNameBytes);
        String serviceName = new String(serviceNameBytes);

        int serviceVersion = dis.readInt();

        int logNameLen = dis.readInt();
        byte[] logNameBytes = new byte[logNameLen];
        dis.readFully(logNameBytes);
        String logName = new String(logNameBytes);

        System.out.printf("Server Name      : %s%n", serverName);
        System.out.printf("Service Name     : %s%n", serviceName);
        System.out.printf("Service Version  : %d%n", serviceVersion);
        System.out.printf("Log Name         : %s%n", logName);

        int vardataTotalLen = dis.readInt();
        boolean cleanShutdown = false;
        if (vardataTotalLen > 0) {
            byte[] varMagic = new byte[8];
            dis.readFully(varMagic);
            if (Arrays.equals(varMagic, VARFIELD_MAGIC)) {
                int rlsVarFieldLen = dis.readInt();
                byte[] rlsVarField = new byte[rlsVarFieldLen];
                dis.readFully(rlsVarField);
                cleanShutdown = (rlsVarField.length > 0 && rlsVarField[0] == 1);

                int serviceDataLen = vardataTotalLen - 8 - 4 - rlsVarFieldLen; //Need to understand this more
                if (serviceDataLen > 0) {
                    dis.skip(serviceDataLen);
                }
            }
        }
        System.out.printf("Clean Shutdown   : %s%n", cleanShutdown ? "YES" : "NO");

        long checkDate = dis.readLong();
        long checkSeq = dis.readLong();
        boolean headerOk = (checkDate == date) && (checkSeq == firstSeq);
        System.out.printf("Header Check   : %s%n", headerOk ? "OK" : "*** INTEGRITY MISMATCH ***");

        if (!headerOk) {
            System.out.printf(" checkDate=%d, expected=%d    checkSeq=%d, expected=%d%n", checkDate, date, checkSeq, firstSeq);
        }
        System.out.println();

        boolean isPartnerlog = logName.toLowerCase().contains("partner");

        //------------------------records

        int recordCount = 0;
        while (dis.available() > 4) {
            byte[] rcrdMagic = new byte[4];
            dis.readFully(rcrdMagic);
            if (!Arrays.equals(rcrdMagic, RCRD_MAGIC)) {
                break;
            }

            recordCount++;

            long headerSeqNum = dis.readLong();
            int dataLen = dis.readInt();
            byte[] recordData = new byte[dataLen];
            dis.readFully(recordData);
            long tailSeqNum = dis.readLong();
            boolean recordOk = (headerSeqNum == tailSeqNum);

            System.out.println(RSEP);
            System.out.printf("RECORD  seq#=%-12d  dataLen=%-6d  integrity=%s%n",
                              headerSeqNum, dataLen, recordOk ? "OK" : "*** BAD TAIL ***");
            System.out.println(RSEP);

            if (recordOk) {
                parseRecoverableUnit(wrap(recordData), isPartnerlog);
            } else {
                System.out.printf("  [Skipped: tail seq# %d != header seq# %d]%n", tailSeqNum, headerSeqNum);
            }
        }

    }

    //Looking at RecoveryManager.java,
    private static void parseRecoverableUnit(DataInputStream dis, boolean isPartnerlog) throws Exception {
        int fsLen = dis.readInt();
        byte[] fsBytes = new byte[fsLen];
        dis.readFully(fsBytes);

        long ruId = dis.readLong();
        short recordType = dis.readShort();

        System.out.printf(" Failure scope : %s%n", parseFailureScope(fsBytes));
        System.out.printf(" RU identity   : %d (0x%016X)%n", ruId, ruId);
        System.out.printf(" Record type   : %s%n",
                          recordType == RECORD_TYPE_NORMAL ? "RECORD_TYPE_NORMAL" : recordType == RECORD_TYPE_DELETED ? "RECORD_TYPE_DELETED" : "Unknown record type: "
                                                                                                                                                + recordType);

        if (recordType == RECORD_TYPE_DELETED) {
            System.out.printf(" [Deletd]   : RU %d has been removed from the log%n", ruId);
        }
        if (recordType != RECORD_TYPE_NORMAL) {
            return;
        }

        while (dis.available() > 4) {
            int sectionId = dis.readInt();
            if (sectionId == END_OF_SECTION) {
                break;
            }

            dis.readShort(); //Section (always 1) not used
            dis.readByte(); //singleData flag
            int numItems = dis.readInt();

            List<byte[]> items = new ArrayList<>();
            for (int i = 0; i < numItems; i++) {
                int size = dis.readInt();
                byte[] data = new byte[size];
                dis.readFully(data);
                items.add(data);
            }

            System.out.printf(" [Section %3d - %s items=%d]%n",
                              sectionId, sectionName(sectionId, isPartnerlog), numItems);
            parseSection(sectionId, items, isPartnerlog);
        }
    }

    private static void parseSection(int sectionId, List<byte[]> items, boolean isPartnerlog) throws Exception {
        for (byte[] data : items) {
            switch (sectionId) {
                case APPLID_DATA_SECTION: {
                    // 20-byte server identity fingerprint.
                    // Generated in TransactionManagerService.createApplicationId() as:
                    //   SHA-256(userDir + serverName + hostName + startupTimeMillis), truncated to 20 bytes.
                    // It is a one-way hash - the original values cannot be recovered from it.
                    System.out.printf("   APPLID (server UUID): %s%n", hex(data));
                    break;
                }

                case EPOCH_DATA_SECTION: {
                    if (data.length >= 4) {
                        int epoch = wrap(data).readInt();
                        System.out.printf("   EPOCH  : %d%n", epoch);
                    } else {
                        System.out.printf("   EPOCH (hex)  : %s%n", hex(data));
                    }
                    break;
                }

                case SERVER_DATA_SECTION: {
                    System.out.printf("   SERVER  : %s%n", new String(data));
                    break;
                }

                case TRAN_STATE_SECTION: {
                    int state = 0;
                    if (data.length >= 4) {
                        state = wrap(data).readInt();
                    } else if (data.length >= 1) {
                        state = data[0] & 0xFF;
                    }
                    System.out.printf("   STATE  : %d (%s)%n", state, TRAN_STATE.getOrDefault(state, "unkown"));
                    break;
                }

                case GLOBALID_SECTION: {
                    printXid(data);
                    break;
                }

                case XARESOURCE_SECTION: {
                    // Each data item: stoken(8) + recoveryId(int32) + seqNo(int16)  [14 bytes]
                    // JTAXAResourceImpl(PartnerLogTable, byte[] tid, byte[] logData)
                    if (data.length >= 14) {
                        DataInputStream dis = wrap(data);
                        long stoken = dis.readLong();
                        int recoveryId = dis.readInt();
                        int seqNo = (dis.readByte() & 0xFF) << 8 | (dis.readByte() & 0xFF);
                        System.out.printf("       XA resource: partnerLogId=%d  branchSeq=%d  stoken=0x%016X%n",
                                          recoveryId, seqNo, stoken);
                    } else {
                        System.out.printf("       XA resource: %s%n", hex(data));
                    }
                    break;
                }

                case RESOURCE_ADAPTER_SECTION: {
                    //created by TransactionState.setState()
                    if (data.length >= 8) {
                        DataInputStream dis = wrap(data);
                        long recoveryId = dis.readLong();
                        System.out.printf("       Recovery ID: %d%n", recoveryId);
                        if (dis.available() > 0) {
                            byte[] rest = new byte[dis.available()];
                            dis.readFully(rest);
                            printXid(rest);
                        }
                    } else {
                        System.out.printf("       Resource adapter (hex): %s%n", hex(data));
                    }
                    break;
                }

                case HEURISTIC_OUTCOME_SECTION: {
                    if (data.length >= 1) {
                        int outcome = data[0] & 0xFF;
                        System.out.printf("       Heuristic outcome: %d  (hex: %s)%n", outcome, hex(data));
                    }
                    break;
                }

                // ── Partner log sections ─────────────────────────────────────

                //stores the next available ID for allocating new partner log entries
                case NEXT_ID_SECTION: {
                    if (data.length >= 8) {
                        long id = wrap(data).readLong();
                        System.out.printf("   Next ID: %d%n", id);
                    } else if (data.length >= 4) {
                        int id = wrap(data).readInt();
                        System.out.printf("   Next ID: %d%n", id);
                    } else {
                        System.out.printf("   Next ID (hex): %s%n", hex(data));
                    }
                    break;
                }

                //enables garbage collection of old partner log entries. Any entry with ID < low watermark can be safely deleted
                case LOW_WATERMARK_SECTION: {
                    if (data.length >= 8) {
                        long wm = wrap(data).readLong();
                        System.out.printf("   Low watermark: %d%n", wm);
                    } else if (data.length >= 4) {
                        int wm = wrap(data).readInt();
                        System.out.printf("   Low watermark: %d%n", wm);
                    } else {
                        System.out.printf("   Low watermark (hex): %s%n", hex(data));
                    }
                    break;
                }

                //help determine whether the server shut down cleanly or crashed during the previous run. 1 - Server was starting, 3- server was stopping
                case SERVER_STATE_SECTION: {
                    if (data.length >= 4) {
                        int state = wrap(data).readInt();
                        System.out.printf("   Server state: %d%n", state);
                    } else {
                        System.out.printf("   Server state: %s%n", hex(data));
                    }
                    break;
                }

                //stores the commit priority for XA resources involved in a transaction. This priority determines the order in which resources are committed during the two-phase commit protocol
                case RESOURCE_PRIORITY_SECTION: {
                    if (data.length >= 4) {
                        int priority = wrap(data).readInt();
                        System.out.printf("   Priority: %d%n", priority);
                    }
                    break;
                }

                //stores serialized XA resource recovery information, contains all the data needed to recreate and recover an XA resource after a server crash or restar
                case XARESOURCEDATA_SECTION: {
                    printXaResourceData(data);
                    break;
                }

                default: {
                    int show = Math.min(data.length, 64); //show maximum of 6 bytes
                    System.out.printf("   data (%d bytes)  : %s%s%n", data.length, hex(Arrays.copyOf(data, show)), data.length > show ? "..." : "");
                    break;
                }
            }
        }
    }

    private static void printXaResourceData(byte[] data) {
        // Format: [classpath bytes] 0x00 [Java-serialized XARecoveryWrapper]
        int nullPos = -1;
        for (int i = 0; i < data.length; i++) {
            if (data[i] == 0) {
                nullPos = i;
                break;
            }
        }

        if (nullPos < 0) {
            System.out.printf("   XA resource data (no null separator, hex): %s%n", hex(data));
            return;
        }

        String classpath = new String(data, 0, nullPos);
        System.out.printf("   Classpath filter : %s%n", classpath.isEmpty() ? "(empty)" : classpath);

        int serialStart = nullPos + 1;
        int serialLen = data.length - serialStart;
        if (serialLen < 4) {
            return;
        }
        byte[] ser = Arrays.copyOfRange(data, serialStart, data.length);
        int serialMagic = ((ser[0] & 0xFF) << 24) | ((ser[1] & 0xFF) << 16)
                          | ((ser[2] & 0xFF) << 8) | (ser[3] & 0xFF);
        if (serialMagic == 0xACED0005) {
            System.out.printf("   Serialized data  : Java-serialized object, %d bytes%n", serialLen);
            extractSerializedClassName(ser);
        } else {
            int show = Math.min(serialLen, 64);
            System.out.printf("   Serialized data  : %d bytes: %s%s%n",
                              serialLen, hex(Arrays.copyOf(ser, show)), serialLen > show ? " ..." : "");
        }

    }

    // Best-effort: extract first class name from Java serialization stream
    static void extractSerializedClassName(byte[] data) {
        try {
            // Scan for TC_CLASSDESC (0x72) followed by a plausible 2-byte length and class name
            for (int i = 4; i < data.length - 3; i++) {
                if ((data[i] & 0xFF) == 0x72) {
                    int len = ((data[i + 1] & 0xFF) << 8) | (data[i + 2] & 0xFF);
                    if (len > 0 && len < 256 && i + 3 + len <= data.length) {
                        String candidate = new String(data, i + 3, len);
                        if (candidate.matches("[\\w.$]+")) {
                            System.out.printf("   Class name       : %s%n", candidate);
                            return;
                        }
                    }
                }
            }
        } catch (Exception e) {
            /* ignore */ }
    }

    private static void printXid(byte[] data) throws Exception {
        if (data.length < 12) {
            System.out.printf("   XID too short (hex) : %s%n", hex(data));
            return;
        }

        DataInputStream dis = wrap(data);
        int formatId = dis.readInt(); //Who created the XID - "WASD"
        int globalTrxIdLen = dis.readInt(); //how many bytes follow the global transaction id - 36
        int branchQualifierLen = dis.readInt(); //how many bytes follow the branch qualifier - 40

        // Try to represent formatId as ASCII
        byte[] fmtBytes = { (byte) (formatId >> 24), (byte) (formatId >> 16), (byte) (formatId >> 8), (byte) formatId };
        boolean printable = true;
        for (byte b : fmtBytes)
            if (b < 0x20 || b > 0x7e) {
                printable = false;
                break;
            }
        String fmtLabel = printable ? " (\"" + new String(fmtBytes) + "\")" : "";

        System.out.printf("       XID  formatId=0x%08X%s  globalTrxIdLen=%d  branchQualifierLen=%d%n",
                          formatId, fmtLabel, globalTrxIdLen, branchQualifierLen);

        //from XidIml.toBytes()
        if (dis.available() >= globalTrxIdLen + branchQualifierLen) {
            byte[] globalTrxId = new byte[globalTrxIdLen];
            byte[] branchQualifier = new byte[branchQualifierLen];
            dis.readFully(globalTrxId);
            dis.readFully(branchQualifier);
            System.out.printf("       globalTrxId : %s%n", hexWrapped(globalTrxId));
            System.out.printf("       branchQualifier : %s%n", hexWrapped(branchQualifier));
        }
    }

    private static String sectionName(int sectionId, boolean isPartnerlog) {
        switch (sectionId) {
            case APPLID_DATA_SECTION:
                return "APPLID_DATA_SECTION";
            case EPOCH_DATA_SECTION:
                return "EPOCH_DATA_SECTION";
            case SERVER_DATA_SECTION:
                return "SERVER_DATA_SECTION";
            case TRAN_STATE_SECTION:
                return isPartnerlog ? "unknown_0" : "TRAN_STATE_SECTION";
            case XARESOURCE_SECTION:
                return isPartnerlog ? "unknown_2" : "XARESOURCE_SECTION";
            case GLOBALID_SECTION:
                return isPartnerlog ? "unknown_3" : "GLOBALID_SECTION";
            case RESOURCE_ADAPTER_SECTION:
                return "RESOURCE_ADAPTER_SECTION";
            case HEURISTIC_OUTCOME_SECTION:
                return "HEURISTIC_OUTCOME_SECTION";
            case NEXT_ID_SECTION:
                return "NEXT_ID_SECTION";
            case LOW_WATERMARK_SECTION:
                return "LOW_WATERMARK_SECTION";
            case SERVER_STATE_SECTION:
                return "SERVER_STATE_SECTION";
            case XARESOURCEDATA_SECTION:
                return "XARESOURCEDATA_SECTION";
            case RESOURCE_PRIORITY_SECTION:
                return "RESOURCE_PRIORITY_SECTION";

            default:
                return "section: " + sectionId;
        }
    }

    private static String parseFailureScope(byte[] data) {
        if (data.length < 2) {
            return "(empty)";
        }
        try {
            DataInputStream dis = wrap(data);
            int factoryId = dis.readUnsignedByte();
            int version = dis.readUnsignedByte();
            String factory;
            switch (factoryId) {
                case 1:
                    factory = "FILE_FAILURE_SCOPE_ID";
                    break;
                case 2:
                    factory = "SERVANT_FAILURE_SCOPE_ID";
                    break;
                case 3:
                    factory = "CONTROLLER_FAILURE_SCOPE_ID";
                    break;
                case 4:
                    factory = "EPOCH_FAILURE_SCOPE_ID";
                    break;
                default:
                    factory = "Unknown factory Id: " + factoryId;
            }

            if (dis.available() >= 2) {
                return String.format("%s[v%d] server=%s", factory, version, dis.readUTF());
            }
            return String.format("%s[v%d]", factory, version);
        } catch (Exception e) {
            return "(parse error: " + e.getMessage() + ") hex=" + hex(data);
        }
    }

    //Hexinghelper
    private static String hex(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "(empty)";
        }

        StringBuilder sb = new StringBuilder(bytes.length * 3);
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0) {
                sb.append(' ');
            }
            sb.append(String.format("%02X", bytes[i] & 0xFF));
        }
        return sb.toString();
    }

    // Hex with line-wrapping at 16 bytes; continuation lines get the given prefix
    static String hexWrapped(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "(empty)";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0 && i % 16 == 0)
                sb.append("\n").append("                ");
            else if (i > 0)
                sb.append(' ');
            sb.append(String.format("%02X", bytes[i] & 0xFF));
        }
        return sb.toString();
    }

    private static String formatDate(long ms) {
        if (ms <= 0 || ms >= 4_000_000_000_000L) {
            return String.valueOf(ms);
        }
        return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS z").format(new Date(ms));
    }

    private static String getStatusName(int status) {
        switch (status) {
            case STATUS_INACTIVE:
                return "INACTIVE";
            case STATUS_ACTIVE:
                return "ACTIVE";
            case STATUS_KEYPOINTING:
                return "KEYPOINTING";
            default:
                return "unknown(" + status + ")";
        }

    }

    private static DataInputStream wrap(byte[] data) {
        return new DataInputStream(new ByteArrayInputStream(data));
    }

    //entry
    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            System.out.println("**********Provide the log path**********");
            System.exit(1);
        }

        Path path = Paths.get(args[0]);
        if (!Files.exists(path)) {
            System.out.println("**********Log path not found**********");

            System.exit(1);
        }

        dumpFile(path);
    }

}
