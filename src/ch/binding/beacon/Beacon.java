/*
 * Copyright 2020 Carl Binding
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ch.binding.beacon;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.Properties;
import java.util.Random;
import java.util.Timer;
import java.util.TimerTask;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import ch.binding.beacon.db.SQLiteIDStore;
import ch.binding.beacon.hci.HCIParser;
import ch.binding.beacon.hci.HCI_Command;
import ch.binding.beacon.hci.HCI_CommandComplete;
import ch.binding.beacon.hci.HCI_CommandStatus;
import ch.binding.beacon.hci.HCI_ConnectionComplete;
import ch.binding.beacon.hci.HCI_EventHandler;
import ch.binding.beacon.hci.HCI_InquiryComplete;
import ch.binding.beacon.hci.HCI_InquiryResult;
import ch.binding.beacon.hci.HCI_PDU;
import ch.binding.beacon.hci.HCI_Event;
import ch.binding.beacon.hci.HCI_PDU_Handler;
import ch.binding.beacon.hci.LE_AdvertisingReport;
import ch.binding.beacon.hci.LE_AdvertisingReport.ADV_DIRECT_IND_Report;
import ch.binding.beacon.hci.LE_AdvertisingReport.ADV_IND_Report;
import ch.binding.beacon.hci.LE_AdvertisingReport.ADV_NONCONN_IND_Report;
import ch.binding.beacon.hci.LE_AdvertisingReport.ADV_SCAN_IND_Report;
import ch.binding.beacon.hci.LE_AdvertisingReport.AdvertisingReport;
import ch.binding.beacon.hci.LE_AdvertisingReport.ContactDetectionServiceReport;
import ch.binding.beacon.hci.LE_AdvertisingReport.DP3TServiceReport;
import ch.binding.beacon.hci.LE_AdvertisingReport.SCAN_RSP_Report;

import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


public class Beacon implements HCI_PDU_Handler, HCI_EventHandler {
	
	private static final long ONE_MIN_MSECS = 60 * 1000;
	private static final long ONE_HR_MSECS = 60 * ONE_MIN_MSECS;
	private static final long ONE_DAY_MSECS = 24 * ONE_HR_MSECS;
	
	/***
	 * file name for properties
	 */
	static final String PROPERTIES_FILE_NAME = "beacon.properties";
	
	static final String DB_FN = "/home/carl/workspace/beacon/sqlite/proximity_id_store.db";
	
	static String getDBFN() {
		return DB_FN;
	}
	
	/***
	 * we save output of hcidump into a file when scanning for other beacons
	 */
	static final String HCI_DUMP_FILE_NAME = "/tmp/hcidump_beacon.trace";
	
	static final int UUID_HEX_LEN = "93 48 59 7e 81 a2 11 ea 97 22 90 61 ae c6 7c 30".length();
	
	// iBeacon stuff
	
	// Bluetooth company IDs. see bluetooth.com. LSB order of 16 bit hex value
	public static final String APPLE_ID = "4C 00";
	public static final String GOOGLE_ID = "E0 00";
	public static final String IBM_ID = "03 00";
	
	public static final String APPLE_IBEACON_PREFIX = "1a ff 4c 00 02 15";
	
	// MSB byte ordering for major & minor
	public static final String APPLE_IBEACON_MAJOR = "00 01";
	public static final String APPLE_IBEACON_MINOR = "00 01";
	
	// public static final String APPLE_IBEACON_TX_POWER = "c5";
	
	// when sending out an Apple iBeacon, we use the rolling proximity ID as payload.
	enum AppType { I_BEACON, APPLE_GOOGLE_CONTACT_TRACING};
	
	// we can switch between Apple iBeacon format and the Apple & Google Exposure Notification formats
	final private AppType appType = AppType.APPLE_GOOGLE_CONTACT_TRACING; // .I_BEACON; // .APPLE_GOOGLE_CONTACT_TRACING;
	
	AppType getAppType() {
		return this.appType;
	}
	
	/***
	 * to convert from dBm into mW
	 * @param dbm power in dBm
	 * @return power in milli-watt
	 */
	public static double dBm2mW( double dbm) {
		return Math.pow(10, dbm/10.0);
	}
	
	/***
	 * 
	 * @param mw power in milli-watt
	 * @return power in dBm
	 */
	public static double mW2dBm( double mw) {
		return 10.0 * Math.log10(mw);
	}
	
	/***
	 * to enable/disable usage of BT random addresses
	 */
	private boolean useRandomAddr = true;
	
	boolean useRandomAddr() {
		return this.useRandomAddr;
	}
	
	// we need to read the TX Power from the HCI BLE world. which is of course painful using hcitools & friends.
	// BLUETOOTH CORE SPECIFICATION Version 5.2 | Vol 4, Part E	page 2486
	// 7.8.6 LE Read Advertising Physical Channel Tx Power command
	// Range: -127 to 20
	// the value to use is *not* the raw sending power, but the sender's power 1 m away from the antenna...
	static int hciTxPower = Integer.MAX_VALUE;		
	
	// exposure notification Google & Apple
	
	public static final int ADVERTISING_INTERVAL_IBEACON = 100; // msecs
	public static final int ADVERTISING_INTERVAL_CONTACT_TRACING = 200; // msecs
	
	/***
	 * size in octets of the rolling proxy id as per Advertising Payload specs
	 */
	public static final int ROLLING_PROXY_ID_LENGTH = 16;
	
	/***
	 * 4 bytes in addition to the rolling proxy id as per Advertising Payload specs version 1.1
	 */
	public static final int ASSOCIATED_META_DATA_LENGTH = 4;
	
	/***
	 * we iterate over these 3 states...
	 *
	 */
	static enum State {
		ADVERTISING,   // beacon is advertising
		SCANNING,      // beacon is scanning
		IDLE           // beacon is idle
	}
	
	/***
	 * beacon can be advertising, scanning, or idling.
	 */
	private State state;
	
	public State getState() {
		return this.state;
	}
	
	public void setState( State s) {
		this.state = s;
	}
	
	// flag to indicate if BT addr and rolling proximity ID are to be renewed.
	private boolean changeAddressFlag = false;
	
	public synchronized void setChangeAddressFlag( boolean flag) {
		this.changeAddressFlag = flag;
	}
	
	public synchronized boolean getChangeAddressFlag() {
		return this.changeAddressFlag;
	}
	
	/***
	 * period of beacon cycle.
	 */
	private static final long BEACON_PERIOD = 30*1000; // msecs
	
	/***
	 * duration of advertising phase. 
	 * milliseconds.
	 */
	private static final long BEACON_ADVERTISING_DURATION = 10*1000;  // msecs
	
	/***
	 * duration of scanning phase. we use hcidump to get incoming advertisement. using --duplicates that may be quite a bit of data.
	 * milliseconds
	 */
	private static final long BEACON_SCANNING_DURATION = 10*1000;    // msecs
	
	
	// variables so we can use properties...
	private static long beaconPeriod = BEACON_PERIOD;
	
	private static long beaconAdvertisingDuration = BEACON_ADVERTISING_DURATION;
	private static long beaconScanningDuration = BEACON_SCANNING_DURATION;
	
	private static long getBeaconPeriod() {
		return beaconPeriod;
	}
	
	private static long getBeaconAdvertisingDuration() {
		return beaconAdvertisingDuration;
	}
	
	private static long getBeaconScanningDuration() {
		return beaconScanningDuration;
	}
	
	private static long getBeaconIdleDuration() {
		return beaconPeriod - beaconAdvertisingDuration - beaconScanningDuration;
	}
	
	/***
	 * the rolling proximity ID shall be changed once so often. The specs link the
	 * change to a change of BLE (random) address. We don't do this for now and use
	 * the fixed BT_ADDR of the Linux box. But we change the rolling-proximity-ID
	 * using this interval
	 * 
	 * milli-secs
	 */
	private static final long ROLLING_PROXIMITY_INTERVAL = 10*60*1000; // msecs
		
	// BLUETOOTH CORE SPECIFICATION Version 5.2 | Vol 4, Part E,	page 2483
	// Advertising_Type:
	public static final byte ADV_IND = 0x00;
	public static final byte ADV_DIRECT_IND_HIGH_DUTY = 0x01;
	public static final byte ADV_SCAN_IND = 0x02;
	public static final byte ADV_NONCONN_IND = 0x03;
	public static final byte ADV_DIRECT_IND_LOW_DUTY = 0x04;
	
	public static final byte Own_Address_Type_Public_Device_Address = 0x00;
	public static final byte Own_Address_Type_Random_Device_Address = 0x01;
	public static final byte Own_Address_Type_Resolvable_Private_Address_Public_Address = 0x02;
	public static final byte Own_Address_Type_Resolvable_Private_Address_LE_Set_Random_Address = 0x03;
	
	public static final byte Advertising_Channel_37 = 0x01;
	public static final byte Advertising_Channel_38 = 0x02;
	public static final byte Advertising_Channel_39 = 0x04;
	
	/***
	 * 
	 * @param arr
	 * @param reverseOrder: most-significant-byte first or least-significant-byte first...
	 * @param spaceSeparated: if true, insert spaces between hex-digits of bytes.
	 * @return hex representation of array data, space separated
	 */
	public static String byteArrToHex( byte [] arr, boolean reverseOrder, boolean withSpaces) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < arr.length; i++) {
			
            if ( withSpaces && i > 0)
            	sb.append( " ");
           
            if ( reverseOrder) {
            	sb.append( String.format("%02x", arr[i]));
            } else {
            	sb.append( String.format("%02x", arr[arr.length-1-i]));
            }
        }
		return sb.toString();
		
	}
	
	/***
	 * 
	 * @param s hexadecimal string, 2 hex digits per byte. no space.
	 * @return byte-array
	 */
	public static byte[] hexStrToBytes( String s) {
		if ( s == null) {  
			throw new IllegalArgumentException();
		}
		
		final int sl = s.length();
		if ( sl == 0 || sl % 2 != 0) {
			throw new IllegalArgumentException();
		}
		
		final byte b[] = new byte[sl/2];
		for ( int i = 0; i < b.length; i++) {
			final String ss = s.substring( i*2, (i+1)*2);
			final int j = Integer.parseInt( ss, 0x10);
			b[i] = (byte) (j & 0xFF);
		}
		return b;
	}
	
	/***
	 * converts a 16 byte array into a hex-dec string
	 * @param rollingProxyID
	 * @param msb most-significant byte first or last (MSB vs LSB)
	 * @return hex-dec string
	 */
	public static String proxyToHex(byte[] rollingProxyID, boolean msb) {
		assert( rollingProxyID != null && rollingProxyID.length == Beacon.ROLLING_PROXY_ID_LENGTH);
		final String s = byteArrToHex( rollingProxyID, msb, true);
		assert( s.length() == UUID_HEX_LEN);
		return s;
	}
	
	// significant length of iBeacon signal data
	private final static String IBEACON_SIGNIFICANT_DATA_LEN = "1e";
	
	// Flags as per Supplement to the Bluetooth Core Specification
	// 1.3 Flags
	//  LE General Discoverable Mode | BR/EDR Not Supported. Bit 37 of LMP Feature Mask Definitions (Page 0)
	//  bit pos 1 & 2: 0x06
	//  len (1) data type (1) value (1):  2 bytes long, data type == 01 == Flags, flag value == 06
	private final static String IBEACON_ADV_DATA_TYPE_FLAGS="02 01 06";

	public static final String LOG_FILE_NAME = "/tmp/beacon_log.txt";
	
	/***
	 * convert a signed Java integer value into an 8 bit two's complement positive Java integer.
	 * 
	 * @param i a Java integer in the range -128..127
	 * @return an positive Java integer in the range 0..255
	 * 
	 * @throws IllegalArgumentException
	 */
	public static int twosComplement8Bit( final int i ) {
		if ( i < -128 || i > 127) {
			throw new IllegalArgumentException( "8 bit value out of range: " + Integer.toString(i));
		}
		int ui = 0;
		if ( i < 0) {
			ui = (0x80 | (hciTxPower & 0x7F)) & 0xFF;
		} else {
			ui = hciTxPower & 0x7F;
		}
		// unsigned 8 bit value...
		assert( ui >= 0 && ui <= 0xFF);
		
		return ui;
	}
	
	public static String getSetRandomBTAddrCmd( byte [] btRandomAddr) {
		StringBuffer sb = new StringBuffer();
		sb.append( String.format( "0x%02x 0x%04x ", HCI_Command.HCI_LE_Controller_OGF, HCI_Command.HCI_LE_Set_Random_Address_OCF));
		
		// space separated, unchanged byte order. LSB first
		String addrStr = Beacon.byteArrToHex( btRandomAddr, true, true);
		sb.append( addrStr);
		
		return sb.toString();
	}
	
	/**
	 * 
	 * @param rollingProxyID
	 * @return a command string which can be passed to HCI for an Apple iBeacon advertising data packet
	 */
	public static String getIBeaconSetAdvertisementDataCmd( byte [] rollingProxyID, int hciTxPower) {
		
		// 7.8.7 LE Set Advertising Data command
		// BLUETOOTH CORE SPECIFICATION Version 5.2 | Vol 4, Part E,	page 2487
		
		String beaconUUID = Beacon.proxyToHex( rollingProxyID, true);
		assert( beaconUUID != null && beaconUUID.length() == Beacon.UUID_HEX_LEN);
		
		StringBuffer sb = new StringBuffer();
		sb.append( String.format( "0x%02x 0x%04x ", HCI_Command.HCI_LE_Controller_OGF, HCI_Command.HCI_LE_Set_Advertising_Data_OCF));
		
		sb.append( IBEACON_SIGNIFICANT_DATA_LEN + " ");
		sb.append( IBEACON_ADV_DATA_TYPE_FLAGS + " ");
		sb.append( APPLE_IBEACON_PREFIX + " ");
		sb.append( beaconUUID + " ");
		sb.append( APPLE_IBEACON_MAJOR + " ");
		sb.append( APPLE_IBEACON_MINOR + " ");
		
		// two's complement
		int txPwr = twosComplement8Bit( hciTxPower);
		
		/*
		if ( hciTxPower < 0) {
			txPwr = (0x80 | (hciTxPower & 0x7F)) & 0xFF;
		} else {
			txPwr = hciTxPower & 0x7F;
		}
		*/
		sb.append( String.format( "%02x ", (txPwr & 0xFF)));
		
		sb.append( "00"); // to make the length 31		
		
		return sb.toString();
	}
	
	/***
	 * 
	 * @param duration in milli-secs
	 * @return nbr of intervals in LSB
	 */
	public static String getAdvertisingInterval( double duration) {
		final int nbrIntervals = (int) (duration / 0.625);
		
		assert( 0x0020 <= nbrIntervals && nbrIntervals <= 0x4000);
		
		final String s = String.format( "%02x %02x ", (nbrIntervals & 0xFF), ((nbrIntervals >> 8) & 0xFF));
		
		return s;
		
	}
	
	// BLUETOOTH CORE SPECIFICATION Version 5.2 | Vol 4, Part E,	page 2482
	// 7.8.5 LE Set Advertising Parameters command
	private static String getIBeaconSetAdvertisementParametersCommand( boolean useRandomAddr) {
		StringBuffer sb = new StringBuffer();
		
		sb.append( String.format( "0x%02x 0x%04x ", HCI_Command.HCI_LE_Controller_OGF, HCI_Command.HCI_LE_Set_Advertising_Parameters_OCF));
		
		String advertisingInterval = getAdvertisingInterval( Beacon.ADVERTISING_INTERVAL_IBEACON);
		
		// sb.append( "a0 00 ");  // Advertising_Interval_Min:	Size: 2 octets
		// sb.append( "a0 00 ");  // Advertising_Interval_Max:	Size: 2 octets
		
		sb.append( advertisingInterval);   // Advertising_Interval_Min:	Size: 2 octets
		sb.append( advertisingInterval);   // Advertising_Interval_Max:	Size: 2 octets
		
		sb.append( String.format( "%02x ", ADV_NONCONN_IND));     // Advertising_Type:	Size: 1 octet
		
		final byte ownAddrType = useRandomAddr?Beacon.Own_Address_Type_Random_Device_Address:Own_Address_Type_Public_Device_Address;
		
		sb.append( String.format( "%02x ", ownAddrType));                                // Own_Address_Type:	Size: 1 octet
		sb.append( String.format( "%02x ", Own_Address_Type_Public_Device_Address));     // Peer_Address_Type: Size: 1 octet
		
		sb.append( "00 00 00 00 00 00 "); // Peer_Address: Size: 6 octets
		// Advertising_Channel_Map: Size: 1 octet
		sb.append(  String.format( "%02x ", Advertising_Channel_37 | Advertising_Channel_38 | Advertising_Channel_39));
		sb.append( "00");    // Advertising_Filter_Policy: Size: 1 octet
		return sb.toString();
	}
	
	
	// BLUETOOTH CORE SPECIFICATION Version 5.2 | Vol 4, Part E,	page 2482
	// 7.8.5 LE Set Advertising Parameters command
	private static String getContactTracingSetAdvertisingParametersCommand( boolean useRandomAddr) {
		StringBuffer sb = new StringBuffer();
		sb.append( String.format( "%02x %04x ", HCI_Command.HCI_LE_Controller_OGF, HCI_Command.HCI_LE_Set_Advertising_Parameters_OCF));
		
		String advertisingInterval = getAdvertisingInterval( Beacon.ADVERTISING_INTERVAL_CONTACT_TRACING);
		sb.append( advertisingInterval);  // Advertising_Interval_Min:	Size: 2 octets
		sb.append( advertisingInterval);  // Advertising_Interval_Max:	Size: 2 octets
		
		// Advertising_Interval_Min:	Size: 2 octets
		// sb.append( String.format( "%02x %02x ", ((nbrIntervals >> 8) & 0xFF), (nbrIntervals & 0xFF)));
		
		// Advertising_Interval_Max:	Size: 2 octets
		// sb.append( String.format( "%02x %02x ", ((nbrIntervals >> 8) & 0xFF), (nbrIntervals & 0xFF)));
		
		// sb.append( "a0 00 ");  // Advertising_Interval_Min:	Size: 2 octets
		// sb.append( "a0 00 ");  // Advertising_Interval_Max:	Size: 2 octets
		
		// 0x03 Non connectable undirected advertising (ADV_NONCONN_IND)
		sb.append( String.format( "%02x ", ADV_NONCONN_IND));    // Advertising_Type:	Size: 1 octet
		
		
		final byte ownAddrType = useRandomAddr?Beacon.Own_Address_Type_Random_Device_Address:Own_Address_Type_Public_Device_Address;
		
		sb.append( String.format( "%02x ", ownAddrType));     							 // Own_Address_Type:	Size: 1 octet
		sb.append( String.format( "%02x ", Own_Address_Type_Public_Device_Address));     // Peer_Address_Type: Size: 1 octet
		
		sb.append( "00 00 00 00 00 00 "); // Peer_Address: Size: 6 octets
		
		// Advertising_Channel_Map: Size: 1 octet
		sb.append(  String.format( "%02x ", Advertising_Channel_37 | Advertising_Channel_38 | Advertising_Channel_39));
		
		sb.append( "00");    // Advertising_Filter_Policy: Size: 1 octet
		
		return sb.toString();
	}
	
	/***
	 * to get the Exposure Notification Advertising Payload in a format to be used by hcitool
	 * @param rollingProxyID
	 * @param txPowerLevel
	 * @return a command string for hcitool
	 */
	public static String getContactTracingSetAdvertisingDataCommand( byte [] rollingProxyID, final int txPowerLevel) {
		
		// the unencrypted meta-data. is null for crypto version 1...
		final byte metaData[] = ContactDetectionService.getMetaData(txPowerLevel);
		
		
		// which is then encrypted...
		byte encryptedMetaData[] = null;
		try {
			
			// use the current key stuff, thus passing no temp exposure key nor an ENIN.
			encryptedMetaData = (metaData==null)?null:Crypto.getAssociatedEncryptedMetadata(metaData, null, -1);
			
		} catch (Exception e) {
			logger.severe( e.getMessage());
			e.printStackTrace();
			return null;
		}
		
		assert( encryptedMetaData == null || encryptedMetaData.length == Beacon.ASSOCIATED_META_DATA_LENGTH);
		
		final byte[] contactDetectionService = ContactDetectionService.toBytes( rollingProxyID, encryptedMetaData);
		
		StringBuffer sb = new StringBuffer();
		sb.append( String.format( "%02x %04x ", HCI_Command.HCI_LE_Controller_OGF, HCI_Command.HCI_LE_Set_Advertising_Data_OCF));
		
		// The number of significant octets in the Advertising_Data.
		assert( contactDetectionService.length == ContactDetectionService.CONTACT_DETECTION_SERVICE_LENGTH ||
				contactDetectionService.length == (ContactDetectionService.CONTACT_DETECTION_SERVICE_LENGTH + Beacon.ASSOCIATED_META_DATA_LENGTH));
		
		byte advertisingDataLength = ContactDetectionService.CONTACT_DETECTION_SERVICE_LENGTH;
		
		// BLUETOOTH CORE SPECIFICATION Version 5.2 | Vol 4, Part E	page 2487
		// 7.8.7 LE Set Advertising Data command
		// 31 octets of advertising data formatted as defined in [Vol 3] Part C, Section 11.
		// the Exposure Notification Service, Advertising Payload uses all 31 bytes
		// 3 bytes flags, 4 bytes service UUID, service data: 1 byte len, 1 byte type, 2 bytes exposure notification service, 20 bytes rolling-proximity-ID | associated encrypted meta-data
		byte advertisingData[] = new byte[HCI_Command.ADVERTISING_DATA_LENGTH];
		
		// BLUETOOTH CORE SPECIFICATION Version 5.2 | Vol 3, Part C,	page 1392
		// 11 ADVERTISING AND SCAN RESPONSE DATA FORMAT
		
		// Supplement to Bluetooth Core Specification | CSSv7, Part A	page 9
		// 1 DATA TYPES DEFINITIONS AND FORMATS
		
		// Contact Detection Service uses 3 data types:
		// Flags
		// Services UUID 16 bit
		// Service data 16 bit UUID with 16 bytes service-data + 4 bytes of meta-data (encrypted) payload
		System.arraycopy( contactDetectionService, 0, advertisingData, 0, contactDetectionService.length);
		
		if (encryptedMetaData != null) {
			// crypto version 2: append the encrypted meta data which are 4 bytes
			assert( encryptedMetaData.length == Beacon.ASSOCIATED_META_DATA_LENGTH);
			assert( advertisingData.length <= advertisingDataLength + Beacon.ASSOCIATED_META_DATA_LENGTH);
			
			System.arraycopy( encryptedMetaData, 0, advertisingData, advertisingDataLength, encryptedMetaData.length);
			advertisingDataLength += encryptedMetaData.length;
		}
		
		// the payload is length (1 byte) || advertising data (31 bytes) which may include the encrypted meta data.
		sb.append( String.format( "%02x ", advertisingDataLength));
		sb.append( Beacon.byteArrToHex( advertisingData, true, true));
		
		final String cmd = sb.toString();
		return cmd;
	}
	
	public static String getSetAdvertisingEnableCmd( boolean enable) {
		StringBuffer sb = new StringBuffer();
		sb.append( String.format( "0x%02x 0x%04x ", HCI_Command.HCI_LE_Controller_OGF, HCI_Command.HCI_LE_Set_Advertising_Enable_OCF));
		
		// command parameters: Advertising_Enable, 1 octet
		// 01: enable, 00: disable
		sb.append( enable?"01":"00");
		
		return sb.toString();
	}
	
	public static String getReadAdvertisingPhysicalChannelTxPower() {
		// BLUETOOTH CORE SPECIFICATION Version 5.2 | Vol 4, Part E	page 2486
		// 7.8.6 LE Read Advertising Physical Channel Tx Power command
		StringBuffer sb = new StringBuffer();
		sb.append( String.format( "0x%02x 0x%04x ", HCI_Command.HCI_LE_Controller_OGF, HCI_Command.HCI_LE_Read_Advertising_Physical_Channel_Tx_Power_OCF));
		
		return sb.toString();
	}
	
	private static Logger logger = Logger.getLogger(Beacon.class.getName());

	// properties for the application
	private static Properties appProps;
	
	static Properties getProps() {
		return appProps;
	}
	
	public static Logger getLogger() {
		return logger;
	}
	
	static {
		
		try {
			
			FileHandler fh = new FileHandler( Beacon.LOG_FILE_NAME);
			logger.addHandler( fh);
			SimpleFormatter formatter = new SimpleFormatter();  
	        fh.setFormatter(formatter);  
	        
		} catch (SecurityException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}   
		
		logger.setLevel( Level.ALL);
	}
	
	/***
	 * we have seen during scanning or during advertising an incoming LE_AdvertisingReport event which
	 * we take apart further as it may contain multiple AdvertisingReports.
	 * 
	 * @param advRep LE_AdvertisingReport	  
	 * @param timeOfCapture
	 * 
	 * @return success/failure
	 */
	private boolean handle_LE_AdvertisingReport( LE_AdvertisingReport advRep, Date timeOfCapture) {
		
		if ( this.getAppType() == Beacon.AppType.I_BEACON)
			return true;
		if ( this.idStore == null) {
			logger.warning( "no ID store when handling LE_AdvertisingReport");
			return false;
		}
		
		final int nbrReports = advRep.getNumberReports();
		
		for ( int i = 0; i < nbrReports; i++) {
			try {
				
				AdvertisingReport ar = advRep.getAdvertisingReport(i);
				// further narrow the AdvertisingReport...
				ar = ar.parse();
				
				
				if ( ar instanceof ADV_NONCONN_IND_Report) {
					
					// these are the ones we are expecting for contact tracing... try to parse the report further
					final ADV_NONCONN_IND_Report advNonConnIndRep = ((ADV_NONCONN_IND_Report) ar).parse();
					
					// this is the case for the Apple & Google protocol
					if ( advNonConnIndRep instanceof ContactDetectionServiceReport) {
						
						// finally we got a contact detection event...
						final ContactDetectionServiceReport cdsr = (ContactDetectionServiceReport) advNonConnIndRep;
						
						String cdsrPayload = cdsr.getContactDetectionService().toHex( true);
						int rssi = cdsr.getRSSI();
													
						String serviceData = cdsr.getContactDetectionService().serviceDataToHex();
						
						logger.info( String.format( "cdsr: %s %s %d", timeOfCapture.toString(), cdsrPayload, rssi));
						
						this.idStore.store( serviceData, rssi, timeOfCapture);
						
					} else if ( advNonConnIndRep instanceof DP3TServiceReport) {
						// DP3T protocol
					} else {
						// logger.info( "ADV_NONCONN_IND: not a ContactDetectionServiceReport: " + ar.toString());
					}
				} else if ( ar instanceof ADV_IND_Report) {
				} else if ( ar instanceof ADV_DIRECT_IND_Report) {
				} else if ( ar instanceof ADV_SCAN_IND_Report) {
				} else if ( ar instanceof SCAN_RSP_Report) {
				} else {
					logger.warning( "unhandled AdvertisingReport: " + ar.toString());
				}
			} catch (Exception e) {
				logger.severe( e.getMessage());
				e.printStackTrace();
				return false;
			}
		}	
		return true;
	}
	
	/*** 
	 * callback during parsing of a hcidump trace file for events gotten in hcidump trace during the scanning phase
	 */
	@Override
	public boolean onPDU( HCI_PDU pdu) {
		
		if ( pdu instanceof LE_AdvertisingReport) {
			
			Date timeOfCapture = new Date( pdu.getTimeOfCapture());
			
			return this.handle_LE_AdvertisingReport( (LE_AdvertisingReport) pdu, timeOfCapture);
		
		}
		
		return true;
	}
	
	/***
	 * additional event handling for events of interest which we receive from hcitool and scripts during advertising...
	 * This does happen...
	 */
	@Override
	public boolean onEvent( HCI_Event evt) {
		if ( evt instanceof HCI_CommandComplete) {
		} else if ( evt instanceof HCI_CommandStatus) {
		} else if ( evt instanceof HCI_InquiryComplete) {
		} else if ( evt instanceof HCI_InquiryResult) {
		} else if ( evt instanceof HCI_ConnectionComplete) {
		} else if ( evt instanceof LE_AdvertisingReport) {
			final LE_AdvertisingReport le_ar = (LE_AdvertisingReport) evt;
			Date timeOfCapture = new Date(); // current time
			return this.handle_LE_AdvertisingReport( le_ar, timeOfCapture);
		} else {
			logger.warning( "unhandled event: " + evt.toString());
		}
		return true;
	}
	
	/***
	 * to parse and narrow incoming HCI events and testing the status value for some HCI_Events we get back from hcitool.
	 * This routine is called for every incoming event, independent of additional event handlers onEvent().
	 * 
	 * @param hciEvent
	 * 
	 * @return null if event needs no further handling or the possibly parsed/narrowed event.
	 */
	private static HCI_Event handleHCIEvent( final String hciEvent) {
		try {
			
			HCI_Event hciEvt = new HCI_Event(hciEvent).parse();
			// System.err.println("HCI_Event: " + hciEvt.toString());
			
			if ( hciEvt instanceof HCI_CommandComplete) {
				
				byte status = ((HCI_CommandComplete) hciEvt).getStatus();
				if ( status != 0x00) {
					HCI_Command.ErrorCode ec = HCI_Command.getErrorCode(status);
					logger.severe( String.format( "error 0x%02x, \"%s\" in HCI_CommandComplete: %s", ec.code, ec.name, hciEvt.toString()));
				}
				return null; // no further handling of event...
				
			} else if ( hciEvt instanceof HCI_CommandStatus) {
				
				byte status = ((HCI_CommandStatus) hciEvt).getStatus();
				if ( status != 0x00) {
					HCI_Command.ErrorCode ec = HCI_Command.getErrorCode(status);
					logger.severe( String.format( "error 0x%02x, \"%s\" in HCI_CommandStatus: %s", ec.code, ec.name, hciEvt.toString()));
				}
				return null; // no further handling of event...
				
			} else if ( hciEvt instanceof HCI_InquiryComplete) {
				logger.info( "HCI_InquiryComplete: " + hciEvt.toString());
			} else if ( hciEvt instanceof HCI_InquiryResult) {
				logger.info( "HCI_InquiryResult: " + hciEvt.toString());
			} else if ( hciEvt instanceof HCI_ConnectionComplete) {
				logger.info( "HCI_ConnectionComplete: " + hciEvt.toString());
			} else if ( hciEvt instanceof LE_AdvertisingReport) {
				// we get an incoming LE_AdvertisingReport while advertising?
				logger.info( "LE_AdvertisingReport: " + hciEvt.toString());
				logger.info( hciEvt.toString());
			} else {
				logger.warning( "No narrowing for HCI_Event in HCI response: " + hciEvt.toString());
			}
			return hciEvt;
			
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
		
	}
	
	/***
	 * to run a shell script passing it the name of the script and a bunch of environment variables.
	 * we expect the shell script to contain hcitool commands which return a bunch of command-complete events.
	 * evidently this is all pretty clumsy and gross. but that's the way I could tame bluez on Linux for now.
	 * 
	 * @param script
	 * @param envVars array of strings passed to the script as environment variables, format is "ENV_VAR_NAME=value"
	 * @param eventHandler up-call for specialized event handling.
	 * @param lineHandler to handle all lines which are not part of an "> HCI Event" response string from HCI.
	 * 
	 * @return success/failure
	 */
	private static boolean runScript( String script, String [] envVars, 
			HCI_EventHandler eventHandler, ScriptLineHandler lineHandler) {
		
		try {
			Process process = Runtime.getRuntime().exec(script, envVars);
			
			int exitStatus = process.waitFor();
			if ( exitStatus < 0) {
				logger.severe( "runCommands: process exit status: " + String.valueOf( exitStatus));
			}
			
			BufferedReader stdInput = new BufferedReader(new InputStreamReader(process.getInputStream()));
			BufferedReader stdError = new BufferedReader(new InputStreamReader(process.getErrorStream()));
			
			String s = null;
			StringBuffer sb = null;				
			
			while ((s = stdInput.readLine()) != null) {
				
				System.err.println( "stdout: " + s);

				// responses from hcitool start with an "> HCI Event:" string, followed by some length indication 
				// HCI Events are split across two lines... it seems
				// otherwise we can detect the end of an HCI Event by using some length value which comes along on the first line
				if (s.startsWith("> HCI Event:")) {
					sb = new StringBuffer(s);
				} else {
					if (sb != null) {
						sb.append(s);		
						HCI_Event evt = handleHCIEvent( sb.toString());
						// callback for the event
						if ( evt != null && eventHandler != null) {
							eventHandler.onEvent( evt);
						}
						sb = null;							
					} else {
						if ( lineHandler != null) {
							lineHandler.onStdOutLine( s);
						}
					}
				}
			}
			
			while ((s = stdError.readLine()) != null) {
				
               System.err.println( "stderr: " + s);
               
               if ( s.contains( "Connection timed out") ||
            		s.contains( "Network is down")) {
            	   logger.severe( "BLE hardware hung-up? " + s);
            	   System.exit( -1);
               }
               
               if ( lineHandler != null)
            	   lineHandler.onStdErrLine( s);
			}	
	
		} catch (Exception e) {
			logger.severe( "runCommands: " + e.getMessage());
			e.printStackTrace();
			return false;
		}
		
		return true;
	}
	
	
	/***
	 * null in case of iBeacon.
	 */
	private ProximityIDStore idStore = null;
	
	// to encrypt temp exposure keys
	private static String pwd = null;
	
	/**
	 * 
	 * @return password of Beacon, can be null.
	 */
	static String getPWD() {
		return pwd;
	}
	
	
	
	public Beacon( String pwd) throws Exception {
		super();
		Beacon.pwd = pwd;
		if (this.getAppType() == Beacon.AppType.APPLE_GOOGLE_CONTACT_TRACING) {
			this.idStore = new SQLiteIDStore( Beacon.DB_FN);
		} else {
			this.idStore = null;
		}
	}

	private static byte [] getBTRandomNonResolvableAddress() {
		Random rd = new Random();
		byte[] arr = new byte[HCIParser.BT_ADDR_SIZE];
		rd.nextBytes(arr);
		
		// BLUETOOTH CORE SPECIFICATION Version 5.2 | Vol 6, Part B	page 2859
		// addresses are LSB..MSB and bit 46:47 are 00. which are the lowest 2 bits of the last byte...
		// the mask thus is 0xFC == 1111 1100 = 15 12 = 0xF 0xC
		
		arr[HCIParser.BT_ADDR_SIZE-1] = (byte) (arr[HCIParser.BT_ADDR_SIZE-1] & 0xFC);
		
		return arr;
	}
	
		
	/***
	 * almost periodically, we change the blue-tooth address of the device and the proximity identifier.
	 * this can only be done when BLE device is idle.
	 */
	void changeBTAddress() {
		
		// if ( this.beacon.getAppType() == AppType.APPLE_GOOGLE_CONTACT_TRACING ) {
		if ( this.useRandomAddr()) {
			// try to change the BT address
			
			// the address is LSB..MSB and bits 47:46 are 0 i.e. bits 0 & 1 of right-most byte are 0.
			byte btRandomAddr[] = getBTRandomNonResolvableAddress();
			
			// generate the hcitool command string
			String hciCmd = getSetRandomBTAddrCmd( btRandomAddr);
			
			logger.info( "SetRandomBTAddrCmd: " + hciCmd);
			
			// do the right thing...
			final String envVars[] = { 
				"SET_RAND_ADDR_CMD=" + hciCmd
			};
						
			final String cmd = "./scripts/set_random_addr";
			
			boolean status = runScript( cmd, envVars, this, null);
		}
			
	}
	
	
	/**
	 * 
	 * @param UUID a 16 byte UUID as uuidgen -t generated string
	 * @return a string containing each byte as hex-dec nbr separated by " ".
	 */
	private static String uuid2hex( String UUID) {
		StringBuffer sb = new StringBuffer();
		int i = 0;
		while ( i < UUID.length()) {
			if ( UUID.charAt(i) == '-') {
				i++;
				continue;
			}
			final String ss = UUID.substring( i, i+2);
			sb.append( ss);		
			if ( i + 2 < UUID.length())
				sb.append( " ");			
			i = i + 2;			
		};
		return sb.toString();
	}	

	static class BeaconOn extends TimerTask 
	implements HCI_EventHandler {
	
		private Beacon beacon = null;
		
		private BeaconOn( Beacon beacon) {
			super();
			this.beacon = beacon;			
		}		
		
		/***
		 * 
		 * @param appType
		 * @param rollingProxyID
		 * @param txPower device transmission power as per BLE specs
		 * 
		 * @return an array of 3 strings: set advertisement parameters command, set advertisement data command, set advertising enable
		 * 
		 * @throws Exception 
		 */
		private static String[] getHCIToolCmds( AppType appType, byte [] rollingProxyID, int txPower,
				boolean useRandomAddr) throws Exception {
			String cmds[] = new String[3];
			switch ( appType) {
			
			case I_BEACON:
				// https://en.wikipedia.org/wiki/IBeacon
				// hcitool -i hci0 cmd 0x08 0x0006 a0 00 a0 00 03 00 00 00 00 00 00 00 00 07 00
				cmds[0] = getIBeaconSetAdvertisementParametersCommand( useRandomAddr);
				// hcitool -i hci0 cmd 0x08 0x0008 1E 02 01 06 1A FF 4C 00 02 15 FB 0B 57 A2 82 28 44 CD 91 3A 94 A1 22 BA 12 06 00 01 00 02 D1 00
				cmds[1] = getIBeaconSetAdvertisementDataCmd( rollingProxyID, txPower);
				// hcitool -i hci0 cmd 0x08 0x000a 01
				cmds[2] = getSetAdvertisingEnableCmd( true);
				break;
				
			case APPLE_GOOGLE_CONTACT_TRACING:
				cmds[0] = getContactTracingSetAdvertisingParametersCommand( useRandomAddr);
				cmds[1] = getContactTracingSetAdvertisingDataCommand( rollingProxyID, txPower);
				if ( cmds[1] == null) {
					throw new Exception( "failure to generate set advertising data command");
				}
				cmds[2] = getSetAdvertisingEnableCmd( true);
				break;
			default: throw new IllegalArgumentException();
			}
			
			return cmds;
		}
		
		/**
		// a power default level of 0xCE == -50 dBm which is roughly what I measure with my smart-phone on
		// top of my ubuntu/bluez BLE box....
		private int txPowerLevel = (byte) 0xCE;  // sign extension in Java...
		
		public boolean onEvent( HCI_Event evt) {
			if ( evt instanceof HCI_CommandComplete) {
				final HCI_CommandComplete evtCC = (HCI_CommandComplete) evt;
				if ( evtCC.isCCReadAdvertisingPhysicalChannelTxPower()) {
					try {
						this.txPowerLevel = evtCC.getTxPowerLevel();
					} catch (Exception e) {
						e.printStackTrace();
						return false;
					}
				} 
			}
			return true;			
		}
		**/
		
		public boolean onEvent( HCI_Event evt) {
			return true;
		}
		
		/***
		 *  both, iBeacon and exposure-notification-service send out the TX Power to determine distances.
		 *  (whatever that is worth in reality). we need to kindly query the HCI world what its TX power is
		 *  
		 * @return a signed integer indicating the transmission power (TX Power) according to the BLE specs. range -127..20 dBm
		 */
		int readHCITxPower() {
			
			if ( Beacon.hciTxPower != Integer.MAX_VALUE) {
				return Beacon.hciTxPower;
			}
			
			/**
			 * some points on TX Power: it is *not* the power used by the BLE chip. Instead it is the power
			 * measured 1 m away from the sender.
			 * https://stackoverflow.com/questions/37268460/beacon-why-we-need-calibrate-tx-power
			 * 
			 * So we try to get this value from the properties or use a default. Querying HCI would give the wrong value,
			 * namely the actual sending power, not the power measured 1 m away.
			 */
			
			final Properties props = Beacon.getProps();
			
			// we expect a 2 hex-digit value using two's complement.
			final String txPwr = props.getProperty( "beacon.txPower", "-50");
			int txPowerLevel = Integer.parseInt( txPwr, 10);
			if ( txPowerLevel < HCI_Command.TX_POWER_MIN || txPowerLevel > HCI_Command.TX_POWER_MAX) {
				throw new IllegalArgumentException( "power level property out of range: " + txPwr);
			}
			
			Beacon.hciTxPower = txPowerLevel;
			
			return Beacon.hciTxPower;
			
			/**
			String hciCmd = getReadAdvertisingPhysicalChannelTxPower();
			
			logger.info( "ReadAdvertisingPhysicalChannelTxPowerCmd: " + hciCmd);
			
			// do the right thing...
			final String envVars[] = { 
				"READ_TX_POWER_CMD=" + hciCmd
			} ;
			
			final String cmd = "./scripts/read_tx_power";
			
			// https://en.wikipedia.org/wiki/DBm are words of wisdom on dBm power measurement
			// some default value... -50 decimal
			this.txPowerLevel = (byte) 0xCE;
			
			// the Dell/Ubuntu/bluez/hcitool returns a power level of 0x07. which is ridiculously high.
			// thus I suspect a bug somewhere and just use a default value
			boolean ENABLE_HCI_READ_TX_POWER = false;
			if ( ENABLE_HCI_READ_TX_POWER) {
				boolean status = runScript( cmd, envVars, this, null);
			}
			
			// Range: -127 to 20, Units: dBm, Accuracy: ±4 dB			
			assert( this.txPowerLevel >= -127 && this.txPowerLevel <= 20); // dBm
			
			Beacon.hciTxPower = this.txPowerLevel;
			
			return Beacon.hciTxPower;
			
			*/
		}
		
		/**
		 * we turn on the Bluetooth LE beacon. using a shell-script which in turn uses bluez Bluetooth features.
		 * @param beaconUUID the payload for the beacon.
		 */
		private void turnBeaconOn( byte rollingProxyID[]) {
			
			// rollingProxyID length is well known...
			assert( rollingProxyID.length == Crypto.ROLLING_PROXIMITY_IDENTIFIER_LEN);
			
			// the UUID is MSB
			String beaconUUID = Beacon.proxyToHex( rollingProxyID, true);
			assert( beaconUUID != null && beaconUUID.length() == Beacon.UUID_HEX_LEN);
			
			assert( beaconUUID.length() == UUID_HEX_LEN);
			
			// get the hcitool cmd string(s). see man hcitool
			
			// we need to query the HW to get the TX power. but do this only once...
			int txPower = readHCITxPower();
			
			String hciToolCmds[];
			try {
				hciToolCmds = getHCIToolCmds( this.beacon.getAppType(), rollingProxyID, txPower, this.beacon.useRandomAddr());
			} catch (Exception e1) {
				logger.severe( e1.getMessage());
				e1.printStackTrace();
				return;
			}
						
			final String envVars[] = { 
					// "BEACON_UUID=" + beaconUUID,
					"SET_ADV_PARAMS_CMD=" +  hciToolCmds[0],
					"SET_ADV_DATA_CMD=" + hciToolCmds[1],
					"SET_ADV_ENABLE_CMD=" + hciToolCmds[2]
					} ;
			
			final String cmd = "./scripts/beacon_start";
			
			// we seem to be getting some unsolicited events...
			boolean status = runScript( cmd, envVars, this.beacon, null);
		
		}
		
		
		@SuppressWarnings("deprecation")
		@Override
		public void run() {
			
			// BeaconOn: from idle to advertising
			
			logger.info( "BeaconOn");
			
			byte rollingProxyID[] = null;
			
			if ( Crypto.VERSION == 1) {			
								
				try {
					final long dayNbr = Crypto.getDayNumber( System.currentTimeMillis());
					final char timeInterval = Crypto.getTimeIntervalNumber( dayNbr);
					
					logger.info( "BeaconOn: dayNbr: " + String.valueOf( dayNbr) + ", timeInterval: " + String.valueOf( (int) timeInterval));
					
					final String tracingKey = Crypto.getTracingKeyProperty();
					byte dailyTracingKey[] = Crypto.getDailyTracingKey( tracingKey, dayNbr);
					rollingProxyID = Crypto.getRollingProxyID( dailyTracingKey, timeInterval);		
					
				} catch (Exception e) {
					e.printStackTrace();
					return;
				}
			
			} else {
				try {
					rollingProxyID = Crypto.getRollingProximityID();
				} catch (InvalidKeyException | NoSuchAlgorithmException
						| NoSuchPaddingException | IllegalBlockSizeException
						| BadPaddingException | IOException e) {
					logger.severe( e.getMessage());
					e.printStackTrace();
				}
			}
			
			this.beacon.setStartTime( System.currentTimeMillis());
			
			this.turnBeaconOn( rollingProxyID);		
			this.beacon.setState( State.ADVERTISING);
			
			
			// schedule the task to turn beacon off			
			BeaconOff beaconOffTask = new BeaconOff( this.beacon);	
			this.beacon.beaconTimer.schedule( beaconOffTask, Beacon.getBeaconAdvertisingDuration());
			
		}
		
	}
	
	static class BeaconIdle extends TimerTask {
		
		Beacon beacon;
		
		BeaconIdle( Beacon beacon) {
			super();
			this.beacon = beacon;
		}
		
		/***
		 * to turn off the processes which run hcidump and hcitool.
		 */
		private void turnScanningOff() {
			
			final String hciDumpPID = this.beacon.getHCIDumpPID();
			final String hciToolPID = this.beacon.getHCIToolPID();
			
			if ( hciDumpPID == null || hciToolPID == null) {
				logger.info( "No PIDs for hcitool or hcidump");
				return;
			}
			
			final String envVars[] = { 
					"HCI_DUMP_PID=" + hciDumpPID,
					"HCI_TOOL_PID=" + hciToolPID,
			};
			
			final String cmd = "./scripts/kill_hcidump";
			
			boolean status = runScript( cmd, envVars, null, null);
					
			// try to parse the dump file...
			try {
				
				String fn = HCI_DUMP_FILE_NAME;
				byte pduTypes[] = { HCIParser.HCI_EVENT /*, HCIParser.HCI_COMMAND */ };
				
				logger.info( String.format( "parsing hcidump trace: %s", fn));
				
				// callback is Beacon.onPDU()
				status = HCIParser.parseHCI( fn, pduTypes, beacon);	
				
			} catch ( Exception e) {
				logger.severe( "failure in parsing dump trace: " + e.getMessage());
				e.printStackTrace();
			}
			
		}
		
		
		@Override
		public void run() {
			
			// from scanning to idle
			logger.info( "BeaconIdle");
			
			this.turnScanningOff();
			this.beacon.setState( State.IDLE);
			
			// we only set a flag to change address since this can only be done when Bluetooth is idle....
			// and now can test the flag and do it...
			if ( this.beacon.getChangeAddressFlag()) {
				this.beacon.setChangeAddressFlag( false);
				
				// change the BT address
				this.beacon.changeBTAddress();
				
				// renew the rolling proximity ID
				try {
					logger.info( "generating a new proximity identifier");
					Crypto.generateRollingProximityID();
				} catch (InvalidKeyException | NoSuchAlgorithmException
						| NoSuchPaddingException
						| IllegalBlockSizeException | BadPaddingException
						|  IOException e) {
					logger.severe( e.getMessage());
					e.printStackTrace();
				}
						
			}
			
			// when we go idle we attempt to purge the stores.
			this.beacon.purge();
			
			// schedule the beaconOnTask to start advertising again.
			
			// how long where we busy?
			long busyDuration = System.currentTimeMillis() - this.beacon.getStartTime();
			assert( busyDuration > 0);
			long idleDuration = Beacon.getBeaconPeriod() - busyDuration;
			
			if ( idleDuration <= 0) {			
				logger.info( "no time to idle: idleDuration <= 0: " + Long.toString( idleDuration));
				idleDuration = 0;
			}
		
			BeaconOn beaconOnTask = new BeaconOn( this.beacon);	
			this.beacon.beaconTimer.schedule( beaconOnTask, idleDuration);
			
			
		}
		
	}
	
	static class BeaconOff extends TimerTask
	implements ScriptLineHandler {
		
		private Beacon beacon;
		
		BeaconOff( Beacon beacon) {
			super();
			this.beacon = beacon;
		}
		
		/***
		 * the launch_hcidump script puts out the PIDs of the hcidump & hcitool processes.
		 * @param s output line of launch_hcidump script.
		 */
		private void saveHCIDumpPIDs( final String s) {
			String tokens[] = s.split( "\\s+");
			assert( tokens.length == 3);
			beacon.setHCIDumpPID( tokens[1]);
			beacon.setHCIToolPID( tokens[2]);
		}
		
		@Override
		public void onStdOutLine(String line) {
			if ( line.contains( "pids:")) {
				saveHCIDumpPIDs( line);
			}
		}

		@Override
		public void onStdErrLine(String line) {			
		}
		
		/***
		 * this is ugly. we start two processes: one to enable the HCI/BLE world to scan for advertisements, another
		 * one to trace the incoming BLE traffic via hcidump. 
		 * Evidently a better interface to BLE would help, but do I want to figure out the BlueZ sources to extract the useful
		 * C code and possibly make it callable from Java???
		 */
		private void turnScanningOn() {
			
			final String envVars[] = { 
					"HCI_DUMP_TRACE_FN=" + HCI_DUMP_FILE_NAME
			};
			
			final String cmd = "./scripts/launch_hcidump";
			
			boolean status = runScript(cmd, envVars, null, this);
			
			/**			
			try {
				Process process = Runtime.getRuntime().exec(cmd, envVars);
								
				int exitStatus = process.waitFor();
				if ( exitStatus < 0) {
					logger.severe( "turnScannerOn: process exit status: " + String.valueOf( exitStatus));
				}
				
				BufferedReader stdInput = new BufferedReader(new InputStreamReader(process.getInputStream()));
				BufferedReader stdError = new BufferedReader(new InputStreamReader(process.getErrorStream()));
				String s = null;
				
				while ((s = stdInput.readLine()) != null) {
					System.err.println(s);
					if ( s.contains( "pids:")) {
						saveHCIDumpPIDs( s);
					}
				}
				
				while ((s = stdError.readLine()) != null) {
	                System.err.println(s);
				}	
		
			} catch (Exception e) {
				logger.severe( "turnScannerOn: " + e.getMessage());
				e.printStackTrace();
			}
			*/ 
		}
				
		/***
		 * to turn the beacon, i.e. advertising off.
		 */
		private void turnBeaconOff() {
			
			String beaconSetAdvertisingDisable = getSetAdvertisingEnableCmd( false);
			
			final String envVars[] = { 
					"SET_ADV_ENABLE_CMD=" + beaconSetAdvertisingDisable
			};
			
			final String cmd = "./scripts/beacon_stop";
			
			boolean status = runScript( cmd, envVars, null, null);
			
		}
		
		@Override
		public void run() {
			
			// from advertising to scanning...
			
			logger.info( "BeaconOff");	
			
			
			turnBeaconOff();				
			turnScanningOn();
			this.beacon.setState( State.SCANNING);
						
			// schedule the idling task.
			BeaconIdle beaconIdleTask = new BeaconIdle( this.beacon);
			this.beacon.beaconTimer.schedule( beaconIdleTask, Beacon.getBeaconScanningDuration());

		}		
	}

	/***
	 * task to set the changeAddressFlag in beacon so that when we go idle we do the right things...
	 * which are to generate a new proximity identifier and to generate a new random address.
	 *
	 */
	private static class RollingProximityGenerationIndicator extends TimerTask {
		
		private Beacon beacon = null;
		
		RollingProximityGenerationIndicator( Beacon beacon) {
			super();
			this.beacon = beacon;
		}

		/***
		 * set flag to trigger change of address when going IDLE.
		 */
		@Override
		public void run() {
			logger.info( "RollingProximityGenerationIndicator run");
			this.beacon.setChangeAddressFlag( true);
		}
		
	}
	
	// after RTFM regd. timers: we have to timers i.e. threads which schedule multiple tasks
	
	/***
	 * timer thread scheduling periodic tasks to trigger generation of new proximity IDs
	 * and BT random addresses
	**/
	private Timer rollingProximityGenerationTimer = null;
	
	/**
	 * the main timer thread which schedules the advertising, scanning and idling tasks in
	 * a round-robin fashion.
	 */
	private Timer beaconTimer = null;
	
		
	private void loop() {
		
		// the very first thing we do is to change BT address if needed
		if ( this.useRandomAddr()) {
			this.changeBTAddress();
		}
	
		
		// schedule the BeaconOnTask which will then start the beacon cycle.
		this.beaconTimer = new Timer();
		BeaconOn beaconOnTask = new BeaconOn( this);		
		this.beaconTimer.schedule( beaconOnTask, 0);
				
		// a periodic task to indicate change of BT address and renewal of proximity ID.
		// the interval is 10 minutes which if scheduling were real-time should cause distinct
		// ENINs to be used in proximity ID generation.
		this.rollingProximityGenerationTimer = new Timer();	
		TimerTask indicatorTask = new RollingProximityGenerationIndicator( this);	
		
		// (task, delay in milli-seconds, period in milli-seconds). note that we are not scheduling on ENIN boundaries...		
		this.rollingProximityGenerationTimer.scheduleAtFixedRate( indicatorTask, ROLLING_PROXIMITY_INTERVAL, ROLLING_PROXIMITY_INTERVAL);
	
	}
	
	/**
	 * how often do we try to purge ephemeral encounters?
	 */
	private static long PURGE_EPHEMERAL_IDS_INTERVAL = 30 * ONE_MIN_MSECS; // milli-secs
	/***
	 * how often do we try to purge old temporary exposure keys?
	 */
	private static long PURGE_TEMP_EXP_KEYS_INTERVAL = 24 * ONE_HR_MSECS; // milli-secs
	/***
	 * how often do we try to purge old exposure IDs?
	 */
	private static long PURGE_EXP_IDS_INTERVAL = 24 * ONE_HR_MSECS; // milli-secs
	
	/**
	 * time-stamp of last purge of obsolete temporary exposure keys.
	 */
	private long purgedObsoleteTempExpKeysTS = 0;
	
	/***
	 * time-stamp of last purge of ephemeral exposure IDs
	 */
	private long purgedEphemeralIDsTS = 0;
	
	/***
	 * time-stamp of last purge of obsolete exposure IDs.
	 */
	private long purgedObsoleteExposureIDsTS = 0;
	
	private void setPurgedObsoleteTempExpKeysTS( long ts) {
		this.purgedObsoleteTempExpKeysTS = ts;
	}
	
	private void setPurgedEphemeralIDsTS( long ts) {
		this.purgedEphemeralIDsTS = ts;
	}
	
	private void setPurgedObsoleteExposureIDsTS( long ts) {
		this.purgedObsoleteExposureIDsTS = ts;
	}
	
	private long getPurgedObsoleteTempExpKeysTS() {
		return this.purgedObsoleteTempExpKeysTS;
	}
	
	private long getPurgedEphemeralIDsTS() {
		return this.purgedEphemeralIDsTS;
	}
	
	private long getPurgedObsoleteExposureIDsTS() {
		return this.purgedObsoleteExposureIDsTS;
	}

	private static long getPurgeEphemeralIDsInterval() {
		return PURGE_EPHEMERAL_IDS_INTERVAL;
	}
	
	private static long getPurgeTempExpKeysInterval() {
		return PURGE_TEMP_EXP_KEYS_INTERVAL;
	}
	
	private static long getPurgeExpIDsInterval() {
		return PURGE_EXP_IDS_INTERVAL;
	}
	
	/***
	 * when an exposure is shorter than that duration (ephemeral), we eventually purge it
	 * in the minutes range
	 */
	private static long MIN_DURATION_OF_EXPOSURE = 3 * ONE_MIN_MSECS; // milli-secs
	
	/***
	 * we keep ephemeral exposures for some time, in the hour range
	 */
	private static long DURATION_KEEP_EPHEMERAL_EXPOSURE = 3 * ONE_HR_MSECS; // milli-secs
	
	/***
	 * how long do we keep exposure IDs? talking about days here...
	 */
	private static long DURATION_KEEP_EXPOSURE_IDS = 21 * ONE_DAY_MSECS; // milli-secs
	
	/***
	 * how long do we keep our own temporary exposure keys? talking about days here...
	 */
	private static long DURATION_KEEP_TEMP_EXP_KEYS = DURATION_KEEP_EXPOSURE_IDS;
	
	static long getDurationKeepTempExpKeys() {
		return DURATION_KEEP_TEMP_EXP_KEYS;
	}
	
	static long getDurationKeepEphemeralExposures() {
		return DURATION_KEEP_EPHEMERAL_EXPOSURE;
	}
	
	static long getMinDurationOfExposure() {
		return MIN_DURATION_OF_EXPOSURE;
	}
	
	static long getDurationKeepExposureIDs() {
		return DURATION_KEEP_EXPOSURE_IDS;
	}

	/***
	 * purge wweks old temporary exposure keys.
	 * @param now time-stamp, milli-secs since EPOCH.
	 */
	private void purgeObsoleteTempExpKeys( long now) {
		long beforeTS = now - getDurationKeepTempExpKeys();
		if ( Crypto.purgeObsoleteTempExpKeys( beforeTS)) {
			// set time-stamp of last purge
			setPurgedObsoleteTempExpKeysTS( now);
		} else {
			logger.warning( "failed to purge temporary exposure keys");
		}
	}
	
	/***
	 * exposures which were too short and lie in the past can be deleted.
	 * @param now
	 */
	private void purgeEphemeralIDs( long now) {
		assert( this.getAppType() == Beacon.AppType.APPLE_GOOGLE_CONTACT_TRACING);
		long beforeTS = now - getDurationKeepEphemeralExposures();
		if ( !this.idStore.purgeEphemeralEncounters( getMinDurationOfExposure(), new Date( beforeTS))) {
			logger.warning( "failure to purge ephemeral encounters");
		} else {
			setPurgedEphemeralIDsTS( now);
		};		
	}
	
	
	/***
	 * exposures of weeks ago can be purged...
	 * 
	 * @param now
	 */
	private void purgeObsoleteExposureIDs( long now) {
		assert( this.getAppType() == Beacon.AppType.APPLE_GOOGLE_CONTACT_TRACING);
		long beforeTS = now - getDurationKeepExposureIDs();
		if ( !this.idStore.purge( new Date( beforeTS))) {
			logger.warning( "failure to purge old exposures");
		} else {
			setPurgedObsoleteExposureIDsTS( now);
		}
	}
	
	/***
	 * invoked during IDLE phase to cleanse out key-store and proximity-id-store
	 */
	void purge() {
				
		long now = System.currentTimeMillis();
		
		// when sending out I_BEACON we do change the UUID based on temp exposure keys
		// and thus need to purge these occasionally....
		if ( now - getPurgedObsoleteTempExpKeysTS() > getPurgeTempExpKeysInterval()) {
			purgeObsoleteTempExpKeys( now);
		}
		
		// when in I_BEACON MODE, we don't store any IDs...
		if ( this.getAppType() == Beacon.AppType.I_BEACON) {
			return;
		}
		
		if ( now - getPurgedEphemeralIDsTS() > getPurgeEphemeralIDsInterval()) {
			purgeEphemeralIDs( now);			
		}
		
		if ( now - getPurgedObsoleteExposureIDsTS() > getPurgeExpIDsInterval()) {
			purgeObsoleteExposureIDs( now);
		}
	}

	/***
	 * time-stamp of Becaon cycle start
	 */
	private long startTime = System.currentTimeMillis();
	
	/***
	 * to set the time-stamp of Beacon cycle start
	 * @param ts time-stamp, milli-secs
	 */
	public void setStartTime(long ts) {
		this.startTime = ts;		
	}
	
	/***
	 * 
	 * @return start time-stamp of last Beacon cycle start, milli-secs
	 */
	public long getStartTime() {
		return this.startTime;
	}

	// when we launch the hcidump & hcitool to listen for incoming BLE advertisements we use
	// two UNIX sub-processes.
	private String hciToolPID = null;
	private String hciDumpPID = null;

	public void setHCIToolPID(String pid) {
		this.hciToolPID = pid;		
	}

	public void setHCIDumpPID(String pid) {
		this.hciDumpPID = pid;		
	}

	/***
	 * 
	 * @return PID of hcitool process while scanning for incoming advertisement. can be null...
	 */
	public String getHCIToolPID() {
		return this.hciToolPID;
	}

	/***
	 * 
	 * @return PID of hcidump process while scanning for incoming advertisement. can be null...
	 */
	public String getHCIDumpPID() {
		return this.hciDumpPID;
	}
		
	public static void main(String[] args) {
		
		
		String pwd = null;
		
		// create Options object
		Options options = new Options();
		// add p option for SUDO pwd
		options.addOption("p", "pwd", true, "user's beacon password");
		// command line -p=<sudo password>
		// configure project run-time arguments settings
		CommandLineParser parser = new DefaultParser();
		try {
			CommandLine cmd = parser.parse( options, args);
			
			if ( cmd.hasOption('p')) {
				pwd = cmd.getOptionValue("p");
				if ( pwd == null || pwd.length() == 0) {
					System.err.println( "no password in -p option");
					System.exit( -1);
				} 
			} else {
			}
		} catch (ParseException e) {
			System.err.println( "failure to parse command line options");
			e.printStackTrace();
			System.exit( -1);
		}
		
		String cwd = System. getProperty("user.dir");
		logger.info( "current working directory: " + cwd);	
		
				
		Beacon.appProps = new Properties();
		
		try {
			final String pfn = cwd + File.separator + PROPERTIES_FILE_NAME;			
			Beacon.appProps.load(new FileInputStream( pfn));
			
			Crypto.setProperties(appProps, pfn);
			
		} catch (IOException e) {
			logger.severe( "exception with properties: " + e.getMessage());
			e.printStackTrace();
			System.exit(-1);
		}
		
		
		boolean TEST_CRYPTO = false;
		if ( TEST_CRYPTO) {
			try {
				byte [] rollingProxyID = Crypto.getRollingProximityID();
			} catch (InvalidKeyException | NoSuchAlgorithmException
					| NoSuchPaddingException | IllegalBlockSizeException
					| BadPaddingException | IOException e) {
				logger.severe( e.getMessage());
				e.printStackTrace();
			}
			
			try {
				byte [] metadataKey = Crypto.getAssociatedEncryptedMetadataKey( null, -1);
				
				byte [] metadata = "some metadata".getBytes( "UTF-8");
				
				byte [] encryptedMetaData = Crypto.getAssociatedEncryptedMetadata(metadata, null, -1);
				
				assert( encryptedMetaData.length == metadata.length);
			} catch (Exception e) {
					logger.severe( e.getMessage());
					e.printStackTrace();
			}
			
			System.exit( 0);
		}
		
		try {
			String fn = Beacon.HCI_DUMP_FILE_NAME;
			File f = new File( fn);
			if ( f.exists() && !f.delete()) {
				logger.severe( "failure to delete " + fn);
			}
		} catch ( Exception e) {}
		
		try {
			Beacon beacon = new Beacon( pwd);
			
			boolean TEST_PARSER = true;
			
			if ( TEST_PARSER) {
				try {
					String fn = cwd + File.separator + "scripts" + File.separator + "hcidump.trace";
					// String fn = Beacon.HCI_DUMP_FILE_NAME;
					byte pduTypes[] = { HCIParser.HCI_EVENT, HCIParser.HCI_COMMAND };
					
					boolean status = HCIParser.parseHCI( fn, pduTypes, beacon);
					// List<ContactDetectionServiceReport> contactTracingReports = HCIParser.getContactTracingReports( l);	
					
				} catch ( Exception e) {
					logger.severe( "failure in parsing dump trace: " + e.getMessage());
					e.printStackTrace();
					System.exit( -1);
				}
				System.exit( 0);
			}
			
			beacon.loop();		
		} catch ( Exception e) {
			e.printStackTrace();
			System.exit( -1);
		}
	}

	
}
