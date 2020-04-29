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
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import java.util.Random;
import java.util.Timer;
import java.util.TimerTask;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import ch.binding.beacon.hci.HCIParser;
import ch.binding.beacon.hci.HCI_Command;
import ch.binding.beacon.hci.HCI_CommandComplete;
import ch.binding.beacon.hci.HCI_EventHandler;
import ch.binding.beacon.hci.HCI_PDU;
import ch.binding.beacon.hci.HCI_Event;
import ch.binding.beacon.hci.HCI_PDU_Handler;
import ch.binding.beacon.hci.LE_AdvertisingReport;
import ch.binding.beacon.hci.LE_AdvertisingReport.ADV_NONCONN_IND_Report;
import ch.binding.beacon.hci.LE_AdvertisingReport.AdvertisingReport;
import ch.binding.beacon.hci.LE_AdvertisingReport.ContactDetectionServiceReport;

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


public class Beacon implements HCI_PDU_Handler {
	
	/***
	 * file name for properties
	 */
	static final String PROPERTIES_FILE_NAME = "beacon.properties";
	
	/***
	 * we save output of hcidump into a file when scanning for other beacons
	 */
	static final String HCI_DUMP_FILE_NAME = "/tmp/hcidump_beacon.trace";
	
	static final int UUID_HEX_LEN = "93 48 59 7e 81 a2 11 ea 97 22 90 61 ae c6 7c 30".length();
	
	// iBeacon stuff
	
	// Bluetooth company IDs. see bluetooth.com
	public static final String APPLE_ID = "4C 00";
	public static final String IBM_ID = "03 00";
	
	public static final String APPLE_IBEACON_PREFIX = "1a ff 4c 00 02 15";
	
	// MSB byte ordering for major & minor
	public static final String APPLE_IBEACON_MAJOR = "00 01";
	public static final String APPLE_IBEACON_MINOR = "00 01";
	
	// public static final String APPLE_IBEACON_TX_POWER = "c5";
	
	// we need to read the TX Power from the HCI BLE world. which is of course painful using hcitools & friends.
	// BLUETOOTH CORE SPECIFICATION Version 5.2 | Vol 4, Part E	page 2486
	// 7.8.6 LE Read Advertising Physical Channel Tx Power command
	// Range: -127 to 20
	static int hciTxPower = Integer.MAX_VALUE;		
	
	// exposure notification Google & Apple
	
	// TBD: this is probably not the right way, but what do I know about BLE?
	// public static final byte EXPOSURE_NOTIFICATION_TX_POWER = (byte) 0xC5;
		
	public static final int CONTACT_TRACING_ADVERTISING_INTERVAL = 200; // msecs
	
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
	
	
	/***
	 * duration of idling phase. milliseconds
	 * 
	 */
	private static final long BEACON_IDLE_DURATION = BEACON_PERIOD-BEACON_ADVERTISING_DURATION-BEACON_SCANNING_DURATION;
	
	
	
	/***
	 * the rolling proximity ID shall be changed once so often. The specs link the
	 * change to a change of BLE (random) address. We don't do this for now and use
	 * the fixed BT_ADDR of the Linux box. But we change the rolling-proximity-ID
	 * using this interval
	 * 10 minutes
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
	 * @param msb: most-significant-byte first or least-significant-byte first...
	 * @param spaceSeparated: if true, insert spaces between hex-digits of bytes.
	 * @return hex representation of array data, space separated
	 */
	public static String byteArrToHex( byte [] arr, boolean msb, boolean withSpaces) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < arr.length; i++) {
			
            if ( withSpaces && i > 0)
            	sb.append( " ");
           
            if ( msb) {
            	sb.append( String.format("%02x", arr[i]));
            } else {
            	sb.append( String.format("%02x", arr[arr.length-1-i]));
            }
        }
		return sb.toString();
		
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
	
	
	// BLUETOOTH CORE SPECIFICATION Version 5.2 | Vol 4, Part E,	page 2482
	// 7.8.5 LE Set Advertising Parameters command
	private static String getIBeaconSetAdvertisementParametersCommand() {
		StringBuffer sb = new StringBuffer();
		sb.append( String.format( "0x%02x 0x%04x ", HCI_Command.HCI_LE_Controller_OGF, HCI_Command.HCI_LE_Set_Advertising_Parameters_OCF));
		
		sb.append( "a0 00 ");  // Advertising_Interval_Min:	Size: 2 octets
		sb.append( "a0 00 ");  // Advertising_Interval_Max:	Size: 2 octets
		
		sb.append( String.format( "%02x ", ADV_NONCONN_IND));     // Advertising_Type:	Size: 1 octet
		sb.append( String.format( "%02x ", Own_Address_Type_Public_Device_Address));     // Own_Address_Type:	Size: 1 octet
		sb.append( String.format( "%02x ", Own_Address_Type_Public_Device_Address));     // Peer_Address_Type: Size: 1 octet
		
		sb.append( "00 00 00 00 00 00 "); // Peer_Address: Size: 6 octets
		// Advertising_Channel_Map: Size: 1 octet
		sb.append(  String.format( "%02x ", Advertising_Channel_37 | Advertising_Channel_38 | Advertising_Channel_39));
		sb.append( "00");    // Advertising_Filter_Policy: Size: 1 octet
		return sb.toString();
	}
	
	public static String getAdvertisingInterval( double duration) {
		final int nbrIntervals = (int) (duration / 0.625);
		
		assert( 0x0020 <= nbrIntervals && nbrIntervals <= 0x4000);
		
		final String s = String.format( "%02x %02x ", ((nbrIntervals >> 8) & 0xFF), (nbrIntervals & 0xFF));
		
		return s;
		
	}
	// BLUETOOTH CORE SPECIFICATION Version 5.2 | Vol 4, Part E,	page 2482
	// 7.8.5 LE Set Advertising Parameters command
	private static String getContactTracingSetAdvertisingParametersCommand() {
		StringBuffer sb = new StringBuffer();
		sb.append( String.format( "%02x %04x ", HCI_Command.HCI_LE_Controller_OGF, HCI_Command.HCI_LE_Set_Advertising_Parameters_OCF));
		
		String advertisingInterval = getAdvertisingInterval( CONTACT_TRACING_ADVERTISING_INTERVAL);
		
		// Advertising_Interval_Min:	Size: 2 octets
		// sb.append( String.format( "%02x %02x ", ((nbrIntervals >> 8) & 0xFF), (nbrIntervals & 0xFF)));
		
		// Advertising_Interval_Max:	Size: 2 octets
		// sb.append( String.format( "%02x %02x ", ((nbrIntervals >> 8) & 0xFF), (nbrIntervals & 0xFF)));
		
		sb.append( "a0 00 ");  // Advertising_Interval_Min:	Size: 2 octets
		sb.append( "a0 00 ");  // Advertising_Interval_Max:	Size: 2 octets
		
		// 0x03 Non connectable undirected advertising (ADV_NONCONN_IND)
		sb.append( String.format( "%02x ", ADV_NONCONN_IND));    // Advertising_Type:	Size: 1 octet
		
		sb.append( String.format( "%02x ", Own_Address_Type_Public_Device_Address));     // Own_Address_Type:	Size: 1 octet
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
			
			encryptedMetaData = (metaData==null)?null:Crypto.getAssociatedEncryptedMetadata(metaData);
			
		} catch (InvalidKeyException | NoSuchAlgorithmException
				| NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException
				| InvalidAlgorithmParameterException | IOException e) {
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
	
	static Logger logger = Logger.getLogger(Beacon.class.getName());
	
	static {
		logger.setLevel( Level.ALL);
	}
	
	
	
	/***
	 * to parse HCI events and handle the status value for HCI_Events we get back from hcitool. ugly, ugly.
	 * @param hciEvent
	 */
	private static HCI_Event handleHCIEvent( final String hciEvent) {
		try {
			HCI_Event hciEvt = new HCI_Event(hciEvent).parse();
			// System.err.println("HCI_Event: " + hciEvt.toString());
			if ( hciEvt instanceof HCI_CommandComplete) {
				byte status = ((HCI_CommandComplete) hciEvt).getStatus();
				if ( status != 0x00) {
					HCI_Command.ErrorCode ec = HCI_Command.getErrorCode(status);
					logger.severe( String.format( "error 0x%02x, \"%s\" in HCI Event: %s", ec.code, ec.name, hciEvt.toString()));
				}
				return hciEvt;
			} else {
				logger.severe( "unhandled HCI Event in HCI response");
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	/***
	 * to run a shell script passing it the name of the script and a bunch of environment variables.
	 * we expect the shell script to contain hcitool commands which return a bunch of command-complete events.
	 * evidently this is all pretty clumsy and gross. but that's the way I could tame bluez on Linux for now.
	 * 
	 * @param script
	 * @param envVars array of strings passed to the script as environment variables, format is "ENV_VAR_NAME=value"
	 * @param eventHandler upcall to handle each event.
	 * @param lineHandler to handle all lines which are not part of an "> HCI Event"
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
				System.err.println(s);

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
						if ( eventHandler != null) {
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
               System.err.println( s);
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
	
	
	public Beacon() {
	}

	/*** 
	 * callback during parsing of a hcidump trace file
	 */
	@Override
	public boolean onPDU( HCI_PDU pdu) {
		
		if ( pdu instanceof LE_AdvertisingReport) {
			
			Date timeOfCapture = new Date( pdu.getTimeOfCapture());
			
			logger.info( String.format( "LE_AdvertisingReport: %s", timeOfCapture.toString()));
			
			// LE_AdvertisingReport can nest multiple advertisement reports...
			final LE_AdvertisingReport advRep = (LE_AdvertisingReport) pdu;
			final int nbrReports = advRep.getNumberReports();
			
			for ( int i = 0; i < nbrReports; i++) {
				try {
					AdvertisingReport ar = advRep.getAdvertisingReport(i);
					ar = ar.parse();
					if ( ar instanceof ADV_NONCONN_IND_Report) {
						// these are the ones we are expecting... try to parse the report further
						final ADV_NONCONN_IND_Report advNonConnIndRep = ((ADV_NONCONN_IND_Report) ar).parse();
						if ( advNonConnIndRep instanceof ContactDetectionServiceReport) {
							
							// finally we got one...
							final ContactDetectionServiceReport cdsr = (ContactDetectionServiceReport) advNonConnIndRep;
						
							
							String cdsrPayload = cdsr.getContactDetectionService().toHex( false);
							int rssi = cdsr.getRSSI();
														
							logger.info( String.format( "cdsr: %s %s %d", timeOfCapture.toString(), cdsrPayload, rssi));
							
							
						}
					} else {
						
					}
				} catch (Exception e) {
					e.printStackTrace();
				}
			}	
		}
		
		return true;
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
		
		// when sending out an Apple iBeacon, we use the rolling proximity ID as payload.
		enum AppType { I_BEACON, APPLE_GOOGLE_CONTACT_TRACING};
		
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
		private static String[] getHCIToolCmds( AppType appType, byte [] rollingProxyID, int txPower) throws Exception {
			String cmds[] = new String[3];
			switch ( appType) {
			
			case I_BEACON:
				// https://en.wikipedia.org/wiki/IBeacon
				// hcitool -i hci0 cmd 0x08 0x0006 a0 00 a0 00 03 00 00 00 00 00 00 00 00 07 00
				cmds[0] = getIBeaconSetAdvertisementParametersCommand();
				// hcitool -i hci0 cmd 0x08 0x0008 1E 02 01 06 1A FF 4C 00 02 15 FB 0B 57 A2 82 28 44 CD 91 3A 94 A1 22 BA 12 06 00 01 00 02 D1 00
				cmds[1] = getIBeaconSetAdvertisementDataCmd( rollingProxyID, txPower);
				// hcitool -i hci0 cmd 0x08 0x000a 01
				cmds[2] = getSetAdvertisingEnableCmd( true);
				break;
				
			case APPLE_GOOGLE_CONTACT_TRACING:
				cmds[0] = getContactTracingSetAdvertisingParametersCommand();
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
			
			String hciCmd = getReadAdvertisingPhysicalChannelTxPower();
			
			System.err.println( "ReadAdvertisingPhysicalChannelTxPowerCmd: " + hciCmd);
			
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
			
			// we can switch between Apple iBeacon format and the Apple & Google Exposure Notification formats
			final AppType appType = AppType.APPLE_GOOGLE_CONTACT_TRACING; // I_BEACON; // APPLE_GOOGLE_CONTACT_TRACING;
			
			// we need to query the HW to get the TX power. but do this only once...
			int txPower = readHCITxPower();
			
			String hciToolCmds[];
			try {
				hciToolCmds = getHCIToolCmds( appType, rollingProxyID, txPower);
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
			
			boolean status = runScript( cmd, envVars, null, null);
			
			/** 
			try {
				Process process = Runtime.getRuntime().exec(cmd, envVars);
				
				int exitStatus = process.waitFor();
				if ( exitStatus < 0) {
					logger.severe( "turnBeaconOn: process exit status: " + String.valueOf( exitStatus));
				}
				
				BufferedReader stdInput = new BufferedReader(new InputStreamReader(process.getInputStream()));
				BufferedReader stdError = new BufferedReader(new InputStreamReader(process.getErrorStream()));
				
				String s = null;
				StringBuffer sb = null;
				
				while ((s = stdInput.readLine()) != null) {
					System.err.println(s);

					// HCI Events are split across two lines... it seems
					// otherwise we can detect the end of an HCI Event only when we see the next HCI Command... which is too late.
					if (s.startsWith("> HCI Event:")) {
						sb = new StringBuffer(s);
					} else {
						if (sb != null) {
							sb.append(s);							
							HCI_Event evt = handleHCIEvent( sb.toString());
							sb = null;							
						}
					}
				}
				
				while ((s = stdError.readLine()) != null) {
	               System.err.println( s);
				}	
		
			} catch (Exception e) {
				logger.severe( "turnBeaconOn: " + e.getMessage());
				e.printStackTrace();
			}
			
			*/
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
			
			/**
			try {
				Process process = Runtime.getRuntime().exec(cmd, envVars);
								
				int exitStatus = process.waitFor();
				if ( exitStatus < 0) {
					logger.severe( "turnScanningOff: process exit status: " + String.valueOf( exitStatus));
				}
				
				BufferedReader stdInput = new BufferedReader(new InputStreamReader(process.getInputStream()));
				BufferedReader stdError = new BufferedReader(new InputStreamReader(process.getErrorStream()));
				
				String s = null;
				
				while ((s = stdInput.readLine()) != null) {
					System.err.println(s);
				}
				while ((s = stdError.readLine()) != null) {
	                System.err.println(s);
				}	
		
			} catch (Exception e) {
				logger.severe( "turnScanningOff: " + e.getMessage());
				e.printStackTrace();
			}
			*/
			
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
	
		@SuppressWarnings("deprecation")
		@Override
		public void run() {
			
			// BeaconOn: from idle to advertising
			
			// this.turnScanningOff();
			
			byte rollingProxyID[] = null;
			
			if ( Crypto.VERSION == 1) {			
								
				try {
					final long dayNbr = Crypto.getDayNumber( new Date().getTime());
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
			
			this.turnBeaconOn( rollingProxyID);		
			this.beacon.setState( State.ADVERTISING);
			
			// schedule the task to turn beacon off			
			Date timeToTurnOff = new Date();
			timeToTurnOff.setTime( timeToTurnOff.getTime() + BEACON_ADVERTISING_DURATION);
			BeaconOff beaconOffTask = new BeaconOff( this.beacon);	
			new Timer().schedule( beaconOffTask, timeToTurnOff);
			
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
			
			// schedule the beaconOnTask to start advertising again.
			Date timeToTurnOn = new Date();
			long idleDuration = Beacon.BEACON_IDLE_DURATION;
			assert( idleDuration > 0);
			
			timeToTurnOn.setTime( timeToTurnOn.getTime() + idleDuration);
			BeaconOn beaconOnTask = new BeaconOn( this.beacon);	
			new Timer().schedule( beaconOnTask, timeToTurnOn);
			
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
			
			/**
			try {
				Process process = Runtime.getRuntime().exec(cmd, envVars);
								
				int exitStatus = process.waitFor();
				if ( exitStatus < 0) {
					logger.severe( "turnBeaconOff: process exit status: " + String.valueOf( exitStatus));
				}
				
				
				BufferedReader stdInput = new BufferedReader(new InputStreamReader(process.getInputStream()));
				BufferedReader stdError = new BufferedReader(new InputStreamReader(process.getErrorStream()));
				String s = null;
				
				StringBuffer sb = null;
				while ((s = stdInput.readLine()) != null) {
					System.err.println(s);

					// HCI Events are split across two lines... it seems
					// otherwise we can detect the end of an HCI Event only when we see the next HCI Command... which is too late.
					if (s.startsWith("> HCI Event:")) {
						sb = new StringBuffer(s);
					} else {
						if (sb != null) {
							sb.append(s);							
							HCI_Event evt = Beacon.handleHCIEvent( sb.toString());
							sb = null;							
						}
					}
				}
				
				while ((s = stdError.readLine()) != null) {
	                System.err.println(s);
				}	
		
			} catch (Exception e) {
				logger.severe( "turnBeaconOff: " + e.getMessage());
				e.printStackTrace();
			}
			*/
			
		}

		@Override
		public void run() {
			
			// from advertising to scanning...
			
			logger.info( "BeaconOff");	
			
			turnBeaconOff();				
			turnScanningOn();
			this.beacon.setState( State.SCANNING);
						
			// schedule the idling task.
			Date timeToTurnIdle = new Date();
			timeToTurnIdle.setTime( timeToTurnIdle.getTime() + BEACON_SCANNING_DURATION);			
			BeaconIdle beaconIdleTask = new BeaconIdle( this.beacon);
			new Timer().schedule( beaconIdleTask, timeToTurnIdle);

		}

		
		
	}
	
	
	
	private Timer rollingProximityGenerationTimer;
	
	private void loop() {
		
		// schedule the BeaconOnTask which will then start the beacon cycle.
		Timer beaconOnTimer = new Timer();
		BeaconOn beaconOnTask = new BeaconOn( this);		
		// this.beaconOnTimer.scheduleAtFixedRate(beaconOnTask, 0, BEACON_PERIOD);
		beaconOnTimer.schedule( beaconOnTask, 0);
		
		if ( Crypto.VERSION == 2) {
			
			// Each time the Bluetooth Low Energy MAC randomized address changes, 
			// we derive a new Rolling Proximity Identifier using the Rolling Proximity Identifier Key
			// here we simulate this as we do not create random sender addresses (yet?)
			rollingProximityGenerationTimer = new Timer();
			
			rollingProximityGenerationTimer.scheduleAtFixedRate( new TimerTask() {

				@Override
				public void run() {
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
				
			}, 0, ROLLING_PROXIMITY_INTERVAL);
		}
	
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
		
		/*
		// create Options object
		Options options = new Options();
		// add p option for SUDO pwd
		options.addOption("p", "pwd", true, "user's SUDO password");
		// command line -p=<sudo password>
		// configure project run-time arguments settings
		CommandLineParser parser = new DefaultParser();
		try {
			CommandLine cmd = parser.parse( options, args);
			
			if ( cmd.hasOption('p')) {
				String sudoPwd = cmd.getOptionValue("p");
				if ( sudoPwd == null || sudoPwd.length() == 0) {
					System.err.println( "empty SUDO password");
				}
				Sender.setSudoPwd( sudoPwd);
			} else {
				System.err.println( "missing SUDO password option 'p'");
				System.exit( -1);
			}
		} catch (ParseException e) {
			System.err.println( "failure to parse command line options");
			e.printStackTrace();
			System.exit( -1);
		}
		*/
		
		String cwd = System. getProperty("user.dir");
		logger.info( "current working directory: " + cwd);	
		
		
		
		Properties appProps = new Properties();
		try {
			final String pfn = cwd + File.separator + PROPERTIES_FILE_NAME;			
			appProps.load(new FileInputStream( pfn));
			
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
				byte [] metadataKey = Crypto.getAssociatedEncryptedMetadataKey();
				
				byte [] metadata = "some metadata".getBytes( "UTF-8");
				
				byte [] encryptedMetaData = Crypto.getAssociatedEncryptedMetadata(metadata);
				
				assert( encryptedMetaData.length == metadata.length);
			} catch (InvalidKeyException | NoSuchAlgorithmException
						| NoSuchPaddingException | IllegalBlockSizeException
						| BadPaddingException
						| InvalidAlgorithmParameterException e) {
					logger.severe( e.getMessage());
					e.printStackTrace();
			} catch (IOException e) {
				logger.severe( e.getMessage());
				e.printStackTrace();
			}
			
			System.exit( 0);
		}
		
		Beacon beacon = new Beacon();
		
		boolean TEST_PARSER = false;
		
		if ( TEST_PARSER) {
			try {
				String fn = cwd + File.separator + "scripts" + File.separator + "hcidump.trace";
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
	}

	
}
