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
package ch.binding.beacon.hci;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import ch.binding.beacon.hci.LE_AdvertisingReport.ADV_NONCONN_IND_Report;
import ch.binding.beacon.hci.LE_AdvertisingReport.AdvertisingReport;
import ch.binding.beacon.hci.LE_AdvertisingReport.ContactDetectionServiceReport;

/***
 * parsing the output of hcidump command line tool. Gross interface into the BLE world.
 * 
 * @author carl
 *
 */
public class HCIParser {
	
static Logger logger = Logger.getLogger(HCIParser.class.getName());
	
	static {
		logger.setLevel( Level.ALL);
	}
	
	public static final int BT_ADDR_SIZE = 0x06; // nbr of bytes
	
	/**
	 * http://software-dl.ti.com/lprf/simplelink_cc26x2_sdk-1.60/docs/ble5stack/vendor_specific_guide/BLE_Vendor_Specific_HCI_Guide/hci_interface.html
	 * 
	 * Host Controller Interface
	 * Volume 4
	 * Host Controller Interface
	 * Part A: UART TRANSPORT LAYER
	 * UART Protocol Layer, 2. Protocol
	 */
	public static final int HCI_COMMAND = 0x01;
	public static final int HCI_ASYNC_DATA = 0x02;
	public static final int HCI_SYNC_DATA = 0x03;
	public static final int HCI_EVENT = 0x04;
	
	/************************** event codes ***********************************************/
	/**
	 * Host Controller Interface
	 * PART E: HOST CONTROLLER
	 * INTERFACE FUNCTIONAL SPECIFICATION
	 * 7 HCI COMMANDS AND EVENTS
	 */
	
	// section 7.7 Events
	public static final int HCI_Inquiry_Complete = 0x01;
	public static final int HCI_Inquiry_Result = 0x02;
	public static final int HCI_Connection_Complete = 0x03;
	public static final int HCI_Connection_Request = 0x04;
	public static final int HCI_Disconnection_Complete = 0x05;
	public static final int HCI_Authentication_Complete = 0x06;
	public static final int HCI_Remote_Name_Request_Complete = 0x07;
	public static final int HCI_Encryption_Change = 0x08;
	public static final int HCI_Change_Connection_Link_Key_Complete = 0x09;
	public static final int HCI_Master_Link_Key_Complete = 0x0A;
	public static final int HCI_Read_Remote_Supported_Features_Complete = 0x0B;
	public static final int HCI_Read_Remote_Version_Information_Complete = 0x0C;
	public static final int HCI_QoS_Setup_Complete = 0x0D;
	public static final int HCI_Command_Complete = 0x0E;
	// TBD
	
	// 7.7.65 LE Meta event
	public static final int LE_META_EVENT = 0x3E;
	
	/*************************** Meta Event sub-event type codes  ************************/
		
	// 7.7.65.1 LE Connection Complete event
	public static final int HCI_LE_Connection_Complete = 0x01;
	
	// 7.7.65.2 LE Advertising Report event
	public static final int HCI_LE_Advertising_Report = 0x02;
	
	// 7.7.65.3 LE Connection Update Complete event
	public static final int HCI_LE_Connection_Update_Complete = 0x03;
	
	// 7.7.65.4 LE Read Remote Features Complete event
	public static final int HCI_LE_Read_Remote_Features_Complete = 0x04;
	
	// 7.7.65.5 LE Long Term Key Request event
	public static final int HCI_LE_Long_Term_Key_Request = 0x05;
	
	// TBD: additional sub-event codes as needed
	
	// 7.7.65.34 LE BIGInfo Advertising Report event
	public static final int HCI_LE_BIGInfo_Advertising_Report = 0x22;
	
	
		
	
	private static byte [] readBytes( final FileInputStream in, final long nbrBytes) throws IOException {
		byte data[] = new byte[(int) nbrBytes];
		int n = in.read( data, 0, data.length);
		if ( n != data.length) {
			throw new IOException( "unexpected EOF");
		}
		return data;
	}
	
	private static long getInt32( byte b[]) {
		if ( b == null || b.length != 4)
			throw new IllegalArgumentException();
		long l = 0;
		// big endian
		l =  (b[0] & 0xFF) << 24;
		l |= (b[1] & 0xFF) << 16;
		l |= (b[2] & 0xFF) << 8;
		l |= (b[3] & 0xFF);
		return l;
	}
	
	private static long getLong64( byte b[]) {
		if ( b == null || b.length != 8)
			throw new IllegalArgumentException();
		
		int msi, lsi = 0;
		
		// big endian
		msi =  (int) ((b[0] & 0xFF) << 24);
		msi |= (int) ((b[1] & 0xFF) << 16);
		msi |= (int) ((b[2] & 0xFF) << 8);
		msi |= (int) ((b[3] & 0xFF));
				
		lsi =  (int) ((b[4] & 0xFF) << 24);
		lsi |= (int) ((b[5] & 0xFF) << 16);
		lsi |= (int) ((b[6] & 0xFF) << 8);
		lsi |= (int) ((b[7] & 0xFF));
		
		
		// handling sign extension in Java is always painful...
		long l = ((long) msi) << 32;
		long l2 = ((long) lsi) & 0xFFFFFFFFL; // note the L for long
				
		l2 = l | l2;
		
		assert( l2 >= l);

		return l2;
	}
	
	public final static long BTSNOOP_VERSION = 1;
	
	public final static int HCI_UnEncapsulated = 1001;
	public final static int HCI_UART =	1002;
	public final static int HCI_BSCP = 1003;
	public final static int HCI_Serial = 1004;
	
	private static boolean contains( byte b, byte d[]) {
		for ( int i = 0; i < d.length; i++) {
			if ( b == d[i])
				return true;
		}
		return false;
	}
	
	/**
	 * 
	 * @param data packet-data incl. HCI PDU type at offset 0
	 * @return
	 * @throws Exception
	 */
	private static HCI_Event parseHCIEvent(byte[] data, long tsOfCapture) throws Exception {
				
		HCI_Event hciEvent = new HCI_Event( data, tsOfCapture);
				
		switch ( hciEvent.eventCode) {
		case LE_META_EVENT:	
			LE_MetaEvent metaEvent = new LE_MetaEvent( hciEvent);
			LE_MetaEvent metaSubEvent = metaEvent.parse();
			logger.info( metaSubEvent.toString());
			return metaSubEvent;
		case HCI_Command_Complete:
			HCI_CommandComplete cc = new HCI_CommandComplete( hciEvent);
			logger.info( cc.toString());
			return cc;
		// TBD
		default:
			throw new Exception( "unhandled HCI event code");
		} 
	}

	/**
	 * 
	 * @param data packet-data incl. HCI PDU type at offset 0
	 * @param timeOfCapture: seconds since UNIX EPOCH
	 * @return
	 */
	private static HCI_PDU parseHCICommand(byte[] data, long timeOfCapture) {
		
		final int offset = 1; // HCI packet type still included in data...
		// 5.4.1 HCI Command packet
		// 2 bytes opcode: OCF & OGF
		// 1 byte length
		// command data
		HCI_Command pdu = new HCI_Command( 
				Arrays.copyOfRange( data, offset, offset+2),
				data[offset+2], 
				Arrays.copyOfRange( data,  offset+3, data.length),
				timeOfCapture);
		
		HCIParser.logger.info( pdu.toString());
			
		return pdu;

	}
	
	private static final long carlsDaysFudge = 12L;
	
	/***
	 * the number of days between 01.01.0000 and 01.01.1970. soemhow we were off by 12 days - so I used above fudge.
	 * 
	 * https://www.wolframalpha.com/input/?i=seconds+since+0%3A00%2C+01-01-1970
	 */	
	public static final long nbrDaysSince01010000ToEpoch = 719528+carlsDaysFudge; // (737909 - 18381);
	
 	public static boolean parseHCI( final String fn, byte pduTypes[], HCI_PDU_Handler pduHandler) throws IOException {
 		
 		if ( fn == null || pduTypes == null || pduHandler == null) {
 			throw new IllegalArgumentException();
 		}
		
		FileInputStream in = new FileInputStream( fn);
		int n = 0;
		
		// http://www.fte.com/webhelp/bpa600/Content/Technical_Information/BT_Snoop_File_Format.htm
		// All integer values are stored in "big-endian" order, with the high-order bits first.
		
		// parse the header
		byte identificationPattern[] = readBytes( in, 8);
		String s = new String( Arrays.copyOfRange( identificationPattern, 0, 7), StandardCharsets.US_ASCII);
		if ( !s.equals( "btsnoop")) {
			throw new IOException( "not a btsnoop file?");
		}
		
		byte versionNumber[] = readBytes( in, 4);
		long versNbr = getInt32( versionNumber);
		if ( versNbr != BTSNOOP_VERSION) {
			throw new IOException( "mismatching BTSNOOP VERSION");
		}
		
		byte dataLinkType[] = readBytes( in, 4);
		long dataLinkTypeInt = getInt32( dataLinkType);
		if ( dataLinkTypeInt != HCI_UART) {
			throw new IOException( "data link type != HCI_UART");
		}
		
		// All integer values are stored in "big-endian" order, with the high-order bits first.
		
		while ( in.available() > 0) {
			byte originalLength[] = readBytes( in, 4);
			byte includedLength[] = readBytes( in, 4);
			
			long origLen = getInt32( originalLength);
			long inclLen = getInt32( includedLength);
			
			if ( origLen != inclLen) {
				throw new IOException( "original length != included length");
			}
			
			byte packetFlags[] = readBytes( in, 4);
			byte cumulativeDrops[] = readBytes( in, 4);
			
			// A 64-bit signed integer representing the time of packet arrival, 
			// in microseconds since midnight, January 1st, 0 AD nominal Gregorian.
			byte microseconds[] = readBytes( in, 8);
			long ts = getLong64( microseconds);  // microseconds
			ts = (long) (ts / 1E3);
			ts = ts - (nbrDaysSince01010000ToEpoch * 24 * 60 * 60 * 1000); // milli-seconds
			
			// logger.info( String.format( "parseHCI: event time: %s", new Date( ts).toString()));
			
			// Variable-length field holding the packet that was captured, beginning with its datalink header. 
			// The Datalink Type field of the file header can be used to determine how to decode the datalink header. 
			// The length of the Packet Data field is given in the Included Length field.
			byte packetData[] = readBytes( in, inclLen);
			
			if ( contains( packetData[0], pduTypes)) {
				
				HCI_PDU pdu = null;
						
				switch ( packetData[0]) {
				case HCI_COMMAND:
					// logger.info( "HCI_COMMAND");
					pdu = parseHCICommand( packetData, ts);
					if ( pdu != null) {
						pduHandler.onPDU( pdu);
					}
					break;
				case HCI_EVENT:
					// logger.info( "HCI_EVENT");
					try {
						pdu = parseHCIEvent( packetData, ts);
					} catch (Exception e) {
						logger.severe( "failure to parse HCI event");
						e.printStackTrace();
					}
					if ( pdu != null) {
						pduHandler.onPDU( pdu);
					}
					break;
				case HCI_ASYNC_DATA:
				case HCI_SYNC_DATA:
					logger.info( "unsupported HCI PDU type");
					break;
				default:
					throw new IOException( "unknown HCI PDU type");
				}
			}
			
		}
		
		return true;
	}

	
 	/*

	public static List<ContactDetectionServiceReport> getContactTracingReports(
			List<HCI_PDU> pduList) {
		
		List<ContactDetectionServiceReport> contacts = new ArrayList<ContactDetectionServiceReport>();
		
		for ( HCI_PDU pdu: pduList) {
			
			if ( pdu instanceof LE_AdvertisingReport) {
				
				// LE_AdvertisingReport can nest multiple advertisement reports...
				final LE_AdvertisingReport advRep = (LE_AdvertisingReport) pdu;
				final int nbrReports = advRep.numberReports;
				
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
								contacts.add( cdsr);
							}
						} else {
							
						}
					} catch (Exception e) {
						e.printStackTrace();
					}
				}	
			}
		}
		
		return contacts;
	}
	
	*/

	
}
