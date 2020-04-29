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

import java.util.Arrays;

import ch.binding.beacon.ContactDetectionService;

public class LE_AdvertisingReport extends LE_MetaEvent {
	
	// 7.7.65.2 LE Advertising Report event
	// EVENT_TYPE page 2382
	public static final byte ADV_IND = 0x00;
	public static final byte ADV_DIRECT_IND = 0x01;
	public static final byte ADV_SCAN_IND = 0x02;
	public static final byte ADV_NONCONN_IND = 0x03;
	
	public static final byte SCAN_RSP = 0x04;
	
	// ADDRESS_TYPE page 2383
	public static final byte PublicDeviceAddress = 0x00;
	public static final byte RandomDeviceAddress = 0x01;
	public static final byte PublicIdentityAddress = 0x02;
	public static final byte RandomIdentityAddress = 0x03;
	
	public static class AdvertisingReport {
		
		byte eventType;
		byte addressType;
		byte address[];
		byte dataLen;
		byte data[];  // variable length data field for advertising report
		byte rssi;
		
		AdvertisingReport( byte eventType, byte addressType, byte address[], byte dataLen, byte data[], byte rssi) {
			super();
			this.eventType = eventType;
			this.addressType = addressType;
			this.address = address;
			this.dataLen = dataLen; // can be 0
			this.data = data;       // can be null
			this.rssi = rssi;
		}
		
		AdvertisingReport( AdvertisingReport advRep) {
			super();
			this.eventType = advRep.eventType;
			this.addressType = advRep.addressType;
			this.address = advRep.address;
			this.dataLen = advRep.dataLen;
			this.data = advRep.data;
			this.rssi = advRep.rssi;
		}
	
		public AdvertisingReport parse() throws Exception {
			switch ( this.eventType) {
			case ADV_IND:
				return new ADV_IND_Report( this);
			case ADV_DIRECT_IND:
				return new ADV_DIRECT_IND_Report( this);
			case ADV_SCAN_IND:
				return new ADV_SCAN_IND_Report( this);
			case ADV_NONCONN_IND:
				return new ADV_NONCONN_IND_Report( this);
			case SCAN_RSP:
				return new SCAN_RSP_Report( this);
			default:
				throw new Exception( "unhandled event type in AdvertisingReport");
			}
		}
		
		
	}
	
	byte numberReports; // number of nested reports
	
	public byte getNumberReports() {
		return this.numberReports;
	}
	
	byte eventTypes[];  // nbrReports
	byte addressTypes[]; // nbrReports
	byte addresses[]; // nbrReports * 6 == len of BT Address
	byte dataLengths[]; // nbrReports
	byte advData[]; // total data length, SUM (Data_Length[i]) octets
				// format is specific to address type
	byte rssis[]; // nbrReports
	
	private int getDataIndex( int i) {
		int sum = 0;
		for ( int j = 0; j < i; j++) {
			sum += this.dataLengths[j];
		}
		return sum;
	}
	
	public AdvertisingReport getAdvertisingReport( int i) throws Exception {
		if ( i < 0 || i >= this.numberReports) {
			throw new IllegalArgumentException();
		}
		
		// start of i-th report's data
		int dataIndex = getDataIndex( i);
		AdvertisingReport ar = new AdvertisingReport(
				this.eventTypes[i],
				this.addressTypes[i],
				Arrays.copyOfRange( this.addresses, i*HCIParser.BT_ADDR_SIZE, (i+1)*HCIParser.BT_ADDR_SIZE),
				this.dataLengths[i],
				// the data length can be 0....
				(this.dataLengths[i]==0)?null:Arrays.copyOfRange( this.advData, dataIndex, dataIndex + this.dataLengths[i]),
				this.rssis[i]
				);
		// narrow the AdvertisingReport into one of the sub-classes
		ar = ar.parse();
		return ar;
	}
	
	private int getDataLength() {
		return getDataIndex( this.numberReports);
	}
	
	public LE_AdvertisingReport( LE_MetaEvent ev) {
		
		// 7.7.65.2 LE Advertising Report event
		
		super(ev);
		
		int offset = 1; // sub-event code @ 0
		this.numberReports = ev.data[offset];
		offset += 1;
		this.eventTypes = Arrays.copyOfRange( ev.data, offset, offset + this.numberReports);
		offset += this.numberReports;
		this.addressTypes = Arrays.copyOfRange( ev.data, offset, offset + this.numberReports);
		offset += this.numberReports;
		this.addresses = Arrays.copyOfRange( ev.data, offset, offset + this.numberReports * HCIParser.BT_ADDR_SIZE);
		offset += this.numberReports * HCIParser.BT_ADDR_SIZE;
		this.dataLengths = Arrays.copyOfRange( ev.data, offset, offset + this.numberReports);
		offset += this.numberReports;
		final int dataLength = this.getDataLength();
		
		// data for all reports. each event type has different data layout
		if ( dataLength > 0)
			this.advData = Arrays.copyOfRange( ev.data,  offset, offset + dataLength);
		else
			this.advData = null;
		
		offset += dataLength;
		
		this.rssis = Arrays.copyOfRange( ev.data, offset, offset + this.numberReports);			
	}
	
	@Override
	public LE_AdvertisingReport parse() {
		return this;
	}
	
	@Override
	public String toString() {
		return String.format( "LE_AdvertisingReport: nbrReports: %02d", this.numberReports);
	}
	// 2.3.1.1 ADV_IND, page 2873
	public static class ADV_IND_Report extends AdvertisingReport {
		
		// aliases
		byte advA[]; 	// 6 bytes
		byte advData[]; // 0-31 bytes, null if no data.

		ADV_IND_Report( AdvertisingReport advRep) {
			super( advRep);
			this.advA = advRep.address;
			this.advData = advRep.data;
		}
		
	}
	
	// 2.3.1.2 ADV_DIRECT_IND, page 2874
	public static class ADV_DIRECT_IND_Report extends AdvertisingReport {
		
		byte advA[]; 	// 6 bytes
		byte targetA[]; // 6 bytes

		ADV_DIRECT_IND_Report( AdvertisingReport advRep) {
			super( advRep);
			this.advA = advRep.address;
			assert( advRep.data.length == HCIParser.BT_ADDR_SIZE);
			this.targetA = advRep.data;
		}
		
	}
	
	// 2.3.1.3 ADV_NONCONN_IND, page 2874
	public static class ADV_NONCONN_IND_Report extends AdvertisingReport {
		
		// aliases
		byte advA[]; 	// 6 bytes
		byte advData[]; // 0-31 bytes, null if no data.

		ADV_NONCONN_IND_Report( AdvertisingReport advRep) {
			super( advRep);
			this.advA = advRep.address;
			this.advData = advRep.data;
		}
		
		/***
		 * 
		 * @param advNonConnInd
		 */
		ADV_NONCONN_IND_Report( ADV_NONCONN_IND_Report advNonConnInd) {
			super( advNonConnInd);
			this.advA = advNonConnInd.advA;
			this.advData = advNonConnInd.advData;
		}
		
		/***
		 * to further parse an ADV_NONCONN_IND_Report.
		 * @return an instance of ContactDetectionServiceReport (if matching) or instance of ADV_NONCONN_IND_REPORT
		 */
		public ADV_NONCONN_IND_Report parse() {
			final byte data[] = this.advData;
			
			
			final byte serviceUUID_MSB = (byte) ((ContactDetectionService.CONTACT_DETECTION_SERVICE_UUID >> 8) & 0xFF);
			final byte serviceUUID_LSB = (byte) ((ContactDetectionService.CONTACT_DETECTION_SERVICE_UUID) & 0xFF);
			
			// https://blog.google/documents/58/Contact_Tracing_-_Bluetooth_Specification_v1.1_RYGZbKW.pdf
			if ( (byte) data[0] == 0x02 &&  // length Flags
				 (byte) data[1] == 0x01 &&  // type Flags
				 (byte) data[2] == 0x1A &&  // value Flags
				 (byte) data[3] == 0x03 &&  // length Service UUID
				 (byte) data[4] == 0x03 &&  // type Service UUID
				 // service UUID value, LSB byte order...
				 (byte) (data[5] & 0xFF) == serviceUUID_MSB &&
				 (byte) (data[6] & 0xFF) == serviceUUID_LSB
				 ) {
				return new ContactDetectionServiceReport( this);
			}
			
			return this;						
		}
		
	}
	
	/***
	 * constructor for a ContactDetectionService report which we found after taking apart an AdvertisingReport
	 * nested in an LE_AdvertisingReport. BLE does *not* make it easy...
	 * @author carl
	 *
	 * @see AdvertisingReport
	 * @see LE_AdvertisingReport
	 */
	public static class ContactDetectionServiceReport extends ADV_NONCONN_IND_Report {
		
		// https://blog.google/documents/58/Contact_Tracing_-_Bluetooth_Specification_v1.1_RYGZbKW.pdf
		
		// rather than subclassing even more, we wrap this description.
		ContactDetectionService svcDesc;
		
		public byte getRSSI() {
			return super.rssi;
		}
		
		public ContactDetectionService getContactDetectionService() {
			return this.svcDesc;
		}
		
		ContactDetectionServiceReport(ADV_NONCONN_IND_Report advRep) {
			super(advRep);
			this.svcDesc = new ContactDetectionService( advRep.advData);				
		}
		
		@Override
		public String toString() {
			StringBuffer sb = new StringBuffer();
			
			sb.append( String.format( "adv payload: %s, ", this.svcDesc.toHex( false)));
			sb.append( String.format( "rssi: %d", this.getRSSI()));
			
			return sb.toString();
		}
					
	}
	
	// BLUETOOTH CORE SPECIFICATION Version 5.2 | Vol 6, Part B, page 2875
	// 2.3.1.4 ADV_SCAN_IND
	public static class ADV_SCAN_IND_Report extends AdvertisingReport {

		// aliases
		byte advA[]; 	// 6 bytes
		byte advData[]; // 0-31 bytes, can be null.
		
		ADV_SCAN_IND_Report( AdvertisingReport advRep) {
			super( advRep);
			this.advA = advRep.address;
			this.advData = advRep.data;
		}
		
	}
	
	// BLUETOOTH CORE SPECIFICATION Version 5.2 | Vol 6, Part B	page 2880
	// 2.3.2.2 SCAN_RSP
	public static class SCAN_RSP_Report extends AdvertisingReport {
		
		// aliases
		byte advA[];
		byte scanRspData[];
		
		public SCAN_RSP_Report ( AdvertisingReport ar) {
			super( ar);
			this.advA = ar.address;
			this.scanRspData = ar.data;
		}
	}
}
	