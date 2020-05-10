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

import java.util.Arrays;



/**
 * describing the contact detection service payload - for sender and receiver
 * based on Google & Apple specs
 * @author carl
 *
 */
public class ContactDetectionService  {
	
	// https://blog.google/documents/58/Contact_Tracing_-_Bluetooth_Specification_v1.1_RYGZbKW.pdf
	
	// 2 byte Bluetooth service UUID. this 16 bit service UUID has 
	// been reserved by Apple Inc from the Bluetooth organization as per March 27, 2020
	public static final int CONTACT_DETECTION_SERVICE_UUID = 0xFD6F;
	
	// payload is the rolling proximity UUID, i.e. 16 bytes
	// public static final int ROLLING_PROXIMITY_IDENTIFIER_LENGTH = Beacon.ROLLING_PROXY_ID_LENGTH; // bytes
	
	// as per version 1.1 of Apple & Google specs: Advertising Payload
	// public static final int ASSOCIATED_META_DATA_LENGTH = 4;
	
	// total length of Contact Detection Service description: headers plus payload without meta data...
	public static final int CONTACT_DETECTION_SERVICE_LENGTH = Beacon.ROLLING_PROXY_ID_LENGTH + 11;
	
	byte flagsLen;    // 0
	byte flagsType;   // 1
	byte flags;       // 2
	
	byte serviceUUIDLen;	// 3
	byte serviceUUIDType;	// 4
	byte serviceUUID[];  // 2 bytes, // 5, 6
	
	byte serviceDataLen;	// 7
	byte serviceDataType; 	// 8
	byte serviceDataUUID[]; // 2 bytes redundant ?, // 9, 10
	
	byte serviceData[];  // 16 bytes, 11-26
	
	// since version 1.1
	byte metaData[]; // 4 bytes, 27-30
	
	// 2 bit
	public static final byte MAJOR_VERSION = 0x1;
	
	// 2 bit
	public static final byte MINOR_VERSION = 0x0;
	
	// major version: bit 7-6, minor version: bit 5-4
	public static final byte CONTACT_DETECTION_SERVICE_VERSION = 
			(byte) ((MAJOR_VERSION << 6) | (MINOR_VERSION << 4));
	
	/***
	 * 
	 * @param txPowerLevel -127..20
	 * @return meta data in AdvertisingPayload format (4 bytes)
	 */
	public static byte [] getMetaData( int txPowerLevel) {
		if ( Crypto.VERSION == 1) 
			return null;
		else if ( Crypto.VERSION == 2) {
			
			if ( txPowerLevel < -127 || txPowerLevel > 20) {
				throw new IllegalArgumentException( "power level out of range");
			}; 
			
			byte metaData[] = new byte[Beacon.ASSOCIATED_META_DATA_LENGTH];
			int idx = 0;
			
			// versioning
			metaData[idx++] = CONTACT_DETECTION_SERVICE_VERSION;
			
			// transmit power level
			// two's complement
			int txPwr = Beacon.twosComplement8Bit(txPowerLevel);			
			metaData[idx++] = (byte) (txPwr & 0xFF);
			
			// 2 bytes reserved for future use...
			
			return metaData;
			
		} else {
			throw new IllegalArgumentException();
		}
	}
	
	
	/**
	 * constructor used in parsing
	 * 
	 * @param data byte array of length CONTACT_DETECTION_SERVICE_LENGTH or, since version 1.1, CONTACT_DETECTION_SERVICE_LENGTH+ ASSOCIATED_META_DATA_LENGTH.
	 */
	public ContactDetectionService( byte data[]) {
		
		if ( data.length >= CONTACT_DETECTION_SERVICE_LENGTH) {
						
			this.flagsLen = data[0];
			this.flagsType = data[1];
			this.flags = data[2];
			
			this.serviceUUIDLen = data[3];
			this.serviceUUIDType = data[4];
			
			this.serviceUUID = new byte[2];
			this.serviceUUID[0] = data[5];
			this.serviceUUID[1] = data[6];
			
			this.serviceDataLen = data[7];
			assert( this.serviceDataLen == 0x13 || this.serviceDataLen == 0x17);
			this.serviceDataType = data[8];
			
			this.serviceDataUUID = new byte[2]; 
			this.serviceDataUUID[0] = data[9];
			this.serviceDataUUID[1] = data[10];
			
			// copy out the 16 bytes rolling proximity identifier
			this.serviceData = Arrays.copyOfRange( data, 11, 11+Beacon.ROLLING_PROXY_ID_LENGTH);
			
			// post version 1.1 additional (encrypted) metadata is present
			if ( data.length > CONTACT_DETECTION_SERVICE_LENGTH) {
				
				assert( data.length == CONTACT_DETECTION_SERVICE_LENGTH + Beacon.ASSOCIATED_META_DATA_LENGTH);
				
				this.metaData = Arrays.copyOfRange( data, CONTACT_DETECTION_SERVICE_LENGTH, CONTACT_DETECTION_SERVICE_LENGTH+Beacon.ASSOCIATED_META_DATA_LENGTH);
			} else {
				// no meta-data present.
				
				this.metaData = null;
			}
		} else {
			throw new IllegalArgumentException();
		}
		
		
	}
	
	/***
	 * 
	 * @param serviceData
	 * @param encryptedMetaData can be null for protocol version 1.0
	 * 
	 * @return byte array conforming to Apple & Google Advertising Payload
	 */
	public static byte [] toBytes( byte [] serviceData, byte [] encryptedMetaData) {
		
		assert( serviceData.length == Beacon.ROLLING_PROXY_ID_LENGTH);
		assert( encryptedMetaData == null || encryptedMetaData.length == Beacon.ASSOCIATED_META_DATA_LENGTH);
		
		final int len = CONTACT_DETECTION_SERVICE_LENGTH + ((encryptedMetaData==null)?0:Beacon.ASSOCIATED_META_DATA_LENGTH);
		
		byte data[] = new byte[len];
		int idx = 0;
		
		data[idx++] = 0x02; // len flags
		data[idx++] = 0x01; // type flags
		data[idx++] = 0x1A; // value flags
		
		data[idx++] = 0x03;  // len service UUID
		data[idx++] = 0x03;  // type service UUID
		// note this is LSB...
		data[idx++] = (byte) ((CONTACT_DETECTION_SERVICE_UUID) & 0xFF);			// service UUID, LSB
		data[idx++] = (byte) ((CONTACT_DETECTION_SERVICE_UUID >> 8) & 0xFF);  	// service UUID, MSB
		
		
		int serviceDataLen = serviceData.length + 3; // incl type & uuid, but not len
		if ( encryptedMetaData != null)
			serviceDataLen += encryptedMetaData.length;
		
		assert( serviceDataLen == 0x13 || serviceDataLen == 0x17);
		
		data[idx++] = (byte) (serviceDataLen & 0xFF); // 0x13;  // len service data
		data[idx++] = 0x16;  // type service data
		// note this is LSB...
		data[idx++] = (byte) ((CONTACT_DETECTION_SERVICE_UUID) & 0xFF);			// service UUID, LSB
		data[idx++] = (byte) ((CONTACT_DETECTION_SERVICE_UUID >> 8) & 0xFF); 	// service UUID, MSB
		
		
		System.arraycopy(serviceData, 0, data, idx, serviceData.length);
		idx += serviceData.length;
		
		if ( encryptedMetaData != null) {
			System.arraycopy(serviceData, 0, data, idx, encryptedMetaData.length);
			idx += encryptedMetaData.length;
		}
		
		return data;
		
	}
	
	/***
	 * To generate a ContactDetectionService which contains the given rolling proximity-identifier
	 * 
	 * @param rollingProximityIdentifier
	 * @param encryptedMetaData encrypted meta-data as per Advertising Payload version 1.1 or null
	 * 
	 * @return ContactDetectionService instance
	 */
	public static ContactDetectionService genContactDetectionServiceDescription( byte rollingProximityIdentifier[],
			byte encryptedMetaData[]) {
		
		assert( rollingProximityIdentifier.length == Beacon.ROLLING_PROXY_ID_LENGTH);
		assert( encryptedMetaData == null || encryptedMetaData.length == Beacon.ASSOCIATED_META_DATA_LENGTH);
		
		byte data[] = ContactDetectionService.toBytes(rollingProximityIdentifier, rollingProximityIdentifier);
		
		return new ContactDetectionService( data);
	}
	
	/***
	 * 
	 * @return Advertising Payload as per Google & Apple specs.
	 */
	public byte [] toBytes() {
		return ContactDetectionService.toBytes( this.serviceData, this.metaData);
	}
	
	
	private static String bytes2Hex( byte b[], boolean withSpaces) {
		StringBuffer sb = new StringBuffer();
		for ( int i = 0; i < b.length; i++) {
			String s = null;
			if ( i < b.length-1 && withSpaces) {
				s = String.format( "%02x ", b[i]);
			} else { // no trailing space
				s = String.format( "%02x", b[i]);
			}
			sb.append( s);
		}
		return sb.toString();
	}
	
	public String serviceDataToHex() {
		StringBuffer sb = new StringBuffer();
		
		assert( this.serviceData.length == Beacon.ROLLING_PROXY_ID_LENGTH);
		sb.append( bytes2Hex( this.serviceData, false));
		if ( this.metaData != null) {
			assert( this.metaData.length == Beacon.ASSOCIATED_META_DATA_LENGTH);
			sb.append( bytes2Hex( this.metaData, false));
		}
		return sb.toString();
	}
	
	/**
	 * @param withSpaces if true, hex-dec byte values are space separated.
	 * 	if false, a 4-byte length header is prepended to the non-space separated hex-dec byte values.
	 * 
	 * @return a hex string representation of the contact service data, incl. associated encrypted metadata.
	 */
	public String toHex( boolean withSpaces) {
		StringBuffer sb = new StringBuffer();
		
		if ( withSpaces) {
			sb.append( String.format( "%02x ", this.flagsLen));
			sb.append( String.format( "%02x ", this.flagsType));
			sb.append( String.format( "%02x ", this.flags));
			
			sb.append( String.format( "%02x ", this.serviceUUIDLen));
			sb.append( String.format( "%02x ", this.serviceUUIDType));
			sb.append( String.format( "%02x %02x ", this.serviceUUID[0], this.serviceUUID[1]));
			
			sb.append( String.format( "%02x ", this.serviceDataLen));
			sb.append( String.format( "%02x ", this.serviceDataType));
			sb.append( String.format( "%02x %02x ", this.serviceDataUUID[0], this.serviceDataUUID[1]));
			
			assert( this.serviceData.length == Beacon.ROLLING_PROXY_ID_LENGTH);
			sb.append( bytes2Hex( this.serviceData, withSpaces));
			
			/*
			for ( int i = 0; i < ROLLING_PROXIMITY_IDENTIFIER_LENGTH; i++) {
				String s = null;
				if ( i < ROLLING_PROXIMITY_IDENTIFIER_LENGTH-1) {
					s = String.format( "%02x ", this.serviceData[i]);
				} else { // no trailing space
					s = String.format( "%02x", this.serviceData[i]);
				}
				sb.append( s);
			}	
			*/
			
			if ( this.metaData != null) {
				assert( this.metaData.length == Beacon.ASSOCIATED_META_DATA_LENGTH);
				sb.append( " ");
				sb.append( bytes2Hex( this.metaData, withSpaces));
			}
			
			return sb.toString();
			
		} else {
			sb.append( String.format( "%02x", this.flagsLen));  // 2
			sb.append( String.format( "%02x", this.flagsType)); // 4
			sb.append( String.format( "%02x", this.flags));     // 6
			
			sb.append( String.format( "%02x", this.serviceUUIDLen));  // 8
			sb.append( String.format( "%02x", this.serviceUUIDType)); // 10
			sb.append( String.format( "%02x%02x", this.serviceUUID[0], this.serviceUUID[1])); //12
			
			sb.append( String.format( "%02x", this.serviceDataLen));	//14
			sb.append( String.format( "%02x", this.serviceDataType));	//16
			sb.append( String.format( "%02x%02x", this.serviceDataUUID[0], this.serviceDataUUID[1]));  // 18
			
			assert( this.serviceData.length == Beacon.ROLLING_PROXY_ID_LENGTH);
			sb.append( bytes2Hex( this.serviceData, withSpaces)); // 32 + 18 = 50
			
			/*
			for ( int i = 0; i < ROLLING_PROXIMITY_IDENTIFIER_LENGTH; i++) {
				String s = null;
				if ( i < ROLLING_PROXIMITY_IDENTIFIER_LENGTH-1) {
					s = String.format( "%02x ", this.serviceData[i]);
				} else { // no trailing space
					s = String.format( "%02x", this.serviceData[i]);
				}
				sb.append( s);
			}	
			*/
			
			if ( this.metaData != null) {
				assert( this.metaData.length == Beacon.ASSOCIATED_META_DATA_LENGTH); // 54
				sb.append( bytes2Hex( this.metaData, withSpaces));
			}
			
			String s = sb.toString();
			
			// prepend a 4 byte length header, so we have enough range...
			final int slen = s.length();
			// use LSB
			String ls = String.format( "%02x%02x", (slen & 0xFFFF), ((slen >> 8) & 0xFFFF));
			return ls + s;
		}
		
	}
						
}
