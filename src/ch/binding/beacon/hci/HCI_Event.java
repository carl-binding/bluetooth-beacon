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

import ch.binding.beacon.Beacon;
import ch.binding.beacon.hci.HCI_Event;

// event from HCI to app
public class HCI_Event extends HCI_PDU {
	
	// 7.7.1 Inquiry Complete event
	public static final byte  HCI_Inquiry_Complete = 0x01;
	
	// 7.7.2 Inquiry Result event
	public static final byte HCI_Inquiry_Result = 0x02;
	
	// 7.7.3 Connection Complete event
	public static final byte HCI_Connection_Complete = 0x03;
	
	// 7.7.14 Command Complete event
	public static final byte HCI_Command_Complete = 0x0E;
	
	byte eventCode;
	byte len;
	byte data[]; // event data without eventCode & len bytes
	
	public HCI_Event( byte data[], long tsOfCapture) {
		super( tsOfCapture);
		final int offset = 1; // HCI PDU type
		this.eventCode = data[offset];
		this.len = data[offset+1];
		this.data = Arrays.copyOfRange(data, offset+2, data.length);
	}
	
	public HCI_Event( HCI_Event e) {
		super( e.getTimeOfCapture());
		this.eventCode = e.eventCode;
		this.len = e.len;
		this.data = e.data;
	}
	
	public HCI_Event( String hciOutput) {
		super();
		
		// > HCI Event: 0x0e plen 4  01 06 20 0C
		String tokens[] = hciOutput.split( "\\s+");
		
		this.eventCode = (byte) (Integer.parseInt( tokens[3].substring( 2), 0x10) & 0xFF);
		this.len = (byte) (Integer.parseInt( tokens[5]) & 0xFF);
		
		this.data = new byte[this.len];
		for ( int i = 6; i < tokens.length; i++) {
			byte b = (byte) (Integer.parseInt( tokens[i], 0x10) & 0xFF);
			this.data[i-6] = b;
		}
	}
	
	public HCI_Event parse() throws Exception {
		switch ( this.eventCode) {
		case HCI_Inquiry_Complete:
			return new HCI_InquiryComplete( this);
		case HCI_Inquiry_Result:
			return new HCI_InquiryResult( this);
		case HCI_Connection_Complete:
			return new HCI_ConnectionComplete( this);
		case HCI_Command_Complete:
			return new HCI_CommandComplete( this);
		}
		return this;
	}
	
	@Override
	public String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append( String.format( "0x%02x 0x%02x ", this.eventCode, this.len));
		sb.append( Beacon.byteArrToHex( this.data, true, true));		
		return sb.toString();
	}
}