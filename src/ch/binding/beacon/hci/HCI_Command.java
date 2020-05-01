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

import ch.binding.beacon.hci.HCI_PDU;

// HCI command from app to HCI
public class HCI_Command extends HCI_PDU {
	
	/***
	 * max tx power, dBm
	 */
	public static final int TX_POWER_MAX = 20;
	
	/***
	 * min tx power, dBm
	 */
	public static final int TX_POWER_MIN = -127;
	
	/***
	 * constant defining the maximum length, in bytes, of the advertisement payload.
	 * the data is preceded by one length byte, so we get 32 bytes payload in length-value.
	 * deeply buried in the BLE specs.
	 * 
	 * BLUETOOTH CORE SPECIFICATION Version 5.2 | Vol 4, Part E page 2487
	 * 7.8.7 LE Set Advertising Data command
	 * 31 octets of advertising data formatted as defined in [Vol 3] Part C, Section 11.
	 */
	public static int ADVERTISING_DATA_LENGTH = 31;
	
	public static class ErrorCode {
		
		public byte code;
		public String name;
		
		ErrorCode( int code, String name) {
			super();
			this.code = (byte) (code & 0xFF);
			this.name = name;
		}
		
	}
	
	// BLUETOOTH CORE SPECIFICATION Version 5.2 | Vol 1, Part F,	page 364
	static ErrorCode errorCodes[] = {
		new ErrorCode( 0x00, "Success"),
		new ErrorCode( 0x01, "Unknown HCI Command"),
		new ErrorCode( 0x02, "Unknown Connection Identifier"),
		new ErrorCode( 0x03, "Hardware Failure"),
		new ErrorCode( 0x04, "Page Timeout"),
		new ErrorCode( 0x05, "Authentication Failure"),
		new ErrorCode( 0x06, "PIN or Key Missing"),
		new ErrorCode( 0x07, "Memory Capacity Exceeded"),
		new ErrorCode( 0x08, "Connection Timeout"),
		new ErrorCode( 0x09, "Connection Limit Exceeded"),
		new ErrorCode( 0x0a, "Synchronous Connection Limit To A Device Exceeded"),
		new ErrorCode( 0x0b, "Connection Already Exists"),
		new ErrorCode( 0x0c, "Command Disallowed"),
		new ErrorCode( 0x0d, "Connection Rejected due to Limited Resources"),
		new ErrorCode( 0x0e, "Connection Rejected Due To Security Reasons"),
		new ErrorCode( 0x0f, "Connection Rejected due to Unacceptable BD_ADDR"),
		new ErrorCode( 0x10, "Connection Accept Timeout Exceeded"),
		new ErrorCode( 0x11, "Unsupported Feature or Parameter Value"),
		new ErrorCode( 0x12, "Invalid HCI Command Parameters"),
		new ErrorCode( 0x13, "Remote User Terminated Connection"),
		new ErrorCode( 0x14, "Remote Device Terminated Connection due to Low Resources"),
		new ErrorCode( 0x15, "Remote Device Terminated Connection due to Power Off"),
		new ErrorCode( 0x16, "Connection Terminated By Local Host"),
		new ErrorCode( 0x17, "Repeated Attempts"),
		new ErrorCode( 0x18, "Pairing Not Allowed"),
		new ErrorCode( 0x19, "Unknown LMP PDU"),
		new ErrorCode( 0x1A, "Unsupported Remote Feature / Unsupported LMP Feature"),
		new ErrorCode( 0x1B, "SCO Offset Rejected"),
		new ErrorCode( 0x1C, "SCO Interval Rejected"),
		new ErrorCode( 0x1D, "SCO Air Mode Rejected"),
		new ErrorCode( 0x1E, "Invalid LMP Parameters / Invalid LL Parameters"),
		new ErrorCode( 0x1F, "Unspecified Error"),

	// TBD
	};
	
	public static ErrorCode getErrorCode( byte ec) {
		// we assume table to be sorted along error codes.
		if ( ec >= 0 && ec < errorCodes.length) {
			return errorCodes[ec];
		}
		return new ErrorCode( ec, "error code not yet documented....");
	}
	
	// BLUETOOTH CORE SPECIFICATION Version 5.2 | Vol 4, Part E, page 1890
	// 5.4.1 HCI Command packet
	// BLUETOOTH CORE SPECIFICATION Version 5.2 | Vol 4, Part E, page 2473
	// 7.8 LE CONTROLLER COMMANDS
	// For the LE Controller commands, the OGF code is defined as 0x08.
	public static final byte HCI_LE_Controller_OGF = 0x08; 
	
	// HCI commands have a 16 bit opcode: 6 bits of OGF, 10 bits of OCF
	// for LE Set Advertising Data we have OGF = 0x08 and OCF = 0x08
	// HOST CONTROLLER INTERFACE FUNCTIONAL SPECIFICATION	
	
	// Vol 4, Part E, 7.8.5 LE Set Advertising Parameters command
	// OCF, 10 bits == 2 bytes == 4 hex
	public static final short HCI_LE_Set_Advertising_Parameters_OCF = 0x0006;
	
	// Vol 4, Part E, 7.8.7 LE Set Advertising Data command bluetooth core 5.2 specs pg 2487
	// OCF, 10 bits == 2 bytes == 4 hex
	public static final short HCI_LE_Set_Advertising_Data_OCF = 0x0008;
	
	// Vol 4, Part E, 7.8.9 LE Set Advertising Enable command
	// OCF, 10 bits == 2 bytes == 4 hex
	public static final short HCI_LE_Set_Advertising_Enable_OCF = 0x000A;
	
	// BLUETOOTH CORE SPECIFICATION Version 5.2 | Vol 4, Part E	page 2486
	// 7.8.6 LE Read Advertising Physical Channel Tx Power command
	public static final short HCI_LE_Read_Advertising_Physical_Channel_Tx_Power_OCF = 0x0007;
	
	// BLUETOOTH CORE SPECIFICATION Version 5.2 | Vol 4, Part E	page 2480
	// 7.8.4 LE Set Random Address command
	public static final short HCI_LE_Set_Random_Address_OCF = 0x0005;
	
	
	short OCF; // 10 bit of opcode field
	byte OGF;  // 6 bit of opcode group field
	byte len;
	
	byte data[];
	
	public HCI_Command( byte opcode[], byte parameterTotalLen, byte data[], 
			long tsOfCapture) {
		
		super( tsOfCapture);
		
		// BLUETOOTH CORE SPECIFICATION Version 5.2 | Vol 4, Part E,	page 1891
		// Figure 5.1: HCI Command packet
		// OCF is 10 bits
		this.OCF = (short) (opcode[0] << 2);
		this.OCF += (short) ((opcode[1] >> 6) & 0x3);  // 2 bits
		
		this.OGF = (byte) (opcode[1] & 0x3F);  // 6 bits
		
		this.len = parameterTotalLen;
		this.data = data;
	}
	
	@Override
	public String toString() {
		return String.format("HCI_Command: OCF: 0x%02x OGF: 0x%02x len: 0x%02x", 
				this.OCF, this.OGF, this.len);

	}
}