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

public class HCI_CommandComplete extends HCI_Event {
	
	byte numHCICommandPackets;
	int commandOpcode;
	byte returnParameters[];
	
	short OCF;  // 10 most significant bits of commandOpcode opcode command field
	byte OGF;   // 6 least significant bits of commandOpcode opcode command group
	
	short getOCF() {
		return this.OCF;
	}
	
	byte getOGF() {
		return this.OGF;
	}
		
	public HCI_CommandComplete( HCI_Event hciEvent) {
		super( hciEvent);
		
		this.numHCICommandPackets = hciEvent.data[0];
		
		// 2 bytes for opcode. MSB byte order
		this.commandOpcode = (hciEvent.data[1] << 8) | hciEvent.data[2];
		
		// BLUETOOTH CORE SPECIFICATION Version 5.2 | Vol 4, Part E,	page 1891
		// Figure 5.1: HCI Command packet
		// very strange data layout....
		this.OCF = (short) (hciEvent.data[1] | (hciEvent.data[2] & 0x03) << 8); // 10 bits
		this.OGF = (byte) ((hciEvent.data[2] >> 2) & 0x3F);  // 6 bits
		
		// This is the return parameter(s) for the command specified in the
		// Command_Opcode event parameter. See each command’s definition for
		// the list of return parameters associated with that command.
		this.returnParameters = Arrays.copyOfRange( hciEvent.data, 3, hciEvent.data.length);
	}
	
	@Override
	public String toString() {
		return String.format( "HCI Command Complete: nbrPackets: %02d, opCode: 0x%04x (0x%04x 0x%02x)", 
				this.numHCICommandPackets, this.commandOpcode,
				this.OCF, this.OGF);
	}
	
	/***
	 * 
	 * @return status indication of command completion. 0x00 indicates success, != 0x00 is failure.
	 * @throws Exception
	 */
	public byte getStatus() throws Exception {
		
		/*
		 * this is painful. HCI commands generate different status information.
		 * 
		 * BLUETOOTH CORE SPECIFICATION Version 5.2 | Vol 4, Part E, page 2309
		 * 
		 * Return_Parameter(s): Size: Depends on command
		 * 
		 * This is the return parameter(s) for the command specified in the
		 * Command_Opcode event parameter. See each command’s definition for
		 * the list of return parameters associated with that command.
		 */
		switch ( this.OGF){
		case HCI_Command.HCI_LE_Controller_OGF:
			switch ( this.OCF) {
			
			// some commands have the same behaviour with regards to the status value...
			case HCI_Command.HCI_LE_Set_Advertising_Enable_OCF:
			case HCI_Command.HCI_LE_Set_Advertising_Data_OCF:
			case HCI_Command.HCI_LE_Set_Advertising_Parameters_OCF:
				assert( this.returnParameters.length == 1);
				/*
				 * BLUETOOTH CORE SPECIFICATION Version 5.2 | Vol 4, Part E page 2485
				 * 
				 * 	Status:  Size: 1 octet
				 * 	Value Parameter Description
				 *	0x00 HCI_LE_Set_Advertising_Parameters command succeeded.
				 *	0x01 to 0xFF HCI_LE_Set_Advertising_Parameters command failed. See [Vol 1] Part F, Controller Error Codes for a list of error codes and descriptions.
				 */
				return this.returnParameters[0];
			case HCI_Command.HCI_LE_Read_Advertising_Physical_Channel_Tx_Power_OCF:
				// BLUETOOTH CORE SPECIFICATION Version 5.2 | Vol 4, Part E	page 2486
				assert( this.returnParameters.length == 2);
				return this.returnParameters[0];
			default:
				throw new Exception( "unhandled OCF");
			}
			
		default: throw new Exception( "unhandled OGF");
		}
	}
	
	/***
	 * to test the command complete event to which command (OCF) it was a response...
	 * 
	 * @param OCF 10 bit opcode command field
	 * @param OGF 6 bit opcode group field
	 * @return
	 */
	public boolean isCommandCompleteEvent( short OCF, byte OGF) {
		return this.OGF == OGF && this.OCF == OCF;
	}
	
	public boolean isCCReadAdvertisingPhysicalChannelTxPower() {
		return isCommandCompleteEvent( 
				HCI_Command.HCI_LE_Read_Advertising_Physical_Channel_Tx_Power_OCF, 
				HCI_Command.HCI_LE_Controller_OGF);
	}
	
	public byte getTxPowerLevel() throws Exception {
		switch ( this.OGF){
		case HCI_Command.HCI_LE_Controller_OGF:
			switch ( this.OCF) {
			case HCI_Command.HCI_LE_Read_Advertising_Physical_Channel_Tx_Power_OCF:
				// BLUETOOTH CORE SPECIFICATION Version 5.2 | Vol 4, Part E	page 2486
				assert( this.returnParameters.length == 2);
				
				return this.returnParameters[1];
			default: 
				throw new Exception( "not a HCI_LE_Read_Advertising_Physical_Channel_Tx_Power_OCF response");
			}
		default: throw new Exception( "unhandled OGF");
		}
	}
}
