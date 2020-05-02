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


/***
 * BLUETOOTH CORE SPECIFICATION Version 5.2 | Vol 4, Part E page 2310
 * 7.7.15 Command Status event
 * 
 * @author carl
 *
 */
public class HCI_CommandStatus 
extends HCI_Event
{

	byte status;
	byte numHCICommandPackets;
	int commandOpcode;
	
	short OCF;  // 10 most significant bits of commandOpcode opcode command field
	byte OGF;   // 6 least significant bits of commandOpcode opcode command group
	
	public short getOCF() {
		return this.OCF;
	}
	
	public byte getOGF() {
		return this.OGF;
	}
	
	public byte getStatus() {
		return this.status;
	}
	
	public HCI_CommandStatus(HCI_Event evt) {
		super(evt);
		
		this.status = evt.data[0];
		this.numHCICommandPackets = evt.data[1];
		
		// 2 bytes for opcode. MSB byte order
		this.commandOpcode = (evt.data[2] << 8) | evt.data[3];
		
		// BLUETOOTH CORE SPECIFICATION Version 5.2 | Vol 4, Part E,	page 1891
		// Figure 5.1: HCI Command packet
		// very strange data layout....
		this.OCF = (short) (evt.data[2] | (evt.data[3] & 0x03) << 8); // 10 bits
		this.OGF = (byte) ((evt.data[3] >> 2) & 0x3F);  // 6 bits
		
		
	}

}
