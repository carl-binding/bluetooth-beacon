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

import ch.binding.beacon.hci.LE_AdvertisingReport;

public class LE_MetaEvent extends HCI_Event {
	
	byte subEventCode; // byte 0 of event data. determines type of meta-sub-event
	
	public LE_MetaEvent( LE_MetaEvent e) {
		super( e);
		this.subEventCode = e.subEventCode;
	}
	
	public LE_MetaEvent( HCI_Event hciEvent) {
		super( hciEvent);
		this.subEventCode = hciEvent.data[0];
	}

	/**
	 * To turn an LE Meta Event into a corresponding sub-event.
	 * @return matching LE meta sub-event
	 * @throws Exception
	 */
	public LE_MetaEvent parse() throws Exception {
		switch ( this.subEventCode) {
		case HCIParser.HCI_LE_Advertising_Report:
			LE_AdvertisingReport advRep = new LE_AdvertisingReport( this).parse();			
			return advRep;
		// TBD
		default: 
			throw new Exception( "unhandled meta sub-event code");
		}
	}
	
	@Override
	public String toString() {
		if ( this instanceof LE_AdvertisingReport) {
			return ((LE_AdvertisingReport)this).toString();
		}
		return String.format( "LE Meta Event: 0x%02x", this.subEventCode);
	}
}