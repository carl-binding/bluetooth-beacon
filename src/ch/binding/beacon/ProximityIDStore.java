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

import java.util.Date;
import java.util.HashMap;

/***
 * interface to handle the storage of proximity ID tokens detected on that device.
 * 
 * @author carl
 *
 */
public interface ProximityIDStore {
	
	/***
	 * squirrel away the advertising payload 
	 * 
	 * @param serviceData the service data as a hexadecimal string, 2 digits per byte, no spaces.
	 * we expect 16 bytes rolling proximity identifier plus 4 bytes associated encrypted metadata
	 * thus the string length is 40 hex-dec digits.
	 * 
	 * @param rssi the Received Signal Strength Indication of the received BLE advertising (for whatever it is worth).
	 * 
	 * @param timeOfCapture time-stamp
	 * 
	 * @return success/failure
	 */
	public boolean store( String serviceData, int rssi, Date timeOfCapture);
	
	/***
	 * discard all encounters before the given date.
	 * 
	 * @param before encounters before that date are discarded.
	 * 
	 * @return success/failure
	 */
	public boolean purge( Date before);
	
	/**
	 * purge exposures which are shorter than some min. duration of exposure.
	 * that is, if we see an rolling proximity identifier for less that the duration, we consider
	 * the exposure to be too short to be relevant from an infection point of view and can purge it.
	 * 
	 * @param duration if the encounter is shorter than duration, it will be dropped. milli-seconds
	 * @param before only consider encounters of which the last time of capture is before the given date, which
	 * 		should be sufficiently back in the past. That is, before should be < now - duration.
	 */
	public boolean purgeEphemeralEncounters( long duration, Date before);
	
	/**
	 * the info we stored away during scanning.
	 * 
	 * @author carl
	 *
	 */
	public static class ProximityID {
		
		/***
		 * 
		 * @param proximity_id hex-dec digit string of 16 bytes
		 * @param assoc_enc_meta_data hex-dec digit string of 4 bytes
		 * @param first_toc
		 * @param last_toc
		 * @param rssi
		 */
		public ProximityID( String proximity_id, String assoc_enc_meta_data, long first_toc, long last_toc,
				int rssi) {
			super();
			
			// for whatever reason, we stored these values as hex-dec strings, which is what BLE and hcitools 
			// prefer....
			assert( proximity_id.length() == 2 * Beacon.ROLLING_PROXY_ID_LENGTH);
			assert( assoc_enc_meta_data.length() == 2 * Beacon.ASSOCIATED_META_DATA_LENGTH);
			
			this.proximityID = Beacon.hexStrToBytes( proximity_id);
			this.encodedAssocMetaData = Beacon.hexStrToBytes( assoc_enc_meta_data);
			
			this.rssi = rssi;
			this.first_toc = first_toc;
			this.last_toc = last_toc;
		}
		
		public long first_toc;
		public long last_toc;
		public int rssi;
		public byte proximityID[];
		public byte encodedAssocMetaData[];
	
	}
	
	public HashMap<ByteArray, ProximityID> getProximityIDs( long from_ts, long to_ts);
		

}
