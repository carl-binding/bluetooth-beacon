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
	
	

}
