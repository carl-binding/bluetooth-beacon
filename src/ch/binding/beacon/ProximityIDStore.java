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
	 * @param advertisingPayload the service data as a hexadecimal string, 2 digits per byte, no spaces.
	 * @param rssi the Received Signal Strength Indication of the received BLE advertising (for whatever it is worth).
	 * 
	 * @return success/failure
	 */
	public boolean store( String advertisingPayload, int rssi);
	
	/***
	 * discard all encounters before the given date.
	 * 
	 * @param before encounters before that date are discarded.
	 * 
	 * @return success/failure
	 */
	public boolean purge( Date before);
	
	

}
