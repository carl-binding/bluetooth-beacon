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

public abstract class HCI_PDU {
	
	// milli-seconds since UNIX EPOCH or 0
	private long timeOfCapture = 0;
	
	/***
	 * 
	 * @param timeOfCapture hcidump time-stamp, milli-seconds since UNIX EPOCH.
	 */
	HCI_PDU( long timeOfCapture) {
		this.timeOfCapture = timeOfCapture;
	}
	
	HCI_PDU( ) {}
	
	/***
	 * 
	 * @return time of capture, milli-seconds since UNIX EPOCH or 0 if not-set.
	 */
	public long getTimeOfCapture() {
		return this.timeOfCapture;
	}

}
