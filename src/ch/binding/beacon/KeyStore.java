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

/**
 * Interface to a key-store for temporary exposure keys.
 * 
 * Implementations may or may not be secure...
 * 
 * @author carl
 *
 */
public interface KeyStore {
	
	/***
	 * 
	 * @param keyGenIntvlNbr interval number of key generation, corresponding to the start of some rolling-period.
	 * 
	 * @return key generated at start of rolling-period or null (if no key found). Base64 encoded string.
	 */
	String getKey( long keyGenIntvlNbr) ;
	
	/***
	 * 
	 * @param keyGenIntvlNbr interval number of key generation, corresponding to the start of some rolling-period.
	 * @param key temporary exposure key for the given interval nbr. overwrites any key associated with the same key generation interval number. Encoded as Base64.
	 * 
	 * @return success/failure
	 */
	boolean addKey( long keyGenIntvlNbr, String key);
	
	/***
	 * discards old temporary exposure keys
	 * @param beforeIntvlNbr all keys generated before the given interval are discarded.
	 * 
	 * @return success/failure
	 */
	boolean purge( long beforeIntvlNbr);

}
