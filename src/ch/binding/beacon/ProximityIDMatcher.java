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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * interface to match a set of "infected" temporary exposure keys against the (large) set of
 * scanned proximity IDs. as much as possible we use temporal disjunction to limit search-spaces.
 * The Apple & Google protocol is clever in that regard: proximity IDs can be computed based on
 * the temp. exposure key and some interval. No need to iterate through the daily exposure key à la DP3T.
 * 
 * @author carl
 *
 */
public interface ProximityIDMatcher {
	
	/**
	 * To model temporary exposure keys we would receive for cases of infection.
	 * @author carl
	 *
	 */
	public static class TempExpKey {
		
		public long keyGenIntvlNbr;
		public byte[] tempExposureKey;
		
		public TempExpKey( long intvl, String key) {
			super();
			this.keyGenIntvlNbr = intvl;
			this.tempExposureKey = Base64.getDecoder().decode( key);
		}
		
		public TempExpKey( long intvl, byte[] key) {
			super();
			this.keyGenIntvlNbr = intvl;
			this.tempExposureKey = key;
		}
		
		public static class ProximityID {
			
			private long intvl;
			private byte proximityID[];
			
			ProximityID( long intvl, byte proxID[]) {
				super();
				this.intvl = intvl;
				this.proximityID = proxID;
			}
			
			public long getInterval() {
				return this.intvl;
			}
			
			public byte[] getProximityID() {
				return this.proximityID;
			}
		}
		
		private ArrayList<ProximityID> proximityIDs = null;
		
		/***
		 * 
		 * @return list of proximity IDs derived from temporary exposure keys for one EK_ROLLING_PERIOD
		 * 
		 * @throws InvalidKeyException
		 * @throws FileNotFoundException
		 * @throws NoSuchAlgorithmException
		 * @throws NoSuchPaddingException
		 * @throws IllegalBlockSizeException
		 * @throws BadPaddingException
		 * @throws IOException
		 */
		public List<ProximityID> getProximityIDs() 
				throws InvalidKeyException, FileNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
			if ( this.proximityIDs == null) {
				assert( this.keyGenIntvlNbr % Crypto.EK_ROLLING_PERIOD == 0);
				
				this.proximityIDs = new ArrayList<ProximityID>();
				
				for ( long intvl = this.keyGenIntvlNbr; intvl < this.keyGenIntvlNbr + Crypto.EK_ROLLING_PERIOD; intvl++) {
					byte[] pid = Crypto.getRollingProximityID( this.tempExposureKey, intvl);
					this.proximityIDs.add( new ProximityID( intvl, pid));
				}
			}
			return this.proximityIDs;
		}
	}
	
	
	public static class Match {
		
		public TempExpKey key;
		public ProximityIDStore.ProximityID proxID;
		
		public Match(TempExpKey k, ProximityIDStore.ProximityID pid) {
			super();
			this.key = k;
			this.proxID = pid;
		}
	
	}
	
	/**
	 * 
	 * @param infectedTempExpKeys set of "infected" temporary exposure keys we get from central server
	 * 
	 * @param margin time margin for matching keys with proximity IDs which have been scanned 
	 * 	[keyGenIntvlNbr..keyGenIntvlNbr+margin]
	 * 
	 * @return a list of potential matches - which can be empty.
	 */
	List<Match> matches( List<TempExpKey> infectedTempExpKeys, int margin);
	
	
	

}
