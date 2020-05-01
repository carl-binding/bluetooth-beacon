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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.logging.Logger;

/***
 * a simple, *non secure* key-store for temporary exposure keys.
 * file-based, using java.io.Serializable to save/restore data.
 * 
 * @author carl
 *
 */
public class FileKeyStore implements KeyStore, java.io.Serializable {
	
	static Logger logger = Beacon.getLogger();
	
	/**
	 * 
	 */
	private static final long serialVersionUID = -1174992067971603461L;

	private static class Key implements java.io.Serializable {
		/**
		 * 
		 */
		private static final long serialVersionUID = -1053250910887041813L;
		
		private long keyGenIntvlNbr;
		private String key;
		
		Key( long keyGenIntvlNbr, String key) {
			super();
			this.keyGenIntvlNbr = keyGenIntvlNbr;
		}
	}

	
	private boolean save() {
		try {
			FileOutputStream fileOut = new FileOutputStream( this.fileName);
			ObjectOutputStream out = new ObjectOutputStream(fileOut);
			out.writeObject( this);
			out.close();
			fileOut.close();
			
			logger.info( String.format( "key-store saved: %s", this.fileName));
			
			return true;
		} catch (IOException i) {
			i.printStackTrace();
			return false;
		}
	}
	
	private boolean restore() {
		
		File f = new File(this.fileName);
		if ( ! f.exists()) {
			this.keys = new ArrayList<Key>();
			return true;
		}
		
		FileKeyStore e = null;
	      try {
	         FileInputStream fileIn = new FileInputStream( f);
	         ObjectInputStream in = new ObjectInputStream(fileIn);
	         e = (FileKeyStore) in.readObject();
	         
	         this.keys = e.keys;
	         
	         in.close();
	         fileIn.close();
	         
	         logger.info( String.format( "key-store restored: %s", this.fileName));
	         
	         return true;
	         
	      } catch (IOException i) {
	         i.printStackTrace();
	         return false;
	      } catch (ClassNotFoundException c) {
	         System.err.println("FileKeyStore class not found");
	         c.printStackTrace();
	         return false;
	      }		
	}
	
	private String fileName = null;
	
	private ArrayList<Key> keys = new ArrayList<Key>();
	
	FileKeyStore( final String fn) throws Exception {
		super();
		this.fileName = fn;
		if ( !this.restore()) {
			throw new Exception( "failure to restore key-store: " + fn);
		}
	}
	
	@Override
	public String getKey(long keyGenIntvlNbr) {
		for ( Key k: this.keys) {
			if ( k.keyGenIntvlNbr == keyGenIntvlNbr)
				return k.key;
		}
		return null;
	}

	@Override
	public boolean addKey(long keyGenIntvlNbr, String key) {
		
		boolean duplicate = false;
		for ( Key k: this.keys) {
			if ( k.keyGenIntvlNbr == keyGenIntvlNbr) {
				k.key = key;
				duplicate = true;
			}
		}
		
		if ( !duplicate) {
			keys.add( new Key( keyGenIntvlNbr, key));
		}
		
		return this.save();
	}

	@Override
	public boolean purge(long beforeIntvlNbr) {
		ArrayList<Key> keys = new ArrayList<Key>();

		for ( Key k: this.keys) {
			if ( k.keyGenIntvlNbr > beforeIntvlNbr) {
				logger.info( String.format( "keeping temporary exposure key: %d", k.keyGenIntvlNbr));
				keys.add( k);
			}
		}
		
		this.keys = keys;
		return this.save();
	}

}
