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
package ch.binding.beacon.db;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.logging.Logger;

import ch.binding.beacon.Beacon;
import ch.binding.beacon.KeyStore;
import ch.binding.beacon.utils.AESEncrypt;

public class SQLiteKeyStore 
implements KeyStore {
	
	private static Logger logger = Beacon.getLogger();
	
	private String dbURL = "jdbc:sqlite:/home/carl/workspace/beacon/sqlite/proximity_id_store.db";

	private String pwd;
	
	/**
	 * 
	 * @param pwd if non null, attempt to encrypt/decrypt key material
	 * @param dbFn file name of SQLite DB
	 */
	public SQLiteKeyStore( String pwd, String dbFn) {
		super();
		this.pwd = pwd;
		this.dbURL = "jdbc:sqlite:" + dbFn;
	}
	
	private Connection connect() {
        // SQLite connection string
        Connection conn = null;
        try {
            conn = DriverManager.getConnection( this.dbURL);
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
        return conn;
    }
	
	@Override
	public String getKey(long keyGenIntvlNbr) {

		String select_stmt = "select * from TempExpKeys where ENIN = ?";

		try (Connection conn = this.connect(); PreparedStatement pstmt = conn.prepareStatement(select_stmt);) {

			// set the value
			pstmt.setLong(1, keyGenIntvlNbr);
			// execute query
			ResultSet rs = pstmt.executeQuery();

			int count = 0;
			String key = null;
			// loop through the result set
			while (rs.next()) {
				count++;
				key = rs.getString("key");
			}

			if (count == 0 || key == null) {
				return null;
			} else if ( count > 1) {
				logger.severe( "multiple keys for ENIN = " + Long.toString( keyGenIntvlNbr));
				return null;
			}
			
			if ( pwd != null) {
				String unencryptedKey = AESEncrypt.decrypt( key, this.pwd);
				return unencryptedKey;
			} else {
				return key;
			}
		} catch (SQLException e) {
			logger.severe(e.getMessage());
		} finally {
		}
		return null;
	}

	@Override
	public boolean addKey(long keyGenIntvlNbr, String key) {
		
		final String select_stmt = "select * from TempExpKeys where ENIN = ?";
		final String insert_stmt = "insert into TempExpKeys ( ENIN, key) values( ?, ?)";
		final String update_stmt = "update TempExpKeys set key = ? where ENIN = ?";
		
		String dbKey = key;
		
		if ( this.pwd != null) {
			dbKey = AESEncrypt.encrypt( key, this.pwd);
		}
			
		try ( Connection conn = this.connect();
	          PreparedStatement pstmt  = conn.prepareStatement( select_stmt);
			  PreparedStatement pstmt2 = conn.prepareStatement( insert_stmt);
			  PreparedStatement pstmt3 = conn.prepareStatement( update_stmt);
				){
	            
	            pstmt.setLong( 1, keyGenIntvlNbr);
	            ResultSet rs  = pstmt.executeQuery();
	            
	            int count = 0;
	       	            
	            // loop through the result set
	            while (rs.next()) {
	            	count++;
	            }
	           
	            if ( count == 0) {	          
	            	// insert new key
	            	pstmt2.setLong( 1,keyGenIntvlNbr);
	            	pstmt2.setString( 2, dbKey);	             	
	            	pstmt2.executeUpdate();
	            } else {
	            	// update
	            	pstmt3.setString( 1, dbKey);
	            	pstmt3.setLong( 2, keyGenIntvlNbr);
		            pstmt3.executeUpdate();
	            }
	        } catch (SQLException e) {
	            logger.severe(e.getMessage());
	            return false;
	        } finally {
	        }
		return true;
	}

	@Override
	public boolean purge(long beforeIntvlNbr) {

		String sql = "delete from TempExpKeys where (ENIN < ?)";
		try (Connection conn = this.connect(); 
				PreparedStatement pstmt = conn.prepareStatement(sql);) {

			pstmt.setLong( 1, beforeIntvlNbr);
			pstmt.executeUpdate();

		} catch (SQLException e) {
			logger.severe(e.getMessage());
			return false;
		} finally {
		}
		return true;
	}

}
