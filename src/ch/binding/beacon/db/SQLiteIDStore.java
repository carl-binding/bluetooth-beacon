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
import java.util.Date;
import java.util.logging.Logger;

import ch.binding.beacon.Beacon;
import ch.binding.beacon.ProximityIDStore;

/***
 * a straightforward implementation to store proximity IDs. not space optimized.
 * I.e. data is stored as hex-dec digits, not binary. time-stamps are milli-seconds since UNIX EPOCH.
 * 
 * @author carl
 *
 */
public class SQLiteIDStore implements ProximityIDStore {

	public static final int SERVICE_DATA_LEN = 2*20; // nbr of hex-dec digits
	
	private static final int ONE_SEC = 1000; // milli-secs
	
	private static Logger logger = Beacon.getLogger();
	
	private String dbURL = "jdbc:sqlite:/home/carl/workspace/beacon/sqlite/proximity_id_store.db";
	
	public SQLiteIDStore( final String fn) throws Exception {
		super();
		
		this.dbURL = "jdbc:sqlite:" + fn;
		
		// logger.info( String.format( "dbURL: %s", this.dbURL));
		
	}
	
	private Connection connect() {
        // SQLite connection string
        Connection conn = null;
        try {
            conn = DriverManager.getConnection( this.dbURL);
        } catch (SQLException e) {
            logger.severe(e.getMessage());
        }
        return conn;
    }

	
	@Override
	public boolean store(String serviceData, int rssi, Date timeOfCapture) {
		if ( serviceData == null || serviceData.length() != SERVICE_DATA_LEN) {
			throw new IllegalArgumentException( "advertising payload must be 40 hex-digits");
		}
		long ts = timeOfCapture.getTime();
		final long now = System.currentTimeMillis();
		if ( ts >= now) {
			throw new IllegalArgumentException();
		}
		
		final String proximity_id = serviceData.substring( 0, Beacon.ROLLING_PROXY_ID_LENGTH * 2);
		final String assoc_enc_meta_data = serviceData.substring( Beacon.ROLLING_PROXY_ID_LENGTH * 2);
		
		final String select_stmt = "select * from Encounters where proximity_id = ?";
		final String insert_stmt = "insert into Encounters ( proximity_id, assoc_enc_meta_data, first_toc, last_toc, rssi) values( ?, ?, ?, ?, ?)";
		final String update_stmt = "update Encounters set last_toc = ?, rssi=? where proximity_id = ?";
			
		try ( Connection conn = this.connect();
	          PreparedStatement pstmt  = conn.prepareStatement( select_stmt);
			  PreparedStatement pstmt2 = conn.prepareStatement( insert_stmt);
			  PreparedStatement pstmt3 = conn.prepareStatement( update_stmt);
				){
	            
	            // set the value
	            pstmt.setString( 1, proximity_id);
	            // execute query
	            ResultSet rs  = pstmt.executeQuery();
	            
	            int count = 0;
	            long last_toc = 0;
	            int dbRssi = 0;
	            
	            // loop through the result set
	            while (rs.next()) {
	            	count++;
	            	last_toc = rs.getLong( "last_toc");
	            	dbRssi = rs.getInt( "rssi");
	            }
	           
	            if ( count == 0) {
	          
	            	// insert new payload
	            	pstmt2.setString( 1,proximity_id);
	            	pstmt2.setString( 2,assoc_enc_meta_data);
	            	pstmt2.setLong( 3, ts);
	            	pstmt2.setLong( 4, ts);
	            	pstmt2.setInt( 5, rssi);
	            	
	            	pstmt2.executeUpdate();
	            	
	            } else {
	            	// we keep track of the strongest RSSI...
	            	// there may be smarter things to do?
	            	int maxRssi = dbRssi>rssi?dbRssi:rssi;
	            	
	            	// update only if the new capture is more than a second apart...
	            	if ( ts - last_toc >= ONE_SEC) {
		            	// update last time-of-capture
		            	
		            	pstmt3.setLong( 1, ts);
		            	pstmt3.setInt( 2, maxRssi);
		            	pstmt3.setString( 3, proximity_id);
		            	
		            	pstmt3.executeUpdate();
	            	}
	            	
	            }
	        } catch (SQLException e) {
	            logger.severe(e.getMessage());
	            return false;
	        } finally {
	        }
		
		
		return true;
	}

	@Override
	public boolean purge(Date before) {
		long ts = before.getTime();
		if ( ts >= System.currentTimeMillis()) {
			throw new IllegalArgumentException();
		}
		String sql = "delete from Encounters where (last_toc < ?)";
		try (Connection conn = this.connect(); 
				PreparedStatement pstmt = conn.prepareStatement(sql);) {

			pstmt.setLong( 1, ts);
			pstmt.executeUpdate();

		} catch (SQLException e) {
			logger.severe(e.getMessage());
			return false;
		} finally {
		}
		return true;
	}

	@Override
	public boolean purgeEphemeralEncounters( long duration, Date before) {
		long ts = before.getTime();
		final long now = System.currentTimeMillis();
		if ( now - ts <= duration) {
			throw new IllegalArgumentException( "before time-stamp not sufficiently far back in time...");
		}
		
		String sql = "delete from Encounters where (last_toc < ?) and ((last_toc - first_toc) < ?)";
		
		try (Connection conn = this.connect(); 
				PreparedStatement pstmt = conn.prepareStatement(sql);) {

			pstmt.setLong( 1, ts);
			pstmt.setLong( 2, duration);
			
			pstmt.executeUpdate();

		} catch (SQLException e) {
			logger.severe(e.getMessage());
			return false;
		} finally {
		}
		
		return true;
	}

}
