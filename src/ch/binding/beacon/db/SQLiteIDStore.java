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

public class SQLiteIDStore implements ProximityIDStore {

	public static final int SERVICE_DATA_LEN = 2*20; // nbr of hex-dec digits
	
	private static final int ONE_SEC = 1000; // msecs
	
	private static Logger logger = Beacon.getLogger();
	
	private String dbURL = "jdbc:sqlite:/home/carl/workspace/beacon/sqlite/proximity_id_store.db";
	
	public SQLiteIDStore( final String fn) throws Exception {
		super();
		
		this.dbURL = "jdbc:sqlite:" + fn;
		
		logger.info( String.format( "dbURL: %s", this.dbURL));
		
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
		final String insert_stmt = "insert into Encounters ( proximity_id, assoc_enc_meta_data, first_toc, last_toc) values( ?, ?, ?, ?)";
		final String update_stmt = "update Encounters set last_toc = ? where proximity_id = ?";
			
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
	            
	            // loop through the result set
	            while (rs.next()) {
	            	count++;
	            	last_toc = rs.getLong( "last_toc");
	            }
	            
	            if ( count == 0) {
	            	// insert new payload
	            	pstmt2.setString( 1,proximity_id);
	            	pstmt2.setString( 2,assoc_enc_meta_data);
	            	pstmt2.setLong( 3, ts);
	            	pstmt2.setLong( 4, ts);
	            	
	            	pstmt2.executeUpdate();
	            	
	            } else {
	            	
	            	// update only if the new capture is more than a second younger...
	            	if ( ts - last_toc >= ONE_SEC) {
		            	// update last time-of-capture
		            	
		            	pstmt3.setLong( 1, ts);
		            	pstmt3.setString( 2, proximity_id);
		            	
		            	pstmt3.executeUpdate();
	            	}
	            	
	            }
	        } catch (SQLException e) {
	            System.out.println(e.getMessage());
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
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public boolean purgeEphemerousEncounters(long duration, Date before) {
		long ts = before.getTime();
		final long now = System.currentTimeMillis();
		if ( now - ts <= duration) {
			throw new IllegalArgumentException( "before time-stamp not sufficiently far back in time...");
		}
		// TODO Auto-generated method stub
		return true;
	}

}
