package ch.binding.beacon.dp3t;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.sqlite.SQLiteException;

public class SQLKeyStore2 implements KeyStore2 {

	
	private String dbURL = "jdbc:sqlite:/home/carl/workspace/beacon/sqlite/dp3t.db";
	
	SQLKeyStore2() {
		super();
	}
	
	private Connection connect() {
        // SQLite connection string
        Connection conn = null;
        try {
            conn = DriverManager.getConnection( this.dbURL);
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return conn;
    }

	@Override
	public byte[] getSeed(long epoch) {
		
		String select_stmt = "select * from seeds where epoch = ?";

		try (Connection conn = this.connect(); 
				PreparedStatement pstmt = conn.prepareStatement(select_stmt);
				) {

			ResultSet rs = null;
			
			
			// set the value
			pstmt.setLong(1, epoch);
			// execute query
			rs = pstmt.executeQuery();
			

			int count = 0;
			String seed = null;
			
			// loop through the result set
			while (rs.next()) {
				count++;
				seed = rs.getString("seed");
			}

			if (count == 0 || seed == null) {
				return null;
			} else if ( count > 1) {
				System.err.println( "multiple seeds for epoch nbr = " + Long.toString( epoch));
				return null;
			}
			
			byte seedBytes[] = Base64.getDecoder().decode( seed);
			
			return seedBytes;
				
			
		} catch (SQLException e) {
			e.printStackTrace();
		} finally {
		}
		return null;
		
	}

	@Override
	public boolean putSeed(byte[] seed, long epoch) {
		
		final String insert_stmt = "insert into seeds ( epoch, seed) values( ?, ?)";
		
		String dbSeed = Base64.getEncoder().encodeToString(seed);
			
		try ( Connection conn = this.connect();
	          PreparedStatement pstmt = conn.prepareStatement( insert_stmt);
				){
	            
	            pstmt.setLong( 1, epoch);
	            pstmt.setString( 2, dbSeed);
	            int s = pstmt.executeUpdate();    
	           
	        } catch (SQLException e) {
	            e.printStackTrace();
	            return false;
	        } finally {
	        }
		return true;
		
	}

	@Override
	public void purgeSeeds(long beforeEpoch) {
		// TODO Auto-generated method stub

	}

	private final static int ONE_SEC = 1000;
	
	@Override
	public boolean putObservedEphID(byte[] hash, int rssi, long timeOfCapture) {
		
		String hashStr = Base64.getEncoder().encodeToString( hash);
		
		final String select_stmt = "select * from observed_eph_ids where hash = ?";
		final String insert_stmt = "insert into observed_eph_ids ( hash, first_toc, last_toc, rssi) values( ?, ?, ?, ?)";
		final String update_stmt = "update observed_eph_ids set last_toc = ?, rssi = ? where hash = ?";
			
		try ( Connection conn = this.connect();
	          PreparedStatement pstmt  = conn.prepareStatement( select_stmt);
			  PreparedStatement pstmt2 = conn.prepareStatement( insert_stmt);
			  PreparedStatement pstmt3 = conn.prepareStatement( update_stmt);
				){
	            
	            // set the value
	            pstmt.setString( 1, hashStr);
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
	            	pstmt2.setString( 1, hashStr);
	            	pstmt2.setLong( 2, timeOfCapture);
	            	pstmt2.setLong( 3, timeOfCapture);
	            	pstmt2.setInt( 4, rssi);	            	
	            	pstmt2.executeUpdate();
	            	
	            } else {
	            	// we keep track of the strongest RSSI...
	            	// there may be smarter things to do?
	            	int maxRssi = dbRssi>rssi?dbRssi:rssi;
	            	
	            	// update only if the new capture is more than a second apart...
	            	if ( timeOfCapture - last_toc >= ONE_SEC) {
		            	// update last time-of-capture
		            	
		            	pstmt3.setLong( 1, timeOfCapture);
		            	pstmt3.setInt( 2, maxRssi);
		            	pstmt3.setString( 3, hashStr);
		            	
		            	pstmt3.executeUpdate();
	            	}
	            	
	            }
	        } catch (SQLException e) {
	            e.printStackTrace();
	            return false;
	        } finally {
	        }
		
		
		return true;

	}

	private static final int SQLITE_CONSTRAINT = 19;
	
	@Override
	public boolean putInfectedSeed(byte[] seed, long epoch) {
		String seedStr = Base64.getEncoder().encodeToString(seed);
		
		final String insert_stmt = "insert into infected_seeds ( seed, epoch) values( ?, ?)";
		
		try ( Connection conn = this.connect();
		          PreparedStatement pstmt  = conn.prepareStatement( insert_stmt);
			){
			// insert new payload
        	pstmt.setString( 1, seedStr);
        	pstmt.setInt( 2, (int) epoch);
        	            	
        	pstmt.executeUpdate();
		} catch ( SQLException e) {
			if ( e instanceof SQLiteException) {
				SQLiteException se = (SQLiteException) e;
				int ec = se.getErrorCode();
				// data already in DB.
				if ( ec == SQLITE_CONSTRAINT) {
					return true;
				}
			}
			e.printStackTrace();
			return false;
		}
		return true;
	}

	@Override
	public List<Seed> getInfectedSeeds(long fromEpoch, long toEpoch) {
		
		final String select_stmt = "select * from infected_seeds where ( ? <= epoch) and ( epoch <= ?)";
		try ( Connection conn = this.connect();
		          PreparedStatement pstmt  = conn.prepareStatement( select_stmt);
				 
			){
            
            pstmt.setLong( 1, fromEpoch);
            pstmt.setLong( 2, toEpoch);
            // execute query
            ResultSet rs  = pstmt.executeQuery();
            
            ArrayList<Seed> seeds = new ArrayList<Seed>();
            // loop through the result set
            while (rs.next()) {
            	final long epoch = rs.getLong( "epoch");
            	final String seedStr = rs.getString( "seed");
            	final byte [] seed = Base64.getDecoder().decode( seedStr);
            	seeds.add( new Seed( seed, epoch));
            }
           
           if ( seeds.isEmpty())
        	   return null;
            	
           return seeds;
        } catch (SQLException e) {
            e.printStackTrace();
            return null;
        } finally {
        }
			
	}

}
