package ch.binding.beacon.dp3t;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import ch.binding.beacon.dp3t.KeyStore;

public class SQLKeyStore implements KeyStore, EphIdMatcher {
	
	
	private String dbURL = "jdbc:sqlite:/home/carl/workspace/beacon/sqlite/dp3t.db";
	
	SQLKeyStore() {
		super();
	}
	
	private Connection connect() {
        // SQLite connection string
        Connection conn = null;
        try {
            conn = DriverManager.getConnection( this.dbURL);
        } catch (SQLException e) {
            System.err.println(e.getMessage());
        }
        return conn;
    }
	

	@Override
	public boolean store(SecretKey key) {
		
		final String select_stmt = "select * from secret_keys where day_nbr = ?";
		final String insert_stmt = "insert into secret_keys ( day_nbr, key) values( ?, ?)";
		final String update_stmt = "update secret_keys set key = ? where day_nbr = ?";
		
		String dbKey = Base64.getEncoder().encodeToString(key.getKey());
			
		try ( Connection conn = this.connect();
	          PreparedStatement pstmt  = conn.prepareStatement( select_stmt);
			  PreparedStatement pstmt2 = conn.prepareStatement( insert_stmt);
			  PreparedStatement pstmt3 = conn.prepareStatement( update_stmt);
				){
	            
	            pstmt.setLong( 1, key.getDayNbr());
	            ResultSet rs  = pstmt.executeQuery();
	            
	            int count = 0;
	       	            
	            // loop through the result set
	            while (rs.next()) {
	            	count++;
	            }
	           
	            if ( count == 0) {	          
	            	// insert new key
	            	pstmt2.setLong( 1, key.getDayNbr());
	            	pstmt2.setString( 2, dbKey);	             	
	            	pstmt2.executeUpdate();
	            } else {
	            	// update
	            	pstmt3.setString( 1, dbKey);
	            	pstmt3.setLong( 2, key.getDayNbr());
		            pstmt3.executeUpdate();
	            }
	        } catch (SQLException e) {
	            e.printStackTrace();
	            return false;
	        } finally {
	        }
		return true;
			
	}

	@Override
	public SecretKey getKey( int dayNbr) {
		
		String select_stmt = "select * from secret_keys where day_nbr = ?";
		String select_latest = "select * from secret_keys where day_nbr = ( select max( day_nbr) from secret_keys )";
		

		try (Connection conn = this.connect(); 
				PreparedStatement pstmt = conn.prepareStatement(select_stmt);
				PreparedStatement pstmt2 = conn.prepareStatement( select_latest)) {

			ResultSet rs = null;
			
			if ( dayNbr > 0) {
				// set the value
				pstmt.setLong(1, dayNbr);
				// execute query
				rs = pstmt.executeQuery();
			} else {
				rs = pstmt2.executeQuery();
			}

			int count = 0;
			String key = null;
			// in case we retrieve the newest key, dayNbr < 0...
			int dn = 0;
			
			// loop through the result set
			while (rs.next()) {
				count++;
				key = rs.getString("key");
				dn = rs.getInt("day_nbr");
			}

			if (count == 0 || key == null) {
				return null;
			} else if ( count > 1) {
				System.err.println( "multiple keys for day nbr = " + Long.toString( dayNbr));
				return null;
			}
			
			byte keyBytes[] = Base64.getDecoder().decode(key);
			
			return new SecretKey( dn, keyBytes);
				
			
		} catch (SQLException e) {
			System.err.println(e.getMessage());
		} finally {
		}
		return null;
	}

	@Override
	public boolean purgeSecretKeys(int beforeDayNbr) {
		String sql = "delete from secret_keys where (day_nbr < ?)";
		try (Connection conn = this.connect(); 
				PreparedStatement pstmt = conn.prepareStatement(sql);) {

			pstmt.setInt( 1, beforeDayNbr);
			pstmt.executeUpdate();

		} catch (SQLException e) {
			System.err.println(e.getMessage());
			return false;
		} finally {
		}
		return true;

	}

	@Override
	public List<EphId> getEphIDs(int dayNbr) {
		
		String select_stmt = "select * from eph_ids where ( day_nbr = ?) order by epoch_nbr asc";		

		try (Connection conn = this.connect(); 
				PreparedStatement pstmt = conn.prepareStatement(select_stmt);
				) {

			ResultSet rs = null;
			
			// set the value
			pstmt.setLong(1, dayNbr);
			// execute query
			rs = pstmt.executeQuery();
			

			int count = 0;
			ArrayList<EphId> ephIds = new ArrayList<EphId>();
			
			// loop through the result set which is ordered on epoch_nbr
			while (rs.next()) {
				count++;
				final String ephIdStr = rs.getString( "eph_id");
				final byte [] ephId = Base64.getDecoder().decode( ephIdStr);
				ephIds.add( new EphId( ephId));
			}

			if (count == 0) {
				return null;
			} 
			
			return ephIds;				
			
		} catch (SQLException e) {
			System.err.println(e.getMessage());
		} finally {
		}
		return null;
	}

	@Override
	public boolean storeEphIDs( int dayNbr, List<EphId> ephIds) {
		
		final String insert_stmt = "insert into eph_ids ( day_nbr, epoch_nbr, eph_id) values( ?, ?, ?)";
		
		// the ephIDs are ordered
		int epochNbr = 0;
		
		for ( EphId ephId: ephIds) {
			try (Connection conn = this.connect(); 
					PreparedStatement pstmt = conn.prepareStatement(insert_stmt);
					) {
				final String ephIdStr = Base64.getEncoder().encodeToString( ephId.getData()); 
				pstmt.setLong( 1, dayNbr);
            	pstmt.setInt( 2, epochNbr++);
            	pstmt.setString( 3,  ephIdStr);
            	pstmt.executeUpdate();      
            	            	
			} catch ( Exception e) {
				System.err.println(e.getMessage());
				return false;
			} finally {
			}

		}
		return true;
	}

	@Override
	public boolean purgeEphIDs( int beforeDayNbr) {
		String sql = "delete from eph_ids where (day_nbr < ?)";
		try (Connection conn = this.connect(); 
				PreparedStatement pstmt = conn.prepareStatement(sql);) {

			pstmt.setInt( 1, beforeDayNbr);
			pstmt.executeUpdate();

		} catch (SQLException e) {
			System.err.println(e.getMessage());
			return false;
		} finally {
		}
		return true;

	}

	@Override
	public boolean matches(EphId ephId, int dayNbr) {
		
		final String select_stmt = "select * from foreign_eph_ids where (day_nbr = ?) and (eph_id = ?)";
		final String ephIdStr = Base64.getEncoder().encodeToString( ephId.getData());
		
		try ( Connection conn = this.connect();
		          PreparedStatement pstmt  = conn.prepareStatement( select_stmt);
					){
		            
            // set the value
            pstmt.setInt( 1, dayNbr);
            pstmt.setString( 2,  ephIdStr);
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
           
           return count > 0;
           
        } catch (SQLException e) {
            e.printStackTrace();
      
        } finally {
        }
		
		return false;
	}

	private static final long ONE_SEC = 1000; 
	
	@Override
	public boolean storeForeignEphId(EphId ephId, int rssi, long timeOfCapture) {
		
		final int dayNbr = Crypto.getDayNumber(timeOfCapture);
		
		final String select_stmt = "select * from foreign_eph_ids where (day_nbr = ?) and (eph_id = ?)";
		final String insert_stmt = "insert into foreign_eph_ids ( day_nbr, first_toc, last_toc, eph_id, rssi) values( ?, ?, ?, ?, ?)";
		final String update_stmt = "update foreign_eph_ids set last_toc = ?, rssi=? where (day_nbr = ?) and (eph_id = ?)";
		
		final String ephIdStr = Base64.getEncoder().encodeToString( ephId.getData());
			
		try ( Connection conn = this.connect();
	          PreparedStatement pstmt  = conn.prepareStatement( select_stmt);
			  PreparedStatement pstmt2 = conn.prepareStatement( insert_stmt);
			  PreparedStatement pstmt3 = conn.prepareStatement( update_stmt);
				){
	            
	            // set the value
	            pstmt.setInt( 1, dayNbr);
	            pstmt.setString( 2,  ephIdStr);
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
	          
	            	// insert new ephID
	            	pstmt2.setInt( 1, dayNbr);
	            	pstmt2.setLong( 2, timeOfCapture);
	            	pstmt2.setLong( 3, timeOfCapture);
	            	pstmt2.setString( 4, ephIdStr);
	            	pstmt2.setInt( 5, rssi);
	            	
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
		            	pstmt3.setInt( 3, dayNbr);
		            	pstmt3.setString( 4, ephIdStr);
		            	
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

	
}
