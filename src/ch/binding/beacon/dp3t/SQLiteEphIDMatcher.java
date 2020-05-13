package ch.binding.beacon.dp3t;


import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;


import ch.binding.beacon.ByteArray;



public class SQLiteEphIDMatcher {
	
	private String dbURL = "jdbc:sqlite:/home/carl/workspace/beacon/sqlite/dp3t.db";
	
	SQLiteEphIDMatcher() {
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
	
	/**
	 * ephemerous ID with time-stamps and RSSI
	 * 
	 * @author carl
	 *
	 */
	public static class EphIdTS {
		
		long first_toc;
		long last_toc;
		int rssi;
		byte data[];
		
		public EphIdTS( long first_toc, long last_toc, byte data[], int rssi) {
			super();
			this.first_toc = first_toc;
			this.last_toc = last_toc;
			this.rssi = rssi;
			this.data = data;
		}
		
	}
	
	public static class Match {
		
		private SecretKey key;
		private EphIdTS ephId;
		
		public Match( SecretKey sk, EphIdTS ephId) {
			super();
			this.key = sk;
			this.ephId = ephId;
		}
		
	}
	
	/**
	 * how many days is a non-diagnosed case potentially infectious?
	 */
	public static final int INFECTIUOS_DURATION = 5;
	
	public List<Match> matches( List<SecretKey> infectiousKeys) {
		
		// purge DB of infectious keys
		if ( !purgeInfectiousKeys( 0, Integer.MAX_VALUE)) {
			throw new IllegalStateException();
		}
		
		// enter all infectious keys which are newer than today - INFECTIOUS_DURATION
		// generating the key sequences as needed		
		final long now = System.currentTimeMillis();
		final long curDay = Crypto.getDayNumber(now);
		final long fromDay = curDay - INFECTIUOS_DURATION;
		
		for ( SecretKey sk: infectiousKeys) {
			// we assume that the infectious keys are sent for their oldest infectious day.
			final long skDayNbr = sk.getDayNbr();
			if ( skDayNbr >= fromDay && skDayNbr <= curDay) {
				byte key[] = sk.getKey();
				for ( long day = skDayNbr; day <= curDay; day++) {

					if ( !enterInfectiuosKey( day, key)) {
						throw new IllegalStateException();
					}
					key = Crypto.getSKt1(key);
				}
			} else if ( skDayNbr > curDay) {
				throw new IllegalStateException( "a key of the future?");
			} else {
				System.err.println( String.format( "encountered an obsolete key: %d < %d; ignored.", skDayNbr, fromDay));
			}
		}
		
		ArrayList<Match> matches = new ArrayList<Match>();
		
		// from day to day, starting at the beginning of the infectious period and ending now.
		for ( long day = fromDay; day < curDay; day++) {
			
			// get the keys for the current day. there may be none...
			List<SecretKey> keysOfDay = getInfectiousKeys( day);
			if ( keysOfDay == null || keysOfDay.isEmpty()) {
				continue;
			}
			
			final HashMap<ByteArray, EphIdTS> lkupTbl = getEncounters( day);
			if ( lkupTbl == null || lkupTbl.isEmpty()) {
				continue;
			}
			
			for ( SecretKey sk: keysOfDay) {
				// derive list of EphIds and match against encountered EphIds
				final List<EphId> derivedEphIds = Crypto.createEphIds( sk.getKey(), false);
				if ( derivedEphIds == null || derivedEphIds.isEmpty()) {
					continue;
				}
				
				for ( EphId ephID: derivedEphIds) {
					final ByteArray ba = new ByteArray( ephID.getData());
					if ( lkupTbl.containsKey( ba)) {
						matches.add( new Match( sk, lkupTbl.get( ba)));
					}
				}
			}
		}		
		
		return matches;
		
	}

	/**
	 * 
	 * @param day
	 * @return the set of all encountered EphIds on the given day.
	 */
	private HashMap<ByteArray, EphIdTS> getEncounters(long day) {
		final String select_stmt = "select * from foreign_eph_ids where (day_nbr = ?)";
		
		try (Connection conn = this.connect(); 
				PreparedStatement pstmt = conn.prepareStatement(select_stmt);
			) {

			ResultSet rs = null;
			
			pstmt.setLong(1, day);	
			rs = pstmt.executeQuery();
			
			int count = 0;
			HashMap<ByteArray, EphIdTS> tbl = new HashMap<ByteArray, EphIdTS>();
			
			// loop through the result set
			while (rs.next()) {
				
				count++;
				
				final long first_toc = rs.getLong("first_toc");
				final long last_toc = rs.getLong("last_toc");
				final int rssi = rs.getInt( "rssi");
				final int dayNbr = rs.getInt( "day_nbr");
				final String eph_id = rs.getString( "eph_id");
								
				final EphIdTS ephId = new EphIdTS( first_toc, last_toc, Base64.getDecoder().decode( eph_id), rssi);
				
				tbl.put( new ByteArray( ephId.data), ephId);
			}

			if ( tbl.isEmpty())
				return null;
			
			return tbl;
				
			
		} catch (SQLException e) {
			System.err.println(e.getMessage());
		} finally {
		}
		return null;
	}

	private List<SecretKey> getInfectiousKeys(long day) {
		final String select_stmt = "select * from infectious_keys where (day_nbr = ?)";
			
		try (Connection conn = this.connect(); 
				PreparedStatement pstmt = conn.prepareStatement(select_stmt);
			) {

			ResultSet rs = null;
			
			pstmt.setLong(1, day);	
			rs = pstmt.executeQuery();
			
			int count = 0;
			
			ArrayList<SecretKey> tbl = new ArrayList<SecretKey>();
			
			// loop through the result set
			while (rs.next()) {
				
				count++;
				
				final int day_nbr = rs.getInt( "day_nbr");
				final byte key[] = rs.getBytes( "key"); 
				
				final SecretKey sk = new SecretKey( day_nbr, key);
				
				tbl.add( sk);
			}

			if ( tbl.isEmpty())
				return null;
			
			return tbl;
							
		} catch (SQLException e) {
			System.err.println(e.getMessage());
		} finally {
		}
		// TODO Auto-generated method stub
		return null;
	}

	private boolean enterInfectiuosKey( long day, byte[] key) {
		final String insert_stmt = "insert into infectious_keys ( day_nbr, key) values( ?, ?)";

		try ( Connection conn = this.connect();
				PreparedStatement pstmt  = conn.prepareStatement( insert_stmt);

				){

			pstmt.setLong( 1, day);
			pstmt.setBytes( 2, key);
			pstmt.executeUpdate();
		} catch (SQLException e) {
			e.printStackTrace();
			return false;
		} finally {
		}
		return true;
	}

	private boolean purgeInfectiousKeys(int from_day, int to_day) {
		String delete_stmt = "delete from secret_keys where (? <= day_nbr) and (day_nbr <= ?)";
		try (Connection conn = this.connect(); 
				PreparedStatement pstmt = conn.prepareStatement(delete_stmt);) {

			pstmt.setInt( 1, from_day);
			pstmt.setInt( 2, to_day);
			pstmt.executeUpdate();

		} catch (SQLException e) {
			System.err.println(e.getMessage());
			return false;
		} finally {
		}
		return true;
	}

}
