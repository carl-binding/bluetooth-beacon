package ch.binding.beacon.db;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import ch.binding.beacon.Beacon;
import ch.binding.beacon.ByteArray;
import ch.binding.beacon.Crypto;
import ch.binding.beacon.ProximityIDMatcher;
import ch.binding.beacon.ProximityIDMatcher.Match;
import ch.binding.beacon.ProximityIDMatcher.TempExpKey;
import ch.binding.beacon.ProximityIDStore.ProximityID;
import ch.binding.beacon.ProximityIDStore;
import ch.binding.beacon.utils.AESEncrypt;

public class SQLiteProxIDMatcher implements ProximityIDMatcher {
	
	private String dbURL = "jdbc:sqlite:/home/carl/workspace/beacon/sqlite/proximity_id_store.db";
	private ProximityIDStore idStore = null; 
	
	public SQLiteProxIDMatcher( String dbFn) throws Exception {
		super();
		this.dbURL = "jdbc:sqlite:" + dbFn;
		this.idStore = new SQLiteIDStore("/home/carl/workspace/beacon/sqlite/proximity_id_store.db");
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
	
	
	public static final int INCUBATION_TIME = 21;
	
	/**
	 * 
	 * @param tempExpKeys set of newly "infected" temporary exposure keys. this can be 1'000 or more per day and
	 * for each infected key we get the history of incubation-time (we assume). We also assume that we get newly infected
	 * keys often enough, i.e. if the phone is turned off we may have to get all newly infected keys since the phone was last turned on...
	 * Evidently this can be solved in fetching infected keys since some date in the past....
	 * 
	 * 
	 * @param margin time margin for matching keys with proximity IDs (# of epochs), a small integer >= 1
	 * 
	 * @return a list of potential matches - which can be empty.
	 */
	@Override
	public List<Match> matches( List<TempExpKey> infectedTempExpKeys, int margin) {
		
		if ( infectedTempExpKeys == null || infectedTempExpKeys.isEmpty()) {
			return null;
		}
		
		if ( margin < 0)
			throw new IllegalArgumentException();
		
		// purge old keys
		if ( !purgeInfectedKeys( 0, Integer.MAX_VALUE)) {
			throw new IllegalStateException();
		}

		// enter the newly infected keys into local DB
		if ( !enterInfectedKeys( infectedTempExpKeys)) {
			throw new IllegalStateException();
		}
		
		// iterate over the past INCUBATION_TIME days. so we have around INCUBATION_TIME * # infectedTempExpKeys.
		final long now = System.currentTimeMillis();
		final long curIntvl = Crypto.getENIntervalNumber( now/1000);
		final long fromIntvl = Crypto.getENPeriodStart(curIntvl) - Crypto.EK_ROLLING_PERIOD * INCUBATION_TIME;
		
		ArrayList<Match> matches = new ArrayList<Match>();
		
		// from day to day, starting at the beginning of the incubation period and ending now.
		for ( long startOfPeriod = fromIntvl; startOfPeriod < curIntvl; startOfPeriod += Crypto.EK_ROLLING_PERIOD) {
			
			// keys are generate on a daily basis, for the beginning of the day.
			assert( startOfPeriod % Crypto.EK_ROLLING_PERIOD == 0);
			
			// get the keys for the current day. there may be none...
			List<TempExpKey> keysOfDay = getInfectedKeys( startOfPeriod);
			if ( keysOfDay == null || keysOfDay.isEmpty())
				continue;
			
			// iterate over epochs on the current day and for which we have seen infected keys
			// depending on the size of EK_ROLLING_PERIOD, this loops quite a bit.
			for ( long curEpoch = startOfPeriod; curEpoch <= startOfPeriod + Crypto.EK_ROLLING_PERIOD; curEpoch++) {
				
				// get the scanned proximity IDs for the given epoch on the given day
				// we take twice the life-time of the proximity IDs to handle delays...
				// we may not have seen any proximity IDs for the current epoch on the current day.
				final long from_ts = Crypto.getSecSinceEpoch( curEpoch) * 1000;
				final long to_ts = Crypto.getSecSinceEpoch( curEpoch + margin) * 1000;
				final HashMap<ByteArray, ProximityID>proximityIDs = this.idStore.getProximityIDs( from_ts, to_ts);
				if ( proximityIDs == null || proximityIDs.isEmpty())
					continue;
				
				// for all the keys of that day generate the proximity IDs for the current epoch and match them against the scanned proximity IDs.
				// here the Apple & Google protocol is much better the DP3T where proximity IDs can only be derived sequentially starting with the day's key.
				for ( TempExpKey tek: keysOfDay) {
					try {
						ByteArray proxID = new ByteArray( Crypto.getRollingProximityID( tek.tempExposureKey, curEpoch));
						if ( proximityIDs.containsKey(proxID)) {
							final Match match = new Match( tek, proximityIDs.get(proxID));
							matches.add( match);
						}
					} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
							| IllegalBlockSizeException | BadPaddingException | IOException e) {
						e.printStackTrace();
					}
				}
			}
		}		
		
		return matches;
	}
	
	/**
	 * 
	 * @param intvl interval of a rolling period start.
	 * 
	 * @return all "infected" keys for the given interval
	 */
	private List<TempExpKey> getInfectedKeys(long intvl) {
		
		if ( intvl % Crypto.EK_ROLLING_PERIOD != 0) {
			throw new IllegalArgumentException();
		}
		
		// System.err.println( String.format( "select * from InfectedKeys where (key_gen_intvl == %d)", intvl));
		
		final String select_stmt = "select * from InfectedKeys where (key_gen_intvl == ?)";

		try ( Connection conn = this.connect();
			  PreparedStatement pstmt  = conn.prepareStatement( select_stmt);
				){

			pstmt.setInt( 1, (int) intvl);
			ResultSet rs  = pstmt.executeQuery();

			int count = 0;

			ArrayList<TempExpKey> keys = new ArrayList<TempExpKey>();
			// loop through the result set
			while (rs.next()) {
				count++;
				
				final long dbIntvl = rs.getLong( "key_gen_intvl");
				final byte [] key = rs.getBytes( "key");
				
				TempExpKey tek = new TempExpKey( dbIntvl, key);
				keys.add( tek);
			}

			if ( keys.isEmpty())
				return null;
			
			return keys;

		} catch (SQLException e) {
			e.printStackTrace();
		} finally {
		}
		return null;
	}

	/***
	 * we assume we get all newly infected keys and discard previously received temporary exposure keys.
	 * 
	 * @param from_intvl
	 * @param to_intvl
	 * @return
	 */
	private boolean purgeInfectedKeys( long from_intvl, long to_intvl) {
		String sql = "delete from InfectedKeys where (key_gen_intvl >= ?) and (key_gen_intvl <= ?)";
		try (Connection conn = this.connect(); 
				PreparedStatement pstmt = conn.prepareStatement(sql);) {

			pstmt.setLong( 1, from_intvl);
			pstmt.setLong( 2, to_intvl);
			pstmt.executeUpdate();

		} catch (SQLException e) {
			e.printStackTrace();
			return false;
		} finally {
		}
		return true;
		
	}
	
	/***
	 * enter a list of temporary exposure keys into DB
	 * 
	 * @param infectedTempExpKeys list of temporary exposure keys
	 * 
	 * @return success/failure
	 */
	private boolean enterInfectedKeys(List<TempExpKey> infectedTempExpKeys) {
		
		final String insert_stmt = "insert into InfectedKeys ( key_gen_intvl, key) values( ?, ?)";
		
		// TBD: to batch the insertions...
		for ( TempExpKey tek: infectedTempExpKeys) {		
			try ( Connection conn = this.connect();
			      PreparedStatement pstmt  = conn.prepareStatement( insert_stmt);
				){
				
	            pstmt.setLong( 1, tek.keyGenIntvlNbr);
	            pstmt.setBytes( 2, tek.tempExposureKey);
	                        	
	            pstmt.executeUpdate();
	           
	        } catch (SQLException e) {
	           e.printStackTrace();
	           return false;
	        } finally {
	        }
		}
		
		return true;
	}

	public static void main(String[] args) {
		
		try {
			SQLiteProxIDMatcher m = new SQLiteProxIDMatcher( "/home/carl/workspace/beacon/sqlite/proximity_id_store.db");
			
			List<TempExpKey> tempExpKeys = m.getTempExpKeys(0, Integer.MAX_VALUE);
			
			List<Match> matches = m.matches( tempExpKeys, 2);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	
	}

	/**
	 * for debugging...
	 * 
	 * @param from_enin
	 * @param to_enin
	 * @return
	 */
	private List<TempExpKey> getTempExpKeys( long from_enin, long to_enin) {
		
		String select_stmt = "select * from TempExpKeys where (ENIN >= ?) and (ENIN <= ?)";
		
		ArrayList<TempExpKey> keyList = new ArrayList<TempExpKey>();

		try (Connection conn = this.connect(); 
				PreparedStatement pstmt = conn.prepareStatement(select_stmt);) {

			// set the value
			pstmt.setLong(1, from_enin);
			pstmt.setLong(2, to_enin);
			// execute query
			ResultSet rs = pstmt.executeQuery();

			int count = 0;
			
			
			// loop through the result set
			while (rs.next()) {
				count++;
				
				final String key = rs.getString("key");
				final long enin = rs.getLong( "ENIN");
				
				keyList.add( new TempExpKey( enin, key));				
			}
			
			return keyList;
			
		} catch (SQLException e) {
			e.printStackTrace();
		} finally {
		}
		
		return null;
	}
	

}
