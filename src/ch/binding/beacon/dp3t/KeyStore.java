package ch.binding.beacon.dp3t;

import java.util.List;

public interface KeyStore {

	/***
	 * to store a key in DB
	 * @param key
	 */
	boolean store( ch.binding.beacon.dp3t.SecretKey key);

	/***
	 * 
	 * @param dayNbr number of day since EPOCH. if -1 returns the latest key found in store.
	 * 
	 * @return the key for given dayNbr or null if no matching key is found
	 */
	ch.binding.beacon.dp3t.SecretKey getKey( int dayNbr);

	/***
	 * clean out key-store for keys (strictly) before the given day nbr.
	 * 
	 * @param beforeDayNbr: assumes day-nbr is in the past.
	 */
	boolean purgeSecretKeys( int beforeDayNbr);

	List<EphId> getEphIDs( int dayNbr);

	boolean storeEphIDs( int dayNbr, List<EphId> ephIds);
	
	/***
	 * deletes all self-generated ephemeral IDs on days < beforeDayNbr
	 * @param beforeDayNbr
	 * @return success/failure
	 */
	boolean purgeEphIDs( int beforeDayNbr);
	
	boolean storeForeignEphId( EphId ephId, int rssi, long timeOfCapture);
	
}
