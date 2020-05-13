package ch.binding.beacon.dp3t;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Random;

public class Crypto2 {
	
	public static final long ONE_MIN_MS = 60 * 1000;
	
	public static final long ONE_HR_MS = ONE_MIN_MS * 60;
	
	public static final long ONE_DAY_MS = ONE_HR_MS * 24;
	
	public static final int EPHID_LENGTH = 16;

	public static final int NUMBER_OF_DAYS_TO_KEEP_DATA = 21;
	
	public static final int NUMBER_OF_DAYS_TO_KEEP_EXPOSED_DAYS = 10;
	
	public static final int SEED_LEN = 32;
	
	/***
	 * quarter hours
	 */
	private static final int NUMBER_OF_EPOCHS_PER_DAY = 24 * 4;
	
	public static final int MILLISECONDS_PER_EPOCH = (int) (ONE_DAY_MS / NUMBER_OF_EPOCHS_PER_DAY);
	
	/**
	 * 
	 * @param ts_msec time-stamp, msecs
	 * @return epoch index against UNIX Epoch.
	 */
	public static final long getEpoch( long ts_msec) {
		return (ts_msec / MILLISECONDS_PER_EPOCH);
	}
	
	private static boolean initialized = false;
	
	private static KeyStore2 keyStore = new SQLKeyStore2();
	
	static KeyStore2 getKeyStore() {
		return keyStore;
	}
	
	static void init() {
		if ( initialized)
			return;
		
		
		initialized = true;
	}

	static {
		init();
	}
	
	private static byte [] genRandomSeed() {
		Random rd = new Random( );
	    byte[] arr = new byte[SEED_LEN];
	    rd.nextBytes(arr);
	    return arr;
	}
	
	public static byte[] getSeed( long epoch) {
		byte [] seed = Crypto2.keyStore.getSeed( epoch);
		if ( seed == null) {
			seed = genRandomSeed();
			Crypto2.keyStore.putSeed(seed, epoch);
		}
		return seed;
	}
	
	public static byte[] truncate128( byte b[]) {
		// 128 bit == 16 byte
		if ( b == null || b.length < 16) {
			throw new IllegalArgumentException();
		}
		if ( b.length == 16)
			return b;
		byte c[] = new byte[16];
		System.arraycopy( b, 0, c, 0, 16);
		return c;
	}
	
	private static int getHashLength() throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		return md.getDigestLength();
	}
	private static byte[] hash(byte[] data) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		return md.digest( data);
	} 
	
	public static class SHA256FingerPrinter implements CuckooFilter.FingerPrinter {

		@Override
		public byte[] doFingerprint(byte[] data) throws NoSuchAlgorithmException {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			return md.digest( data);
		}

		@Override
		public int getFPSize() throws NoSuchAlgorithmException {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			return md.getDigestLength();
		}
		
	}

	/**
	 * 
	 * @param seed
	 * @param epoch interval index against UNIX EPOCH.
	 * @return ephemerous ID
	 * @throws NoSuchAlgorithmException
	 */
	public static EphId getEphId( byte [] seed, long epoch) throws NoSuchAlgorithmException {
		return new EphId( Crypto2.truncate128( Crypto2.hash( seed)), epoch);
	}
	
	/**
	 * 
	 * @param ts_msec, time-stamp, msecs
	 * @return ephemerous ID for given time-stamp
	 * @throws NoSuchAlgorithmException
	 */
	public static EphId getEphId( long ts_msec) throws NoSuchAlgorithmException {
		final long epoch = Crypto2.getEpoch( ts_msec);
		final byte seed[] = getSeed( epoch);
		return getEphId( seed, epoch);
	}

	private static int SIZE_OF_INT = 4;  // bytes
	private static int SIZE_OF_LONG = 8; // bytes
	private static int SIZE_OF_BYTE = 8; // bit
	
	public static byte[] getHash( EphId ephId) throws NoSuchAlgorithmException {
		final int dl = ephId.getData().length;
		
		byte data[] = new byte[ dl + SIZE_OF_INT];
		System.arraycopy( ephId.getData(), 0, data, 0, dl);
		int idx = dl;
		
		// we assume that epoch is using 4 bytes and MSB
		// MAX_INT epochs == 2 147 483 647 epochs =~ 214 748 364 days =~ 588351 years
		final int epoch = (int) ephId.getEpoch();
		for ( int i = 0; i < SIZE_OF_INT; i++) {
			// MSB
			final int left_shift = ((SIZE_OF_INT - (i + 1)) * SIZE_OF_BYTE);
			// LSB
			// final int left_shift = (i * SIZE_OF_BYTE);
			data[idx++] = (byte) ((epoch >> left_shift) & 0xFF);
		}
		
		return Crypto2.hash( data);
	}
	
	public static void main(String[] args) {
		
		long now = System.currentTimeMillis();
		
		try {
			EphId ephId = Crypto2.getEphId( now);
			KeyStore2 keyStore = Crypto2.getKeyStore();
			
			final byte[] hashOfEphID = Crypto2.getHash( ephId);
			keyStore.putObservedEphID( hashOfEphID, 0, now+1000*60);
			
			final long epoch = Crypto2.getEpoch( now);
			final byte [] seed = Crypto2.getSeed( epoch);
			keyStore.putInfectedSeed(seed, epoch);
			
			CuckooFilter.FingerPrinter fp = new Crypto2.SHA256FingerPrinter();
			CuckooFilter cf = new CuckooFilter( 1000, 3, Crypto2.getHashLength(), fp);
			
			// get all infected seeds
			List<KeyStore2.Seed> infectedSeeds = keyStore.getInfectedSeeds( 0, Integer.MAX_VALUE); 
			for ( KeyStore2.Seed s: infectedSeeds) {
				final EphId ephID = Crypto2.getEphId( s.getSeed(), s.getEpoch());
				final byte[] hashOfEphId = Crypto2.getHash( ephID);
				
				cf.insert( hashOfEphId);
				
				assert( cf.lookup(hashOfEphId));
				
			}
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}
}
