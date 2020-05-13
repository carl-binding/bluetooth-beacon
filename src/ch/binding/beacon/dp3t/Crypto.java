package ch.binding.beacon.dp3t;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import ch.binding.beacon.dp3t.SQLiteEphIDMatcher.Match;

public class Crypto {
	
	public static final long ONE_MIN_MS = 60 * 1000;
	
	public static final long ONE_HR_MS = ONE_MIN_MS * 60;
	
	public static final long ONE_DAY_MS = ONE_HR_MS * 24;
	
	public static final int EPHID_LENGTH = 16;

	public static final int NUMBER_OF_DAYS_TO_KEEP_DATA = 21;
	
	public static final int NUMBER_OF_DAYS_TO_KEEP_EXPOSED_DAYS = 10;
	
	/***
	 * quarter hours
	 */
	public static final int NUMBER_OF_EPOCHS_PER_DAY = 24 * 4;
	
	public static final int MILLISECONDS_PER_EPOCH = (int) (ONE_DAY_MS / NUMBER_OF_EPOCHS_PER_DAY);

	static final byte[] BROADCAST_KEY = "broadcast key".getBytes();
	
	private static KeyStore keyStore = new SQLKeyStore();
	
	/***
	 * day number since UNIX EPOCH.
	 * 
	 * @param ts_msec time-stamp in milli-secs
	 * 
	 * @return day nbr since UNIX EPOCH
	 */
	static int getDayNumber( long ts_msec) {
		long dn = (ts_msec / ONE_DAY_MS);
		return (int) dn;
	}
	
	private static boolean initialized = false;
	
	
	static void init() throws NoSuchAlgorithmException {
		if ( initialized)
			return;
		
		// get the key for today from store
		final int dayNbr = getDayNumber( System.currentTimeMillis());
		byte [] key = getSecretKeyOfDay( dayNbr);
		
		// if none, create a new one and store for today.
		if ( key == null) {
			// we don't get a key when the DB is empty OR when the newest key is older than NUMBER_OF_DAYS_TO_KEEP_DATA days
			// in which case we start a new key sequence altogether and thus wipe out all data.
			assert( Crypto.purgeOldKeys( true));
			
			key = getNewRandomKey();
			keyStore.store( new ch.binding.beacon.dp3t.SecretKey( dayNbr, key));
		}
		initialized = true;
	}

	static {
		try {
			init();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			System.exit( -1);
		}
	}
	
	static byte[] getNewRandomKey() throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA256");
		SecretKey secretKey = keyGenerator.generateKey();
		return secretKey.getEncoded();
	}
	
	/***
	 * given today's key, generate tomorrow's key.
	 * 
	 * @param SKt0 today's key
	 * @return tomorrow's key
	 */
	 static byte[] getSKt1(byte[] SKt0) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] SKt1 = digest.digest(SKt0);
			return SKt1;
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("SHA-256 algorithm must be present!");
		}
	}
	
	/***
	 * 
	 * @param all if true, delete ALL secret keys and ephemeral IDs before and including today.
	 *   else delete data which is older than the NUMBER_OF_DAYS_TO_KEEP_DATA
	 *   
	 * @return success/failure
	 */
	private static boolean purgeOldKeys( boolean all) {
		
		final int today = getDayNumber( System.currentTimeMillis());
		int beforeDayNbr = today;
		
		if ( ! all) {
			beforeDayNbr -= NUMBER_OF_DAYS_TO_KEEP_DATA;
		} else {
			beforeDayNbr += 10*365; // including today...
		}
		
		boolean r = keyStore.purgeSecretKeys( beforeDayNbr);
		r &= keyStore.purgeEphIDs( beforeDayNbr);
		
		return r;	
	}
	
	static byte[] getSecretKeyOfDay( int dayNbr) {
		
		if ( dayNbr <= 0) {
			throw new IllegalArgumentException( "dayNbr < 0");
		}
		
		// check if dayNbr's key is in database and return
		ch.binding.beacon.dp3t.SecretKey key = keyStore.getKey( dayNbr);
		if ( key != null)
			return key.getKey();
		
		assert( purgeOldKeys( false));
		
		// if not, get latest key - if any - in database and generate missing day keys as needed
		key = keyStore.getKey( -1);
		if ( key != null) {
						
			// trying to retrieve a key before the most recently generated key?
			// we either retrieve a key in the time-window for which we keep keys or must generate keys moving
			// forward in time.
			if ( dayNbr < key.getDayNbr()) {
				throw new IllegalArgumentException( "day nbr before most recent key");
			}
			
			assert( key.getDayNbr() < dayNbr);
			final int today = getDayNumber( System.currentTimeMillis());
			
			if ( dayNbr > today) {
				System.err.println( "generating key(s) into the future?");
			}
			
			for ( int i = (int) (key.getDayNbr() + 1); i <= dayNbr; i++) {
				// generate daily keys, store them in DB.
				final byte [] keyBytes = getSKt1( key.getKey());
				ch.binding.beacon.dp3t.SecretKey nextKey = new ch.binding.beacon.dp3t.SecretKey( i, keyBytes);
				keyStore.store( nextKey);
				key = nextKey;
			}
			return key.getKey();
		}
		// if no latest key in database, return null.
		return null;
	}
	
	/**
	 * 
	 * @param ts time-stamp, msecs
	 * @return start-of-day, msecs
	 */
	static long getStartOfDay( long ts) {
		long ll =  ts - (ts % ONE_DAY_MS);
		assert( ll % ONE_DAY_MS == 0);
		return ll;
	}
	
	/**
	 * 
	 * @param time time-stamp, msecs
	 * @return epoch on day corresponding to time-stamp
	 */
	static int getEpochCounter(long time) {
		return (int) (time - getStartOfDay( time)) / MILLISECONDS_PER_EPOCH;
	}

	static long getCurrentEpochStart() {
		long now = System.currentTimeMillis();
		return getEpochStart(now);
	}

	/**
	 * 
	 * @param time, time-stamp, msecs
	 * @return time-stamp of epoch start, msecs
	 */
	static long getEpochStart(long time) {
		return getStartOfDay( time) + getEpochCounter(time) * MILLISECONDS_PER_EPOCH;
	}

	static List<EphId> createEphIds(byte[] SK, boolean shuffle) {
		
		// System.err.println( Base64.getEncoder().encodeToString(SK));
		
		try {
			Mac mac = Mac.getInstance("HmacSHA256");
			mac.init(new SecretKeySpec(SK, "HmacSHA256"));
			mac.update(BROADCAST_KEY);
			byte[] prf = mac.doFinal();

			//generate EphIDs
			SecretKeySpec keySpec = new SecretKeySpec(prf, "AES");
			Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
			byte[] counter = new byte[16];
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(counter));
			ArrayList<EphId> ephIds = new ArrayList<>();
			byte[] emptyArray = new byte[EPHID_LENGTH];
			for (int i = 0; i < NUMBER_OF_EPOCHS_PER_DAY; i++) {
				final byte[] ephIdData = cipher.update(emptyArray);
				
				// System.err.println(  Base64.getEncoder().encodeToString(ephIdData));
				
				ephIds.add( new EphId( ephIdData));
			}
			if (shuffle) {
				Collections.shuffle(ephIds, new SecureRandom());
			}
			return ephIds;
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
			throw new IllegalStateException("HmacSHA256 and AES algorithms must be present!", e);
		}
	}

	private static List<EphId> getEphIDs( int dayNbr) {
		final byte [] dailyKey = getSecretKeyOfDay( dayNbr);
		List<EphId> ephIds = keyStore.getEphIDs(dayNbr);
		if ( ephIds == null) {
			ephIds = createEphIds( dailyKey, false);
			if ( !keyStore.storeEphIDs( dayNbr, ephIds)) {
				return null;
			}
		}
		return ephIds;
	}
		
	public static EphId getEphId( long ts_msec) {
		final int dayNbr = getDayNumber( getStartOfDay( ts_msec));
		final int epochNbr = getEpochCounter( ts_msec);
		List<EphId> ephIds = getEphIDs( dayNbr);
		if ( ephIds == null)
			return null;
		return ephIds.get( epochNbr);
	}

	
	private static final int NBR_KEYS = 1000;
	
	public static void main(String[] args) {
		
		long now = System.currentTimeMillis();
		int today = Crypto.getDayNumber( now);
		
		byte[] sk = Crypto.getSecretKeyOfDay( today);
		EphId ephId = Crypto.getEphId( now);
		
		System.out.println( Base64.getEncoder().encodeToString( ephId.getData()));
		
		int tomorrow = Crypto.getDayNumber( now + ONE_DAY_MS);
		byte[] sk2 = Crypto.getSecretKeyOfDay( tomorrow);
				
		KeyStore keyStore = Crypto.keyStore;
		
		keyStore.storeForeignEphId( ephId, -50, now+10*1000);
		
		SQLiteEphIDMatcher matcher = new SQLiteEphIDMatcher();
		ArrayList<ch.binding.beacon.dp3t.SecretKey> infectiousKeys = new ArrayList<ch.binding.beacon.dp3t.SecretKey>();
		infectiousKeys.add( new ch.binding.beacon.dp3t.SecretKey( today, sk));
		
		List<Match> matches = matcher.matches( infectiousKeys);	
		
		infectiousKeys = new ArrayList<ch.binding.beacon.dp3t.SecretKey>();
		
		// build a list of keys
		for ( int i = 0; i < NBR_KEYS; i++) {
			int d = today-3;
			try {
				sk = Crypto.getNewRandomKey();
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
				System.exit( -1);
			}
			
			ch.binding.beacon.dp3t.SecretKey ssk = new ch.binding.beacon.dp3t.SecretKey( d, sk);
			infectiousKeys.add(  ssk);
			
			System.out.println( "new key generated...");
			
			// for every key create ephemerous IDs. we get a list of 96 here
			List<EphId> ephIDs = createEphIds( ssk.getKey(), false);
			
			// pick one eph-id from list
			int epochOfDay = (int) (Math.random() * (NUMBER_OF_EPOCHS_PER_DAY-1)); // 15;
			long ts = (d * ONE_DAY_MS) + epochOfDay * MILLISECONDS_PER_EPOCH;
			keyStore.storeForeignEphId( ephIDs.get( epochOfDay), -50, ts);
			
			// and one more
			keyStore.storeForeignEphId( ephIDs.get( epochOfDay+1), -50, ts+MILLISECONDS_PER_EPOCH);
			
			System.out.println( "eph id stored...");
			
		}
		
		String timeStamp = new SimpleDateFormat("yyyy.MM.dd HH:mm:ss").format(new Date());
		System.out.println( timeStamp);
		
		// now see if we get matches...
		matches = matcher.matches( infectiousKeys);
		
		timeStamp = new SimpleDateFormat("yyyy.MM.dd HH:mm:ss").format(new Date());
		System.out.println( timeStamp);
		
	}
}
