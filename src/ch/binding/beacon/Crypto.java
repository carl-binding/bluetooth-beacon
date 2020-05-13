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
package ch.binding.beacon;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.Properties;
import java.util.Random;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import at.favre.lib.crypto.HKDF;
import ch.binding.beacon.db.SQLiteKeyStore;

public class Crypto {
	
	static private final String KEY_STORE_FN = "keystore.bin";
	
	static Logger logger = Beacon.getLogger();
		
	static private KeyStore keyStore = null;
	
	// switch between file based key store or SQLite based key store
	static private boolean USE_DB = true;
	
	static private void init() {
		
		if ( keyStore != null)
			return;
		
		if ( USE_DB) {
			keyStore = new SQLiteKeyStore( Beacon.getPWD(), Beacon.getDBFN());
		} else {
			// file based
			String cwd = System. getProperty("user.dir");
			String keyStoreFileName = cwd + File.separator + KEY_STORE_FN;
		
			try {
				keyStore = new FileKeyStore( keyStoreFileName);
			} catch ( Exception e) {
				e.printStackTrace();
				logger.severe( e.getMessage());
				System.exit( -1);
			}
		}
		
	}
	
	static {
		init();
	}
	
	static final int VERSION = 2;
	
	private static final int KEY_LEN = 32;
	
	private static final int TEMP_EXPOSURE_KEY_LEN = 32;
	
	private static final int DAILY_TRACING_KEY_LEN = 16;
	
	private static final int ROLLING_PROXIMITY_IDENTIFIER_KEY_LEN = 16;
	
	private static final int ASSOC_ENCRYPTED_META_DATA_KEY_LEN = 16;
	
	static final int ROLLING_PROXIMITY_IDENTIFIER_LEN = 16;
			
	/***
	 * to generate a KEY_LEN random key.
	 * @return key as byte array.
	 */
	static byte [] genRandomKey() {
		Random rd = new Random( );
	    byte[] arr = new byte[KEY_LEN];
	    rd.nextBytes(arr);
	    return arr;
	}

	/***
	 * 
	 * @param tracingKeyBase64
	 * @param dayNumber
	 * @return byte array containing daily tracing key.
	 * @throws UnsupportedEncodingException
	 */
	static byte[] getDailyTracingKey( final String tracingKeyBase64, long dayNumber) 
			throws UnsupportedEncodingException {
		
		byte tracingKey[] = Base64.getDecoder().decode(tracingKeyBase64);
		
		assert( VERSION == 1);
		
		byte ct_dtk_bytes[] = "CT-DTK".getBytes( "UTF-8");
		
		int saltLength = ct_dtk_bytes.length + 4; // sizeof( uint32_t) for dayNumber
		byte salt[] = new byte[saltLength];
		
		// little endian...
		byte dn[] = {
			(byte) (dayNumber % 0xFF),
			(byte) (dayNumber >> 8 % 0xFF),
			(byte) (dayNumber >> 16 % 0xFF),
			(byte) (dayNumber >> 24 % 0xFF)			
		};
		
		System.arraycopy(ct_dtk_bytes, 0, salt, 0, ct_dtk_bytes.length);
		System.arraycopy(dn, 0, salt, ct_dtk_bytes.length, dn.length);
		
		HKDF hkdf = HKDF.fromHmacSha256();
				
		// DayNumber is encoded as a 32-bit (uint32_t) unsigned little-endian value.
		// 4 bytes
		
		return hkdf.extractAndExpand( salt, tracingKey, null, DAILY_TRACING_KEY_LEN);
	}
	
	private static final String HMAC_SHA256 = "HmacSHA256";
	
	// truncate the hash to the length of the rolling proximity ID which is the length of an UUID
	// which is 16 bytes
	private static final int ROLLING_PROXY_ID_LENGTH = 16;
	
	static byte[] getRollingProxyID(byte[] dailyTracingKey,	int timeIntervalNbr) 
			throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException {
		
		assert( VERSION == 1);
		
		byte ct_rpi_bytes[] = "CT-RPI".getBytes( "UTF-8");
		
		int dataLength = ct_rpi_bytes.length + 1; // sizeof( uin8t32_t) for timeIntervalNbr
		byte data[] = new byte[dataLength];
		
		// little endian...
		byte dn[] = {
			(byte) (timeIntervalNbr % 0xFF)		
		};
		
		System.arraycopy(ct_rpi_bytes, 0, data, 0, ct_rpi_bytes.length);
		System.arraycopy(dn, 0, data, ct_rpi_bytes.length, dn.length);
		
		Mac sha256Hmac = Mac.getInstance(HMAC_SHA256);
        SecretKeySpec keySpec = new SecretKeySpec(dailyTracingKey, HMAC_SHA256);		
        sha256Hmac.init(keySpec);
        byte[] macData = sha256Hmac.doFinal(data);
        
        assert( macData.length >= ROLLING_PROXY_ID_LENGTH);
        
        // truncate the MAC 
        return Arrays.copyOfRange(macData, 0, ROLLING_PROXY_ID_LENGTH);
        
	}

	/**
	 * 
	 * @param secsSinceEpoch
	 * @return a number for each 24-hour window. These time windows are based on Unix Epoch Time.
	 */
	static long getDayNumber( long msecsSinceEpoch) {
		return msecsSinceEpoch/(60*60*24*1000);
	}
	
	/**
	 * 
	 * @param dayNumber
	 * @return the index of the 10 minutes interval on the given day
	 */
	 public static char getTimeIntervalNumber( long dayNumber) {
		long now = System.currentTimeMillis();
		long startOfDay = dayNumber * 60 * 60 * 24; // seconds
		long secondsOfDay = (now/1000) - startOfDay;
		long nbr = secondsOfDay / ( 60 * 10);
		return (char) nbr;
	}
	 
	 /***
	  * 
	  * @return tracing key as base64 encoded string.
	  * @throws FileNotFoundException
	  * @throws IOException
	  */
	 static String getTracingKeyProperty() throws FileNotFoundException, IOException {
		 
		 assert( Crypto.VERSION == 1);
		 
		 String key = Crypto.props.getProperty( "TracingKey");
		 if ( key == null || userNameChanged( Crypto.props, Crypto.propsFN) || hostNameChanged( Crypto.props, Crypto.propsFN)) {
			 
			 byte binKey[]= genRandomKey();
			 key = Base64.getEncoder().encodeToString( binKey);
			 
			 Crypto.props.setProperty( "TracingKey", key);
			 Crypto.props.store( new FileOutputStream( Crypto.propsFN), null);
		 }
		 return key;
	}
	 
	 private static final int SECS_PER_MIN = 60;
	 private static final int MINS_PER_INTVL = 10;
	 
	/***
	 * 
	 * @param secsSinceEpoch a timestamp in seconds from Unix Epoch Time.
	 * @return a number for each 10 minute time window that’s shared between all devices
	 *  in the protocol. These time windows are derived from timestamps in Unix Epoch Time.
	 */
	public static long getENIntervalNumber( long secsSinceEpoch) {
		return secsSinceEpoch/(SECS_PER_MIN * MINS_PER_INTVL);
	}
	
	public static long getSecSinceEpoch( long enin) {
		return SECS_PER_MIN * MINS_PER_INTVL * enin;
	}
	
	/***
	 * 
	 * @param intvl index of interval since EPOCH
	 * @return interval at start of rolling period
	 */
	public static long getENPeriodStart( long intvl) {
		// starting interval nbr of current rolling-period, i.e start of day
		final long periodStartIntvl = (long) (Math.floor( (double) intvl / (double) EK_ROLLING_PERIOD) * EK_ROLLING_PERIOD);
		return periodStartIntvl;
	}
	
	/***
	 * The EKRollingPeriod is the duration for which a Temporary Exposure Key is valid (in multiples of 10
			minutes). In our protocol, EKRollingPeriod is defined as 144, achieving a key validity of 24 hours.
	 */
	public static final int EK_ROLLING_PERIOD = 144;  // 24*60*60/10*60;
	
	private static Properties props = null;
	private static String propsFN = null;
	
	/***
	 * to set properties of app
	 * @param props
	 * @param propsFN
	 */
	static void setProperties( Properties props, String propsFN) {
		Crypto.props = props;
		Crypto.propsFN = propsFN;
	}
	
	private static boolean userNameChanged( Properties props, String pfn) throws IOException {
		String propsUserName = props.getProperty( "user.name");
		if ( propsUserName == null || !propsUserName.equals( System.getProperty( "user.name"))) {
			// save the property
			props.setProperty( "user.name", System.getProperty( "user.name"));						
			props.store( new FileOutputStream( pfn), null );				
			return true;
		}
		return false;
	}
	
	private static boolean hostNameChanged( Properties props, String pfn) throws FileNotFoundException, IOException {
		String hostName = InetAddress.getLocalHost().getHostName();
		String propsHostName = props.getProperty( "host.name");
		if ( propsHostName == null || !propsHostName.equals( hostName)) {
			// save the property
			props.setProperty( "host.name", hostName);						
			props.store( new FileOutputStream( pfn), null );			
			return true;
		}
		return false;
	}
	
	/***
	 * to obtain the current temporary exposure key which is valid for one EKRollingPeriod.
	 * if needed, a new temporary exposure key is generated and persisted.
	 * 
	 * @param enin if <= 0, the current time is taken. The temporary exposure key generation interval is the start of the rolling period less or equal to enin.
	 * 
	 * @return current temporary exposure key, byte array
	 * 
	 * @throws FileNotFoundException
	 * @throws IOException
	 */
	private static synchronized byte [] getTemporaryExposureKey( long enin) throws FileNotFoundException, IOException {
		
		assert( Crypto.VERSION == 2);
				
		Crypto.init();
		
		if ( enin <= 0) {
			enin = getENIntervalNumber( System.currentTimeMillis()/1000);
		}
		
		// current interval nbr of 10 minutes intervals since EPOCH
		final long currentIntvlNbr = enin; // getENIntervalNumber( System.currentTimeMillis()/1000);
		
		// starting interval nbr of current rolling-period, i.e start of day
		long currentKeyGenIntervalNbr = getENPeriodStart( currentIntvlNbr); // (long) (Math.floor( (double) currentIntvlNbr / (double) EK_ROLLING_PERIOD) * EK_ROLLING_PERIOD);
		
		assert( currentKeyGenIntervalNbr % EK_ROLLING_PERIOD == 0);
		
		// attempt to retrieve a key from key store
		String key = Crypto.keyStore.getKey( currentKeyGenIntervalNbr);		
		
		if ( key == null) {
			// no key found, generate one
			
			logger.info( String.format( "generating a new temporary exposure key: %d", currentKeyGenIntervalNbr));
			byte temporaryExposureKey[] = genRandomKey();
			
			String keyStr = Base64.getEncoder().encodeToString(temporaryExposureKey);
			
			Crypto.keyStore.addKey(currentKeyGenIntervalNbr, keyStr);
			
			logger.info( String.format( "added new temporary exposure key to store: %d %s", currentKeyGenIntervalNbr, keyStr));
			
			return temporaryExposureKey;
		} 
		
		logger.info( String.format( "retrieved temporary exposure key from store: %d", currentKeyGenIntervalNbr));
	
		return Base64.getDecoder().decode(key);
	}
	
	/***
	 * 
	 * @return the Rolling Proximity Identifier Key (RPIK) which is derived from the Temporary Exposure Key
	 *  note that this key is not time-dependent beyond the time-dependency of the temporary exposure key.
	 *  
	 *  @param tek temporary exposure key or null.
	 *  @param enin 10 minute interval nbr since EPOCH.
	 *  
	 * @throws IOException 
	 * @throws FileNotFoundException 
	 */
	static synchronized byte [] getRollingProximityIdentifierKey( byte [] tek, long enin)
			throws FileNotFoundException, IOException {
		byte en_rpik_bytes[] = "EN-RPIK".getBytes( "UTF-8");
				
		HKDF hkdf = HKDF.fromHmacSha256();
		
		if ( tek == null) {
			tek = getTemporaryExposureKey( enin);
		}
		
		assert( tek.length == TEMP_EXPOSURE_KEY_LEN);
						
		final byte [] rpik = hkdf.extractAndExpand( en_rpik_bytes, tek, null, ROLLING_PROXIMITY_IDENTIFIER_KEY_LEN);
		
		assert( rpik.length == ROLLING_PROXIMITY_IDENTIFIER_KEY_LEN);
		
		return rpik;
	}
	
	/***
	 * rolling proximity ID, 16 byte key. changes whenever the MAC BT_ADDR would change.
	 */
	private static byte rollingProximityID[] = null;
	
	/***
	 * ENIN of currently active proximity ID
	 */
	private static long eninOfProximityIDGeneration = 0;
	
	/***
	 * 
	 * retrieves the currently valid proximity identifier.
	 * 
	 * @return currently valid proximity identifier
	 * 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws IOException 
	 * @throws FileNotFoundException 
	 */
	static synchronized byte [] getRollingProximityID() 
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, 
			IllegalBlockSizeException, BadPaddingException, FileNotFoundException, IOException {
		
		assert( VERSION == 2);
		
		Crypto.init();
		
		if ( Crypto.rollingProximityID == null) {
			Crypto.generateRollingProximityID( );
		}
		
		return Crypto.rollingProximityID;
	}
	
	
	
	/***
	 * To either generate a new rolling proximity ID or reconstruct one based on a known
	 * temporary exposure key and some matching ENIN.
	 * 
	 * @param tek temporary exposure key. can be null.
	 * 
	 * @param enin time interval
	 * 
	 * @return rolling proximity ID, 16 bytes
	 * 
	 * @throws FileNotFoundException
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static synchronized byte [] getRollingProximityID( final byte [] tek, long enin) 
			throws FileNotFoundException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, 
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		
		// when a valid enin is given, the proper key should come along too...
		if ( tek != null && enin <= 0) {
			throw new IllegalArgumentException();
		}
		if ( tek == null && enin <= 0) {
			throw new IllegalArgumentException();
		}
		
		assert( VERSION == 2);
		
		Crypto.init();
		
		byte padding[] = new byte[16];
		
		System.arraycopy( "EN-RPI".getBytes( "UTF-8"), 0, padding, 0, "EN-RPI".length());
		
		// LSB byte ordering, append ENIN
		padding[12] = (byte) (enin & 0xFF);
		padding[13] = (byte) (enin >> 8 % 0xFF);
		padding[14] = (byte) (enin >> 16 % 0xFF);
		padding[15] = (byte) (enin >> 24 % 0xFF);
		
		// Advanced Encryption Standard as specified by NIST in FIPS 197. 
		// Also known as the Rijndael algorithm by Joan Daemen and Vincent Rijmen, AES is a 128-bit block cipher supporting keys of 128, 192, and 256 bits.
		// from the interval nbr enin, we derive the key-generation-enin...
		final byte [] rpik = getRollingProximityIdentifierKey( tek, enin);
		SecretKeySpec aesKey = new SecretKeySpec( rpik, 0, ROLLING_PROXIMITY_IDENTIFIER_KEY_LEN, "AES");
		
		// https://docs.oracle.com/javase/9/docs/api/javax/crypto/Cipher.html
		// "AES/ECB/NoPadding"
		Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init( Cipher.ENCRYPT_MODE, aesKey);
        
        byte rollingProximityID[] = cipher.doFinal( padding);
		
		assert( rollingProximityID.length == ROLLING_PROXIMITY_IDENTIFIER_KEY_LEN);
		
		return rollingProximityID;
		
	}
	
	/***
	 * to generate a new rolling proximity ID. this ID uses the ENIntervalNumber of the curernt time
	 * i.e. the 10 min interval index starting with UNIX EPOCH.
	 * 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws IOException 
	 * @throws FileNotFoundException 
	 */
	static synchronized void generateRollingProximityID( ) 
			throws NoSuchAlgorithmException, 
			NoSuchPaddingException, InvalidKeyException, 
			IllegalBlockSizeException, BadPaddingException, FileNotFoundException, IOException {
		
		final long enin = getENIntervalNumber( System.currentTimeMillis()/1000);
		
		// set the current values
		Crypto.rollingProximityID = getRollingProximityID( null, enin);
		Crypto.eninOfProximityIDGeneration = enin;
		
	}
	
	
	/***
	 * The Associated Metadata Encryption keys are derived from the Temporary Exposure Keys 
	 * in order to encrypt additional metadata.
	 * 
	 * @param tek temporary exposure key or null, in which case the currently valid temp. exposure key is used.
	 * 
	 * @return associated metadata encryption key.
	 * 
	 * @throws IOException 
	 * @throws FileNotFoundException 
	 */
	static synchronized byte [] getAssociatedEncryptedMetadataKey ( byte [] tek, long enin) 
			throws FileNotFoundException, IOException {
		
		if ( tek == null) {
			if ( enin <= 0) {
				enin = Crypto.eninOfProximityIDGeneration;
			}
			assert( enin >= 0);
			tek = Crypto.getTemporaryExposureKey( enin);
		}
		
		assert( tek != null);
		
		byte ct_aemk_bytes[] = "CT-AEMK".getBytes( "UTF-8");
		
		HKDF hkdf = HKDF.fromHmacSha256();
		
		final byte [] key = hkdf.extractAndExpand( ct_aemk_bytes, tek, null, ASSOC_ENCRYPTED_META_DATA_KEY_LEN);
		
		assert( key.length == ASSOC_ENCRYPTED_META_DATA_KEY_LEN);
		
		return key;
		
	}
	
	/***
	 * 
	 * To encrypt BLE metadata. 4 bytes as per Advertising Payload specs Google & Apple. 
	 * Encryption key is derived from temporary-exposure-key and AES 128 COUNTER, no-padding is then used.
	 * 
	 * @param metadata data to be encrypted, array of bytes
	 * @param tek temporary exposure key.
	 * @param enin if < 0 use current enin.
	 * 
	 * @return encrypted data, array of bytes, identical length to input data
	 * @throws Exception 
	 */
	static byte[] getAssociatedEncryptedMetadata( byte metadata[], final byte [] tek, long enin) 
			throws Exception {
		
		Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
		
		if ( tek == null && enin < 0) {
			// we want to use the currently valid ENIN and key...		
			assert( Crypto.eninOfProximityIDGeneration >= 0);
			enin = Crypto.eninOfProximityIDGeneration;
		}
	
		// generate the AES secret key using the associated encrypted metadata key.
		final byte [] encryptionKey = getAssociatedEncryptedMetadataKey( tek, enin);
				
		assert( encryptionKey.length == ASSOC_ENCRYPTED_META_DATA_KEY_LEN);
				
		SecretKeySpec aesKey = new SecretKeySpec( encryptionKey, "AES");
					
		
		// AES CTR takes an initialization vector, IV for which they use the rolling-proximity-ID so they can decrypt when necessary
		byte rpi[] = null;
		
		if ( tek == null) {
			// we want to use the currently valid ENIN and key...					
			rpi = getRollingProximityID();			
		} else {
			rpi = getRollingProximityID( tek, enin);
		}
		
		
		assert( rpi.length == ROLLING_PROXIMITY_IDENTIFIER_LEN);
		
		IvParameterSpec ivSpec = new IvParameterSpec( rpi);
		
		cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
		
		byte encryptedMetadata[] = cipher.doFinal(metadata);
		
		assert( encryptedMetadata.length == metadata.length);
		
		return encryptedMetadata;
		
	}

	/***
	 * 
	 * @param before time-stamp, milli-secs
	 * @return success/failure
	 */
	public static boolean purgeObsoleteTempExpKeys(long before) {
		long beforeENIN = Crypto.getENIntervalNumber( before/1000);
		if ( Crypto.keyStore == null)
			return false;
		return Crypto.keyStore.purge( beforeENIN);
	}

	
}
