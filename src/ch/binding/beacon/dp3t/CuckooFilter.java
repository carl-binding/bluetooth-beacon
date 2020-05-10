package ch.binding.beacon.dp3t;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class CuckooFilter {
	
	public static interface FingerPrinter {
		public byte[] doFingerprint( byte [] x) throws NoSuchAlgorithmException;
		public int getFPSize() throws NoSuchAlgorithmException;
	}

	/***
	 * a bucket contains one or multiple items. Each item is an array of byte.
	 * @author carl
	 *
	 */
	private static class Bucket {
		
		private byte[][] items = null;
		private int count = 0;
		private int itemSize;
		
		Bucket( int size, int itemSize) {
			items = new byte[size][];
			this.itemSize = itemSize;
			for ( int i = 0; i < size; i++) {
				items[i] = null;
			}
		}
		
		boolean checkLength( byte[] item) {
			if ( item.length != this.itemSize)
				throw new IllegalArgumentException( "mismatching item length");
			return true;
		}
		
		boolean isFull() {
			return this.count >= items.length;
		}
		
		boolean hasSpace() {
			return this.count < items.length;
		}
		
		int getRandomEntry() {
			final double r = Math.random() * this.items.length;
			return (int) Math.floor( r);
			
		}
		
		boolean contains( byte[] item) {
			
			checkLength( item);
			
			for ( int i = 0; i < this.count; i++) {
				if ( Arrays.equals( items[i], item)) {
					return true;
				}
			}
			return false;
		}
		
		boolean insert( byte[] item) {
			
			checkLength( item);
			
			if ( isFull())
				return false;
			
			items[this.count] = item;
			this.count++;
			
			return true;
		}
		
		boolean delete( byte[] item) {
			
			checkLength( item);
			
			for ( int i = 0; i < this.count; i++) {
				if ( Arrays.equals( this.items[i], item)) {
					// move other items down so we keep empty spots at end of this.items
					for ( int j = i; j < this.count-1; j++) {
						this.items[j] = this.items[j+1];
					}
					
					this.items[ this.count] = null;
					this.count--;
					
					for ( int j = this.count; j < this.items.length; j++) {
						assert( this.items[j] == null);
					}
					
					return true;
				}
			}
			
			return false;
		}

		public byte[] swap(int eIdx, byte[] f) {
			
			if ( eIdx < 0 || eIdx >= this.items.length)
				throw new IllegalArgumentException();
			if ( f == null || f.length != this.items[0].length)
				throw new IllegalArgumentException();
			if ( !isFull()) {
				throw new IllegalStateException( "swap on an empty bucket?");
			}
			
			final byte[] e = this.items[eIdx];
			this.items[eIdx] = f;
			
			return e;
		}
	}
	
	private Bucket[] table;
	private FingerPrinter fp;
	private long count = 0;
	
	public long getCount() {
		return this.count;
	}
	
	public long getSize() {
		return this.table.length * this.table[0].items.length;
	}
	
	private static byte [] xor( byte[] a, byte [] b) {
		if ( a.length != b.length)
			throw new IllegalArgumentException();
		byte c[] = new byte[a.length];
		for ( int i = 0; i < a.length; i++) 
			c[i] = (byte) ((a[i] ^ b[i]) & 0xFF);
		return c;
	}
	
	/**
	 * 
	 * @param sz > 0
	 * @return smallest integer power of 2 which is larger than sz.
	 */
	private static int pwrOfTwo( int sz) {
		if ( sz <= 0)
			throw new IllegalArgumentException();
		int i = 1;
		int s = 0;
		while ( (i << s) <= sz) s++;
		return i << s;
	}
	
	public CuckooFilter( int tableSize, int bucketSize, int itemSize, FingerPrinter fp) throws NoSuchAlgorithmException {
		super();
		
		if ( tableSize <= 0 || bucketSize <= 0 || fp == null || itemSize <= 0) {
			throw new IllegalArgumentException();
		}
		if ( itemSize != fp.getFPSize()) {
			throw new IllegalArgumentException( "item size does not match finger-printer size");
		}
		
		// make tableSize a power of two so that xor-ing of addr works
		// ex: size 6, addresses 011 and 100 are legal. 011 ^ 100 == 111 which is out of bound.
		tableSize = pwrOfTwo( tableSize);
		
		this.table = new Bucket[tableSize];
		for ( int i = 0; i < tableSize; i++) {
			this.table[i] = new Bucket( bucketSize, itemSize);
		}
		this.fp = fp;
	}
	
	private int hash( byte[] x) {
		int hc = Arrays.hashCode(x) % this.table.length;
		if ( hc < 0) 
			hc += this.table.length;
		assert( hc >= 0);
		return hc;
	}
	
	public boolean insert( byte[] x) throws NoSuchAlgorithmException {
		
		byte f[] = this.fp.doFingerprint(x);
		assert( this.table[0].checkLength(f));
		
		int i1 = this.hash( x);		
		if ( this.table[i1].hasSpace()) {
			assert( this.table[i1].insert( f));
			this.count++;
			return true;
		}
		
		int i2 = i1 ^ this.hash( f);  // xor
		if ( this.table[i2].hasSpace()) {
			assert( this.table[i2].insert( f));
			this.count++;
			return true;
		}
		
		// randomly pick i1 or i2
		int i = (Math.random()>=0.5)?i1:i2;
		
		final int maxNbrKicks = (int) ((float) this.table.length * 0.8);
		assert ( maxNbrKicks > 0);
		for ( int n = 0; n < maxNbrKicks; n++) {
			
			// randomly select an entry e from bucket[i]
			int eIdx = this.table[i].getRandomEntry();
			// swap f and the fingerprint stored in entry e
			f = this.table[i].swap( eIdx, f);
			i = i ^ this.hash( f);
			if ( this.table[i].hasSpace()) {
				assert( this.table[i].insert( f));
				this.count++;
				return true;
			}
		}
		// hashtable full
		return false;
	}
	
	public boolean lookup( byte[] x) throws NoSuchAlgorithmException {
		byte f[] = this.fp.doFingerprint(x);
		assert( this.table[0].checkLength(f));
		
		int i1 = this.hash( x);
		if ( this.table[i1].contains( f)) {
			return true;
		}
		int i2 = i1 ^ this.hash( f);  // xor
		if ( this.table[i2].contains( f)) {
			return true;
		}
		return false;
	}
	
	public boolean delete( byte[] x) throws NoSuchAlgorithmException {
		byte f[] = this.fp.doFingerprint(x);
		assert( this.table[0].checkLength(f));
		
		int i1 = this.hash( x);
		if ( this.table[i1].contains( f)) {
			if ( this.table[i1].delete( f)) {
				this.count--;
				return true;
			} else {
				return false;
			}
		}
		int i2 = i1 ^ this.hash( f);  // xor
		if ( this.table[i2].contains( f)) {
			if ( this.table[i2].delete( f)) {
				this.count--;
				return true;
			} else {
				return false;
			}
		}
		return false;
	}
	
}
