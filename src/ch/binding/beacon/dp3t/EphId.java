package ch.binding.beacon.dp3t;

import java.util.Arrays;

public class EphId {
	
	private byte[] data;
	
	/**
	* if != 0, index of interval against start-of-day (scheme 1)
	* if != 0, index of interval against UNIX EPOCH (scheme 2)
	* */
	private long epoch = 0;

	public EphId(byte[] data) {
		this.data = data;
	}
	
	/**
	 * 
	 * @param data
	 * @param epoch interval against start-of-day (scheme 1) or against UNIX EPOCH (scheme 2).
	 */
	public EphId( byte [] data, long epoch) {
		super();
		this.data = data;
		this.epoch = epoch;
	}

	public byte[] getData() {
		return data;
	}
	
	public long getEpoch() {
		return epoch;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		EphId ephId = (EphId) o;
		return Arrays.equals(data, ephId.data) && (ephId.epoch == this.epoch);
	}

	@Override
	public int hashCode() {
		return Arrays.hashCode(data);
	}

}
