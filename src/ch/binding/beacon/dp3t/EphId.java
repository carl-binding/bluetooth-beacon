package ch.binding.beacon.dp3t;

import java.util.Arrays;

public class EphId {
	
	private byte[] data;
	private long epoch = 0;

	public EphId(byte[] data) {
		this.data = data;
	}
	
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
