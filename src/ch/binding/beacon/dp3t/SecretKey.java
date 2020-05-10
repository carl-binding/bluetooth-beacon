package ch.binding.beacon.dp3t;

public class SecretKey {

	private int dayNbr = 0;
	private byte [] key = null;
	
	SecretKey( int dayNbr, byte [] key) {
		super();
		this.dayNbr = dayNbr;
		this.key = key;
	}

	public byte[] getKey() {
		return this.key;
	}

	public int getDayNbr() {
		return this.dayNbr;
	}
}
