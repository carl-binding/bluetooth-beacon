package ch.binding.beacon.dp3t;

import java.util.List;

public interface KeyStore2 {
	
	public byte [] getSeed( long epoch);
	
	public boolean putSeed( byte [] seed, long epoch);
	
	public void purgeSeeds( long beforeEpoch);
	
	public boolean putObservedEphID( byte [] hash, int rssi, long timeOfCapture);
	
	public boolean putInfectedSeed( byte [] seed, long epoch);
	
	public static class Seed {
		
		private byte [] seed;
		private long epoch;
		
		Seed( byte [] seed, long epoch) {
			super();
			this.seed = seed;
			this.epoch = epoch;
		}

		public byte [] getSeed() {
			return seed;
		}

		public long getEpoch() {
			return epoch;
		}
	
	}
	/**
	 * 
	 * @param fromEpoch
	 * @param toEpoch
	 * @return infected seeds
	 */
	public List<Seed> getInfectedSeeds( long fromEpoch, long toEpoch);
	

}
