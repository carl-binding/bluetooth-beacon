package ch.binding.beacon.dp3t;

public interface EphIdMatcher {
	
	/***
	 * have we found a match with an encountered ephID?
	 * 
	 * @param ephId an ephID of a now declared infected person.
	 * @param dayNbr the day on which the ephId was emitted by the now infected person
	 * 
	 * @return true if we have seen this ephID on that day.
	 */
	public boolean matches( EphId ephId, int dayNbr);

}
