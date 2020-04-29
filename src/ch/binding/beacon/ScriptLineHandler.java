package ch.binding.beacon;

public interface ScriptLineHandler {
	

	/***
	 * to handle an input line from a sub-process which is running a script.
	 * @param line
	 */
	public void onStdOutLine( final String line);
	
	public void onStdErrLine( final String line);

}
