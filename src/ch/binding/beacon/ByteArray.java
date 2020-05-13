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

import java.util.Arrays;

/***
 * a simple wrapper for array of bytes so that we can use such beasts in hash-tables
 * by overriding hashCode() and equals()
 * 
 * @author carl
 *
 */
public class ByteArray {
	
	private byte b[];
	
	public ByteArray( byte b[]) {
		super();
		this.b = b;
	}

	public byte[] getBytes() {
		return this.b;
	}
	
	@Override
	public int hashCode() {
		return Arrays.hashCode(b);
	}
	
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		ByteArray ba = (ByteArray) o;
		return Arrays.equals( ba.b, this.b);
	}
	
}
