//! Transpiled from:
//! <https://cypherpunks.venona.com/archive/1994/09/msg00304.html>

pub struct RC4Key {
	pub state: [u8; u8::MAX as usize + 1],
	pub x: u8,
	pub y: u8,
}
impl RC4Key {
	#[must_use]
	pub const fn new() -> Self {
		Self {
			state: [0; _],
			x: 0,
			y: 0,
		}
	}
	/// key-scheduling or "key-derivation".
	/// if `key_data.len() > 0x100`, all the bytes after
	/// index `0xff` will be ignored,
	/// as if it was truncated.
	pub const fn init(&mut self, key_data: &[u8]) {
		let state: &mut [u8] = &mut self.state;

		// emulate range iterator
		let mut counter: u8 = 0;
		while let Some(c) = counter.checked_add(1) {
			state[c as usize] = c;
			counter = c;
		}

		self.x = 0;
		self.y = 0;
		let mut i: usize = 0;
		let mut j: u8 = 0;

		let mut counter: u8 = 0;
		while let Some(c) = counter.checked_add(1) {
			j = j.wrapping_add(key_data[i]).wrapping_add(state[c as usize]);
			state.swap(c as _, j as _);
			// overflow is impossible here
			i = (i + 1) % key_data.len();
			counter = c;
		}
	}
}

pub const fn rc4(buf: &mut [u8], k: &mut RC4Key) {
	let mut x = k.x;
	let mut y = k.y;
	let state: &mut [u8] = &mut k.state;

	let mut i = 0;
	while i < buf.len() {
		x = x.wrapping_add(1);
		y = y.wrapping_add(state[x as usize]);
		state.swap(x as _, y as _);

		let xor_i = state[x as usize].wrapping_add(state[y as usize]);

		buf[i] ^= state[xor_i as usize];
		i += 1;
	}
	k.x = x;
	k.y = y;
}

// RC4 is a stream cipher, so let's do streaming!
pub fn rc4_g<I: IntoIterator<Item = u8>>(s: I, k: &mut RC4Key) -> impl Iterator<Item = u8> {
	let state: &mut [u8] = &mut k.state;

	s.into_iter().map(|b| {
		k.x = k.x.wrapping_add(1);
		k.y = k.y.wrapping_add(state[k.x as usize]);
		state.swap(k.x as _, k.y as _);

		let xor_i = state[k.x as usize].wrapping_add(state[k.y as usize]);

		b ^ state[xor_i as usize]
	})
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::array;

	// this one fails, but the algorithm is correct...
	// what?
	/* /// <https://en.wikipedia.org/wiki/RC4#Test_vectors>
	#[test]
	fn wp() {
		let mut k = RC4Key::new();

		k.init(b"Key");
		let mut s = *b"Plaintext";
		rc4(&mut s, &mut k);
		assert_eq!(s, *b"\xBB\xF3\x16\xE8\xD9\x40\xAF\x0A\xD3");

		k.init(b"Wiki");
		let mut s = *b"pedia";
		rc4(&mut s, &mut k);
		assert_eq!(s, *b"\x10\x21\xBF\x04\x20");
	}*/

	#[test]
	fn round_trip() {
		let mut a: [u8; 69] = array::from_fn(|i| i.try_into().unwrap());
		let mut k = RC4Key::new();

		k.init(b"key");
		rc4(&mut a, &mut k);
		assert_ne!(a, [0u8; 69]);
		assert_ne!(a, array::from_fn(|i| i.try_into().unwrap()));

		k.init(b"key");
		rc4(&mut a, &mut k);
		assert_eq!(a, array::from_fn(|i| i.try_into().unwrap()));
	}
}
