use alloc::vec::Vec;

pub(crate) struct CircularBuffer {
    buffer: Vec<u8>,
    start: usize,
    len: usize,
}

impl CircularBuffer {
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        // Use power-of-2 for efficient modulo via bit masking.
        let capacity = capacity.next_power_of_two().max(4096);

        Self {
            buffer: vec![0u8; capacity],
            start: 0,
            len: 0,
        }
    }

    #[inline]
    pub(crate) fn available_data(&self) -> usize {
        self.len
    }

    /// Get contiguous slices without copying.
    pub(crate) fn as_slices(&self) -> (&[u8], &[u8]) {
        if self.len == 0 {
            return (&[], &[]);
        }

        let end = (self.start + self.len) & (self.buffer.len() - 1);

        if end > self.start {
            // Data is contiguous.
            (&self.buffer[self.start..self.start + self.len], &[])
        } else if end == 0 {
            // Data fills to the end.
            (&self.buffer[self.start..], &[])
        } else {
            // Data wraps around.
            (&self.buffer[self.start..], &self.buffer[..end])
        }
    }

    pub(crate) fn copy_to(&self, out: &mut [u8]) -> usize {
        let copy_len = out.len().min(self.len);
        if copy_len == 0 {
            return 0;
        }

        let (first, second) = self.as_slices();

        if copy_len <= first.len() {
            out[..copy_len].copy_from_slice(&first[..copy_len]);
        } else {
            let first_len = first.len();
            out[..first_len].copy_from_slice(first);
            let remaining = copy_len - first_len;
            if remaining > 0 && !second.is_empty() {
                out[first_len..copy_len].copy_from_slice(&second[..remaining]);
            }
        }

        copy_len
    }

    pub(crate) fn append(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        // Grow if needed (double size).
        if self.len + data.len() > self.buffer.len() {
            let new_capacity = (self.len + data.len()).next_power_of_two();
            let mut new_buffer = vec![0u8; new_capacity];

            let copied = self.copy_to(&mut new_buffer[..self.len]);
            debug_assert_eq!(copied, self.len);

            self.buffer = new_buffer;
            self.start = 0;
        }

        let write_pos = (self.start + self.len) & (self.buffer.len() - 1);
        let available_at_end = self.buffer.len() - write_pos;

        if data.len() <= available_at_end {
            self.buffer[write_pos..write_pos + data.len()].copy_from_slice(data);
        } else {
            self.buffer[write_pos..].copy_from_slice(&data[..available_at_end]);
            self.buffer[..data.len() - available_at_end].copy_from_slice(&data[available_at_end..]);
        }

        self.len += data.len();
    }

    #[inline]
    pub(crate) fn consume(&mut self, count: usize) {
        let consume_count = count.min(self.len);
        self.start = (self.start + consume_count) & (self.buffer.len() - 1);
        self.len -= consume_count;
    }

    pub(crate) fn fill_batch_from_buffer<const BATCH: usize, const DATA_LEN: usize>(
        &self,
        batch_codewords: &mut [[u8; DATA_LEN]; BATCH],
        batch_data_size: usize,
    ) -> bool {
        let (first_slice, second_slice) = self.as_slices();

        if first_slice.len() >= batch_data_size {
            // Data is contiguous, copy directly from first slice.
            for (i, codeword) in batch_codewords.iter_mut().enumerate() {
                let start = i * DATA_LEN;
                codeword.copy_from_slice(&first_slice[start..start + DATA_LEN]);
            }
            return true;
        } else if first_slice.len() + second_slice.len() >= batch_data_size {
            // Data wraps around, handle both slices.
            let mut processed_bytes = 0;
            let mut codeword_idx = 0;

            // Fill codewords from first slice.
            while processed_bytes + DATA_LEN <= first_slice.len() && codeword_idx < BATCH {
                batch_codewords[codeword_idx]
                    .copy_from_slice(&first_slice[processed_bytes..processed_bytes + DATA_LEN]);
                processed_bytes += DATA_LEN;
                codeword_idx += 1;
            }

            // Handle partial codeword at slice boundary if needed.
            if processed_bytes < first_slice.len() && codeword_idx < BATCH {
                let remaining_in_first = first_slice.len() - processed_bytes;
                let needed_from_second = DATA_LEN - remaining_in_first;

                if needed_from_second <= second_slice.len() {
                    batch_codewords[codeword_idx][..remaining_in_first]
                        .copy_from_slice(&first_slice[processed_bytes..]);
                    batch_codewords[codeword_idx][remaining_in_first..DATA_LEN]
                        .copy_from_slice(&second_slice[..needed_from_second]);
                    codeword_idx += 1;
                    processed_bytes = needed_from_second;
                }
            } else {
                processed_bytes = 0;
            }

            // Fill remaining codewords from second slice.
            while processed_bytes + DATA_LEN <= second_slice.len() && codeword_idx < BATCH {
                batch_codewords[codeword_idx]
                    .copy_from_slice(&second_slice[processed_bytes..processed_bytes + DATA_LEN]);
                processed_bytes += DATA_LEN;
                codeword_idx += 1;
            }

            return true;
        }

        false
    }
}
