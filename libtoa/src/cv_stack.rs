use alloc::vec::Vec;

use blake3::hazmat::{ChainingValue, Mode, merge_subtrees_non_root, merge_subtrees_root};

/// Efficient chaining value stack for Blake3 hash computation as described in section 5.1.2 of the
/// Blake3 paper.
pub struct CVStack {
    cv_stack: Vec<ChainingValue>,
    total_chunks: u64,
}

impl CVStack {
    /// Create a new empty CV stack.
    pub fn new() -> Self {
        Self {
            cv_stack: Vec::new(),
            total_chunks: 0,
        }
    }

    /// Add a new chunk chaining value to the stack.
    ///
    /// # Parameters
    /// - `new_cv`: The chaining value of the chunk to add.
    /// - `is_last_chunk`: Whether this is the last chunk in the input.
    pub fn add_chunk_chaining_value(&mut self, mut new_cv: ChainingValue, is_last_chunk: bool) {
        self.total_chunks += 1;

        // Count trailing zeros in the new total to determine how many merges to perform.
        let merge_count = self.total_chunks.trailing_zeros();

        // Check if after all merges we'll have exactly one CV on the stack, which would
        // mean we're creating the complete tree root
        let will_be_root = is_last_chunk && (self.cv_stack.len() == merge_count as usize);

        // Perform merges for each completed subtree.
        for i in 0..merge_count {
            let left_cv = self
                .cv_stack
                .pop()
                .expect("CV stack should have enough entries for merging");

            // If this is the last merge, and we're creating the root, use root merge.
            if will_be_root && i == merge_count - 1 {
                new_cv = merge_subtrees_root(&left_cv, &new_cv, Mode::Hash).into();
            } else {
                new_cv = merge_subtrees_non_root(&left_cv, &new_cv, Mode::Hash);
            }
        }

        self.cv_stack.push(new_cv);
    }

    /// Finalize the stack and compute the root hash.
    ///
    /// This should only be called after all chunks have been added.
    pub fn finalize(&mut self) -> [u8; 32] {
        if self.cv_stack.is_empty() {
            // No chunks were added - Return the default empty hash.
            return blake3::Hasher::new().finalize().into();
        }

        if self.cv_stack.len() == 1 {
            // Only element is already the root hash.
            return self.cv_stack[0];
        }

        // Multiple subtrees remain - merge them right to left.
        let mut cv_iter = self.cv_stack.iter().rev();
        let mut result = *cv_iter.next().expect("cv_stack was empty");

        let mut remaining = cv_iter.len();

        // Merge each CV from right to left.
        for &left_cv in cv_iter {
            if remaining == 1 {
                // This is the final merge - use root flags.
                result = merge_subtrees_root(&left_cv, &result, Mode::Hash).into();
            } else {
                // Intermediate merge - use non-root flags.
                result = merge_subtrees_non_root(&left_cv, &result, Mode::Hash);
            }
            remaining -= 1;
        }

        result
    }

    /// Resets the CV stack.
    pub fn reset(&mut self) {
        self.cv_stack.clear();
        self.total_chunks = 0;
    }

    /// Check if the stack is empty.
    pub fn is_empty(&self) -> bool {
        self.cv_stack.is_empty()
    }

    /// Get the number of chunks processed so far.
    pub fn total_chunks(&self) -> u64 {
        self.total_chunks
    }

    #[cfg(test)]
    fn stack_size(&self) -> usize {
        self.cv_stack.len()
    }
}

impl Default for CVStack {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use blake3::{Hasher, hash, hazmat::HasherExt};

    use super::*;

    #[test]
    fn test_empty_stack() {
        let mut stack = CVStack::new();
        let result = stack.finalize();
        let expected = Hasher::new().finalize();
        assert_eq!(result, *expected.as_bytes());
    }

    #[test]
    fn test_single_1024_byte_chunk() {
        let mut stack = CVStack::new();

        let chunk_data = [0x42u8; 1024];

        let mut hasher = Hasher::new();
        hasher.set_input_offset(0);
        hasher.update(&chunk_data);
        let chunk_cv = *hasher.finalize().as_bytes();

        stack.add_chunk_chaining_value(chunk_cv, true);
        let cv_result = stack.finalize();

        let standard_result = hash(&chunk_data);
        assert_eq!(cv_result, *standard_result.as_bytes());
    }

    #[test]
    fn test_cvstack_handles_many_chunks() {
        let mut stack = CVStack::new();
        let mut chunks = Vec::new();

        for i in 0..10 {
            let mut chunk = [0u8; 1024];
            chunk[0] = (0x40 + i) as u8;
            chunks.push(chunk);

            let mut hasher = Hasher::new();
            hasher.set_input_offset((i * 1024) as u64);
            hasher.update(&chunk);
            let cv = hasher.finalize_non_root();

            let is_last = i == 9;
            stack.add_chunk_chaining_value(cv, is_last);
        }

        assert_eq!(stack.stack_size(), 2);

        let total_chunks = stack.total_chunks();
        assert_eq!(total_chunks, 10);

        let cv_result = stack.finalize();
        let mut combined_data = Vec::with_capacity(10240);
        for chunk in &chunks {
            combined_data.extend_from_slice(chunk);
        }
        let standard_result = hash(&combined_data);
        assert_eq!(cv_result, *standard_result.as_bytes());
    }

    #[test]
    fn test_different_sized_final_chunk() {
        let mut stack = CVStack::new();

        let chunk1 = [0x41u8; 1024];
        let chunk2 = [0x42u8; 1024];
        let chunk3 = [0x43u8; 512];

        let mut hasher1 = Hasher::new();
        hasher1.set_input_offset(0);
        hasher1.update(&chunk1);
        let cv1 = hasher1.finalize_non_root();

        let mut hasher2 = Hasher::new();
        hasher2.set_input_offset(1024);
        hasher2.update(&chunk2);
        let cv2 = hasher2.finalize_non_root();

        let mut hasher3 = Hasher::new();
        hasher3.set_input_offset(2048);
        hasher3.update(&chunk3);
        let cv3 = hasher3.finalize_non_root();

        stack.add_chunk_chaining_value(cv1, false);
        stack.add_chunk_chaining_value(cv2, false);
        stack.add_chunk_chaining_value(cv3, true);
        let cv_result = stack.finalize();

        let mut combined_data = Vec::with_capacity(2560);
        combined_data.extend_from_slice(&chunk1);
        combined_data.extend_from_slice(&chunk2);
        combined_data.extend_from_slice(&chunk3);
        let standard_result = hash(&combined_data);
        assert_eq!(cv_result, *standard_result.as_bytes());
    }

    #[test]
    fn test_powers_of_two_systematically() {
        for power in 1..=6 {
            let num_chunks = 1 << power;
            let mut stack = CVStack::new();
            let mut all_data = Vec::new();

            for i in 0..num_chunks {
                let mut chunk = [0u8; 1024];
                chunk[0] = i as u8;
                chunk[1] = (i >> 8) as u8;
                all_data.extend_from_slice(&chunk);

                let mut hasher = Hasher::new();
                hasher.set_input_offset((i * 1024) as u64);
                hasher.update(&chunk);
                let cv = hasher.finalize_non_root();

                let is_last = i == num_chunks - 1;
                stack.add_chunk_chaining_value(cv, is_last);
            }

            assert_eq!(stack.stack_size(), 1, "Failed for {} chunks", num_chunks);

            let cv_result = stack.finalize();
            let standard_result = hash(&all_data);
            assert_eq!(
                cv_result,
                *standard_result.as_bytes(),
                "Hash mismatch for {} chunks",
                num_chunks
            );
        }
    }
}
