use std::{
    cmp::Ordering,
    collections::BinaryHeap,
    fs::File,
    io::{Result, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::mpsc,
    thread,
};

use blake3::hazmat::HasherExt;

use crate::{
    Read, TOAHeader,
    cv_stack::CVStack,
    decoder::Decoder,
    error_invalid_data,
    header::{TOABlockHeader, is_trailer_after_ecc},
    work_queue::{WorkStealingQueue, WorkerHandle},
};

#[derive(Clone, Debug)]
struct BlockWork {
    index: usize,
    offset: u64,
    compressed_size: u64,
    is_last: bool,
}

#[derive(Debug)]
enum DecoderState {
    Blocks,
    Finished,
}

#[derive(Debug)]
struct CompletedBlock {
    index: usize,
    data: Vec<u8>,
    chaining_value: [u8; 32],
}

impl PartialEq for CompletedBlock {
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index
    }
}

impl Eq for CompletedBlock {}

impl PartialOrd for CompletedBlock {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CompletedBlock {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse ordering for min-heap behavior.
        other.index.cmp(&self.index)
    }
}

/// A multi-threaded TOA file decoder that implements Read trait.
pub struct TOAFileDecoder {
    work_queue: WorkStealingQueue<BlockWork>,
    result_receiver: mpsc::Receiver<Result<CompletedBlock>>,
    worker_handles: Vec<thread::JoinHandle<()>>,
    pending_blocks: BinaryHeap<CompletedBlock>,
    next_block_index: usize,
    total_blocks: usize,
    header: TOAHeader,
    all_blocks: Vec<BlockWork>,
    blocks_queued: usize,
    cv_stack: CVStack,
    max_buffered_blocks: usize,
    workers_finished: bool,
    state: DecoderState,
    current_block: Option<Vec<u8>>,
    current_block_position: usize,
    validate_rs: bool,
    file_path: PathBuf,
}

impl TOAFileDecoder {
    /// Create a new multi-threaded TOA file decoder.
    pub fn new<P: AsRef<Path>>(
        toa_file_path: P,
        max_threads: usize,
        validate_rs: bool,
    ) -> Result<Self> {
        let toa_file_path = toa_file_path.as_ref();
        let mut file = File::open(toa_file_path)?;

        let mut header_buffer = [0u8; 32];
        file.read_exact(&mut header_buffer)?;
        let header = TOAHeader::parse(&header_buffer, validate_rs)?;
        let blocks = Self::calculate_blocks(&mut file)?;
        let total_blocks = blocks.len();

        // Limit thread count to number of blocks - no point having more threads than work.
        let effective_threads = max_threads.min(total_blocks.max(1));
        let max_buffered_blocks = (effective_threads * 2).max(1);

        let (result_sender, result_receiver) = mpsc::sync_channel(max_buffered_blocks);

        let mut decoder = Self {
            work_queue: WorkStealingQueue::new(),
            result_receiver,
            worker_handles: Vec::new(),
            pending_blocks: BinaryHeap::new(),
            next_block_index: 0,
            total_blocks,
            header,
            all_blocks: blocks.clone(),
            blocks_queued: 0,
            cv_stack: CVStack::new(),
            max_buffered_blocks,
            workers_finished: false,
            state: DecoderState::Blocks,
            current_block: None,
            current_block_position: 0,
            validate_rs,
            file_path: toa_file_path.to_path_buf(),
        };

        decoder.start_workers(toa_file_path, effective_threads, result_sender);
        decoder.queue_initial_work();

        Ok(decoder)
    }

    fn calculate_blocks(file: &mut File) -> Result<Vec<BlockWork>> {
        let mut blocks = Vec::new();
        let mut block_offset = 32u64;
        let mut index = 0u64;

        loop {
            let mut header_data = [0u8; 64];
            if file.read_exact(&mut header_data).is_err() {
                break;
            }

            // Apply ECC before checking MSB to prevent corrupted bit from causing misidentification.
            let is_trailer = is_trailer_after_ecc(&header_data, true)?;
            if is_trailer {
                // This is the file trailer, we're done with blocks.
                break;
            }

            let block_header = TOABlockHeader::parse(&header_data, true)?;
            let compressed_size = block_header.physical_size();

            blocks.push(BlockWork {
                index: index as usize,
                offset: block_offset,
                compressed_size,
                is_last: false,
            });

            block_offset += 64 + compressed_size;
            file.seek(SeekFrom::Start(block_offset))?;
            index += 1;
        }

        if let Some(last_block) = blocks.last_mut() {
            last_block.is_last = true;
        }

        Ok(blocks)
    }

    fn start_workers(
        &mut self,
        toa_file_path: &Path,
        max_threads: usize,
        result_sender: mpsc::SyncSender<Result<CompletedBlock>>,
    ) {
        for _ in 0..max_threads {
            let toa_file_path = toa_file_path.to_owned();
            let worker_handle = self.work_queue.worker();
            let sender = result_sender.clone();
            let header = self.header;
            let validate_rs = self.validate_rs;

            let handle = thread::spawn(move || {
                Self::worker_thread(toa_file_path, header, validate_rs, worker_handle, sender);
            });

            self.worker_handles.push(handle);
        }
    }

    fn queue_initial_work(&mut self) {
        let initial_count = self.total_blocks.min(self.max_buffered_blocks);

        for block in self.all_blocks[..initial_count].iter().cloned() {
            self.work_queue.push(block);
            self.blocks_queued += 1;
        }

        if self.blocks_queued >= self.total_blocks {
            self.work_queue.close();
        }
    }

    fn worker_thread(
        toa_file_path: PathBuf,
        header: TOAHeader,
        validate_rs: bool,
        worker_handle: WorkerHandle<BlockWork>,
        result_sender: mpsc::SyncSender<Result<CompletedBlock>>,
    ) {
        loop {
            let Some(block_work) = worker_handle.steal() else {
                // Queue is closed and empty, exit worker.
                return;
            };

            let result = Self::decode_block(&toa_file_path, &header, validate_rs, &block_work).map(
                |(decompressed_data, chaining_value)| CompletedBlock {
                    index: block_work.index,
                    data: decompressed_data,
                    chaining_value,
                },
            );

            // Send result through channel - if receiver is dropped, we exit.
            if result_sender.send(result).is_err() {
                return;
            }
        }
    }

    fn decode_block(
        toa_file_path: &Path,
        header: &TOAHeader,
        validate_rs: bool,
        block_work: &BlockWork,
    ) -> Result<(Vec<u8>, [u8; 32])> {
        use crate::LimitedReader;

        let mut file = File::open(toa_file_path)?;
        file.seek(SeekFrom::Start(block_work.offset))?;

        let mut header_data = [0u8; 64];
        file.read_exact(&mut header_data)?;

        let block_header = TOABlockHeader::parse(&header_data, validate_rs)?;
        let expected_hash = block_header.blake3_hash();

        let limited_reader = LimitedReader::new(file, block_work.compressed_size);
        let decoder = Decoder::new(
            limited_reader,
            header.prefilter(),
            header.error_correction(),
            validate_rs,
            header.lc(),
            header.lp(),
            header.pb(),
            header.dict_size(),
        )?;

        let mut decompressed_data = Vec::new();
        let mut decoder = decoder;
        decoder.read_to_end(&mut decompressed_data)?;

        let mut hasher = blake3::Hasher::new();
        hasher.set_input_offset(block_work.index as u64 * header.block_size());
        hasher.update(&decompressed_data);

        let (hash_verified, chaining_value) = match block_work.is_last && block_work.index == 0 {
            true => {
                // Single block file - use root hash.
                let root_hash = *hasher.finalize().as_bytes();
                (root_hash == expected_hash, root_hash)
            }
            false => {
                // Multi-block file - use chaining value.
                let chaining_value = hasher.finalize_non_root();
                (chaining_value == expected_hash, chaining_value)
            }
        };

        if !hash_verified {
            return Err(error_invalid_data("BLAKE3 hash mismatch"));
        }

        Ok((decompressed_data, chaining_value))
    }

    fn process_completed_blocks(&mut self) -> Result<()> {
        while let Ok(block_result) = self.result_receiver.try_recv() {
            match block_result {
                Ok(completed_block) => {
                    self.pending_blocks.push(completed_block);
                }
                Err(error) => {
                    return Err(error);
                }
            }
        }

        Ok(())
    }

    /// Get the next sequential block if available, updating BLAKE3 state.
    fn get_next_sequential_block(&mut self) -> Option<Vec<u8>> {
        if let Some(next_block) = self.pending_blocks.peek()
            && next_block.index == self.next_block_index
        {
            let completed_block = self.pending_blocks.pop().unwrap();

            let is_last = completed_block.index == self.total_blocks - 1;

            self.cv_stack
                .add_chunk_chaining_value(completed_block.chaining_value, is_last);

            self.next_block_index += 1;

            self.queue_more_work_if_needed();

            Some(completed_block.data)
        } else {
            None
        }
    }

    /// Queue additional work while respecting back pressure limits.
    fn queue_more_work_if_needed(&mut self) {
        if self.blocks_queued >= self.total_blocks {
            return;
        }

        // Calculate how many slots we have for more work.
        let pending_work = self.work_queue.len();
        let pending_results = self.pending_blocks.len();
        let total_in_flight = pending_work + pending_results;

        // If we're under the limit and have more blocks to queue.
        if total_in_flight < self.max_buffered_blocks && self.blocks_queued < self.total_blocks {
            let block = self.all_blocks[self.blocks_queued].clone();
            self.work_queue.push(block);
            self.blocks_queued += 1;

            if self.blocks_queued >= self.total_blocks {
                self.work_queue.close();
            }
        }
    }

    fn finalize(&mut self) -> Result<()> {
        if matches!(self.state, DecoderState::Finished) {
            return Ok(());
        }

        // When this function is called, we know all blocks have been processed:
        debug_assert_eq!(self.next_block_index, self.total_blocks);

        self.join_workers();

        let mut file = File::open(&self.file_path)?;
        file.seek(SeekFrom::End(-64))?;

        let mut trailer_buffer = [0u8; 64];
        file.read_exact(&mut trailer_buffer)?;

        let trailer = crate::trailer::TOAFileTrailer::parse(&trailer_buffer, self.validate_rs)?;
        let computed_root_hash = self.cv_stack.finalize();

        if computed_root_hash != trailer.blake3_hash() {
            return Err(error_invalid_data(
                "file integrity check failed: BLAKE3 root hash mismatch",
            ));
        }

        self.state = DecoderState::Finished;

        Ok(())
    }

    fn join_workers(&mut self) {
        if self.workers_finished {
            return;
        }

        while let Some(handle) = self.worker_handles.pop() {
            let _ = handle.join();
        }

        self.workers_finished = true;
    }
}

impl Read for TOAFileDecoder {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        loop {
            match &mut self.state {
                DecoderState::Blocks => {
                    // First, serve from current block if we have one.
                    if let Some(ref current_block) = self.current_block {
                        let available = current_block.len() - self.current_block_position;
                        if available > 0 {
                            let to_copy = buf.len().min(available);
                            buf[..to_copy].copy_from_slice(
                                &current_block[self.current_block_position
                                    ..self.current_block_position + to_copy],
                            );
                            self.current_block_position += to_copy;

                            if self.current_block_position >= current_block.len() {
                                self.current_block = None;
                                self.current_block_position = 0;
                            }

                            return Ok(to_copy);
                        }
                    }

                    // Try to get the next sequential block.
                    self.process_completed_blocks()?;

                    if let Some(next_block_data) = self.get_next_sequential_block() {
                        self.current_block = Some(next_block_data);
                        self.current_block_position = 0;
                        // Go back to serve from the new block.
                        continue;
                    }

                    if self.next_block_index >= self.total_blocks {
                        self.finalize()?;
                        continue;
                    }

                    // Block waiting for more data from workers.
                    match self.result_receiver.recv() {
                        Ok(block_result) => {
                            match block_result {
                                Ok(completed_block) => {
                                    self.pending_blocks.push(completed_block);
                                    // Try again with new block data.
                                    continue;
                                }
                                Err(error) => {
                                    return Err(error);
                                }
                            }
                        }
                        Err(_) => {
                            // Workers are done, finalize.
                            self.finalize()?;
                            continue;
                        }
                    }
                }
                DecoderState::Finished => {
                    return Ok(0);
                }
            }
        }
    }
}

impl Drop for TOAFileDecoder {
    fn drop(&mut self) {
        self.work_queue.close();
        self.join_workers();
    }
}
