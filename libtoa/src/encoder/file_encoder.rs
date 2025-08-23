use std::{
    cmp::Ordering,
    collections::BinaryHeap,
    fs::File,
    io::{Cursor, Result, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::mpsc,
    thread,
};

use crate::{
    LimitedReader, Read, TOABlockWriter, TOAOptions, copy_wide,
    cv_stack::CVStack,
    header::TOAHeader,
    trailer::TOAFileTrailer,
    work_queue::{WorkStealingQueue, WorkerHandle},
};

#[derive(Clone, Debug)]
struct BlockWork {
    index: usize,
    offset: u64,
    size: u64,
    is_last: bool,
}

#[derive(Debug)]
enum EncoderState {
    Header { position: usize, length: usize },
    Blocks,
    Trailer { position: usize, length: usize },
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

/// A multi-threaded TOA file encoder that implements Read trait.
pub struct TOAFileEncoder {
    work_queue: WorkStealingQueue<BlockWork>,
    result_receiver: mpsc::Receiver<Result<CompletedBlock>>,
    worker_handles: Vec<thread::JoinHandle<()>>,
    pending_blocks: BinaryHeap<CompletedBlock>,
    next_block_index: usize,
    total_blocks: usize,
    all_blocks: Vec<BlockWork>,
    blocks_queued: usize,
    cv_stack: CVStack,
    options: TOAOptions,
    uncompressed_size: u64,
    max_buffered_blocks: usize,
    workers_finished: bool,
    state: EncoderState,
    fixed_buffer: [u8; 64],
    current_block: Option<Vec<u8>>,
    current_block_position: usize,
}

impl TOAFileEncoder {
    /// Create a new multi-threaded TOA file encoder.
    pub fn new<P: AsRef<Path>>(
        input_path: P,
        options: TOAOptions,
        max_threads: usize,
    ) -> Result<Self> {
        let input_path = input_path.as_ref();
        let block_size = options.block_size().unwrap_or(u64::MAX / 2);

        let mut file = File::open(input_path)?;
        file.seek(SeekFrom::End(0))?;
        let file_size = file.stream_position()?;

        let blocks = Self::calculate_blocks(file_size, block_size);
        let total_blocks = blocks.len();

        // Limit thread count to number of blocks - no point having more threads than work.
        let effective_threads = max_threads.min(total_blocks.max(1));
        let max_buffered_blocks = (effective_threads * 2).max(1);

        let (result_sender, result_receiver) = mpsc::sync_channel(max_buffered_blocks);

        let mut encoder = Self {
            work_queue: WorkStealingQueue::new(),
            result_receiver,
            worker_handles: Vec::new(),
            pending_blocks: BinaryHeap::new(),
            next_block_index: 0,
            total_blocks,
            all_blocks: blocks.clone(),
            blocks_queued: 0,
            cv_stack: CVStack::new(),
            options,
            uncompressed_size: file_size,
            max_buffered_blocks,
            workers_finished: false,
            state: EncoderState::Header {
                position: 0,
                length: 0,
            },
            fixed_buffer: [0; 64],
            current_block: None,
            current_block_position: 0,
        };

        encoder.write_header_to_buffer()?;
        encoder.start_workers(
            input_path,
            options,
            block_size,
            effective_threads,
            result_sender,
        );
        encoder.queue_initial_work();

        Ok(encoder)
    }

    fn calculate_blocks(file_size: u64, block_size: u64) -> Vec<BlockWork> {
        let mut blocks = Vec::new();
        let mut offset = 0u64;
        let mut index = 0;

        if file_size == 0 {
            // Empty file still needs one empty block.
            blocks.push(BlockWork {
                index: 0,
                offset: 0,
                size: 0,
                is_last: true,
            });
        } else {
            while offset < file_size {
                let remaining = file_size - offset;
                let size = remaining.min(block_size);

                blocks.push(BlockWork {
                    index,
                    offset,
                    size,
                    is_last: offset + size >= file_size,
                });

                offset += size;
                index += 1;
            }
        }

        blocks
    }

    fn write_header_to_buffer(&mut self) -> Result<()> {
        let header = TOAHeader::from_options(&self.options);
        let mut buffer = Cursor::new(&mut self.fixed_buffer[..]);
        header.write(&mut buffer)?;
        let header_length = buffer.position() as usize;

        self.state = EncoderState::Header {
            position: 0,
            length: header_length,
        };

        Ok(())
    }

    fn start_workers(
        &mut self,
        input_path: &Path,
        options: TOAOptions,
        block_size: u64,
        max_threads: usize,
        result_sender: mpsc::SyncSender<Result<CompletedBlock>>,
    ) {
        for _ in 0..max_threads {
            let input_path = input_path.to_owned();
            let worker_handle = self.work_queue.worker();
            let sender = result_sender.clone();

            let handle = thread::spawn(move || {
                Self::worker_thread(input_path, options, block_size, worker_handle, sender);
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
        input_path: PathBuf,
        options: TOAOptions,
        block_size: u64,
        worker_handle: WorkerHandle<BlockWork>,
        result_sender: mpsc::SyncSender<Result<CompletedBlock>>,
    ) {
        loop {
            let Some(block_work) = worker_handle.steal() else {
                // Queue is closed and empty, exit worker.
                return;
            };

            let result = Self::encode_block(&input_path, options, block_size, &block_work).map(
                |(compressed_data, chaining_value)| CompletedBlock {
                    index: block_work.index,
                    data: compressed_data,
                    chaining_value,
                },
            );

            // Send result through channel - if receiver is dropped, we exit.
            if result_sender.send(result).is_err() {
                return;
            }
        }
    }

    fn encode_block(
        input_path: &Path,
        options: TOAOptions,
        block_size: u64,
        block_work: &BlockWork,
    ) -> Result<(Vec<u8>, [u8; 32])> {
        let mut file = File::open(input_path)?;
        file.seek(SeekFrom::Start(block_work.offset))?;

        let mut limited_reader = LimitedReader::new(file, block_work.size);
        let mut block_writer =
            TOABlockWriter::with_header_space(options, block_size, block_work.offset, true);

        copy_wide(&mut limited_reader, &mut block_writer)?;

        let (header, mut output) = block_writer.finish(block_work.is_last)?;
        let chaining_value = header.blake3_hash();

        // Write header directly into the pre-allocated space
        let mut cursor = Cursor::new(&mut output[..64]);
        header.write(&mut cursor)?;

        Ok((output, chaining_value))
    }

    /// Process completed blocks from the channel and add sequential ones to pending state.
    fn process_completed_blocks(&mut self) -> Result<()> {
        // Receive all available completed blocks.
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

            // Update BLAKE3 tree - use the blocks info to determine if last.
            let is_last = completed_block.index == self.total_blocks - 1;
            self.cv_stack
                .add_chunk_chaining_value(completed_block.chaining_value, is_last);

            self.next_block_index += 1;

            // Queue more work if needed.
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
        if matches!(
            self.state,
            EncoderState::Trailer { .. } | EncoderState::Finished
        ) {
            return Ok(());
        }

        // When this function is called, we know all blocks have been processed
        // because it's only called when next_block_index >= total_blocks
        // or when the worker channel is closed.
        debug_assert_eq!(self.next_block_index, self.total_blocks);

        self.join_workers();

        let root_hash = self.cv_stack.finalize();
        let trailer = TOAFileTrailer::new(self.uncompressed_size, root_hash);
        let mut buffer = Cursor::new(&mut self.fixed_buffer[..]);
        trailer.write(&mut buffer)?;
        let trailer_length = buffer.position() as usize;

        self.state = EncoderState::Trailer {
            position: 0,
            length: trailer_length,
        };

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

    /// Helper method to read from fixed buffer, eliminating duplication between header and trailer reading
    fn read_from_fixed_buffer(
        fixed_buffer: &[u8; 64],
        buf: &mut [u8],
        position: &mut usize,
        length: usize,
    ) -> Option<usize> {
        if *position < length {
            let available = length - *position;
            let to_copy = buf.len().min(available);
            buf[..to_copy].copy_from_slice(&fixed_buffer[*position..*position + to_copy]);
            *position += to_copy;
            Some(to_copy)
        } else {
            None
        }
    }
}

impl Read for TOAFileEncoder {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        loop {
            match &mut self.state {
                EncoderState::Header { position, length } => {
                    if let Some(bytes_read) =
                        Self::read_from_fixed_buffer(&self.fixed_buffer, buf, position, *length)
                    {
                        if *position >= *length {
                            self.state = EncoderState::Blocks;
                        }
                        return Ok(bytes_read);
                    } else {
                        self.state = EncoderState::Blocks;
                        continue;
                    }
                }
                EncoderState::Blocks => {
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

                    // If no blocks available, but we're done processing, finalize.
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
                EncoderState::Trailer { position, length } => {
                    if let Some(bytes_read) =
                        Self::read_from_fixed_buffer(&self.fixed_buffer, buf, position, *length)
                    {
                        if *position >= *length {
                            self.state = EncoderState::Finished;
                        }
                        return Ok(bytes_read);
                    } else {
                        self.state = EncoderState::Finished;
                        continue;
                    }
                }
                EncoderState::Finished => {
                    return Ok(0);
                }
            }
        }
    }
}

impl Drop for TOAFileEncoder {
    fn drop(&mut self) {
        self.work_queue.close();
        self.join_workers();
    }
}
