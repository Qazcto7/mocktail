#include "mocktail/graphics/etc2_decoder.h"

#include "mocktail/mocktail_rust.h"

#include <algorithm>
#include <array>
#include <pthread.h>

#include <atomic>
#include <condition_variable>
#include <deque>
#include <limits>
#include <mutex>
#include <thread>
#include <vector>

namespace mocktail::graphics {

std::size_t EtcBlockBytes(EtcFormat format) {
  switch (format) {
    case EtcFormat::kEtc2Rgba8:
    case EtcFormat::kEacRg11:
    case EtcFormat::kEacRg11Signed:
      return 16;
    default:
      return 8;
  }
}

std::size_t EtcDecodedTexelBytes(EtcFormat format) {
  switch (format) {
    case EtcFormat::kEacR11:
    case EtcFormat::kEacR11Signed:
      return 2;
    default:
      return 4;
  }
}

namespace {

constexpr std::uint64_t kBlocksPerBand = 1024;
constexpr std::uint64_t kParallelMinimumBlocks = 4096;

bool ImageFits(EtcFormat format, const std::uint8_t* source,
               std::size_t source_bytes, std::uint32_t width,
               std::uint32_t height, const std::uint8_t* destination,
               std::size_t destination_bytes) {
  if (source == nullptr || destination == nullptr || width == 0 ||
      height == 0) {
    return false;
  }
  const std::uint64_t blocks_wide = (static_cast<std::uint64_t>(width) + 3) / 4;
  const std::uint64_t blocks_high =
      (static_cast<std::uint64_t>(height) + 3) / 4;
  return blocks_wide * blocks_high * EtcBlockBytes(format) <= source_bytes &&
         static_cast<std::uint64_t>(width) * height *
                 EtcDecodedTexelBytes(format) <=
             destination_bytes;
}

}  // namespace

bool DecodeEtcImage(EtcFormat format, const std::uint8_t* source,
                    std::size_t source_bytes, std::uint32_t width,
                    std::uint32_t height, std::uint8_t* destination,
                    std::size_t destination_bytes) {
  return DecodeEtcImageBlockRows(format, source, source_bytes, width, height, 0,
                                 (height + 3) / 4, destination,
                                 destination_bytes);
}

namespace {

struct DecodeBand {
  EtcDecodeJob* job;
  std::uint32_t first_block_row;
  std::uint32_t block_row_count;
};

struct DecodeBandQueue {
  std::vector<DecodeBand> bands;
  std::atomic<std::size_t> next{0};
  std::mutex mutex;
  std::condition_variable completed;
  unsigned workers = 0;

  void Run() {
    for (;;) {
      const std::size_t index = next.fetch_add(1, std::memory_order_relaxed);
      if (index >= bands.size()) {
        return;
      }
      const DecodeBand& band = bands[index];
      const EtcDecodeJob& job = *band.job;
      DecodeEtcImageBlockRows(job.format, job.source, job.source_bytes,
                              job.width, job.height, band.first_block_row,
                              band.block_row_count, job.destination,
                              job.destination_bytes);
    }
  }
};

class DecodeWorkerPool {
 public:
  DecodeWorkerPool() {
    const unsigned hardware = std::max(1U, std::thread::hardware_concurrency());
    const unsigned limit = std::min(7U, hardware - 1);
    while (worker_count_ < limit) {
      if (pthread_create(&workers_[worker_count_], nullptr, Entry, this) != 0) {
        break;
      }
      ++worker_count_;
    }
  }

  ~DecodeWorkerPool() {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      stopping_ = true;
    }
    ready_.notify_all();
    for (unsigned index = 0; index < worker_count_; ++index) {
      pthread_join(workers_[index], nullptr);
    }
  }

  void Run(DecodeBandQueue* queue, unsigned workers) {
    const unsigned helpers = std::min(workers, worker_count_);
    if (helpers == 0) {
      queue->Run();
      return;
    }
    {
      std::lock_guard<std::mutex> lock(mutex_);
      queue->workers = helpers;
      for (unsigned index = 0; index < helpers; ++index) {
        pending_.push_back(queue);
      }
    }
    ready_.notify_all();
    queue->Run();
    std::unique_lock<std::mutex> lock(queue->mutex);
    queue->completed.wait(lock, [queue] { return queue->workers == 0; });
  }

 private:
  static void* Entry(void* context) {
    static_cast<DecodeWorkerPool*>(context)->RunWorker();
    return nullptr;
  }

  void RunWorker() {
    for (;;) {
      DecodeBandQueue* queue;
      {
        std::unique_lock<std::mutex> lock(mutex_);
        ready_.wait(lock, [this] { return stopping_ || !pending_.empty(); });
        if (pending_.empty()) {
          return;
        }
        queue = pending_.front();
        pending_.pop_front();
      }
      queue->Run();
      std::lock_guard<std::mutex> lock(queue->mutex);
      if (--queue->workers == 0) {
        queue->completed.notify_one();
      }
    }
  }

  std::mutex mutex_;
  std::condition_variable ready_;
  std::deque<DecodeBandQueue*> pending_;
  std::array<pthread_t, 7> workers_{};
  unsigned worker_count_ = 0;
  bool stopping_ = false;
};

}  // namespace

void DecodeEtcJobs(EtcDecodeJob* jobs, std::size_t count,
                   unsigned worker_count) {
  if (jobs == nullptr) {
    return;
  }
  DecodeBandQueue queue;
  std::vector<DecodeBand>& bands = queue.bands;
  std::uint64_t total_blocks = 0;
  for (std::size_t index = 0; index < count; ++index) {
    EtcDecodeJob& job = jobs[index];
    job.ok = ImageFits(job.format, job.source, job.source_bytes, job.width,
                       job.height, job.destination, job.destination_bytes);
    if (!job.ok) {
      continue;
    }
    const std::uint32_t blocks_wide =
        (static_cast<std::uint64_t>(job.width) + 3) / 4;
    const std::uint32_t blocks_high =
        (static_cast<std::uint64_t>(job.height) + 3) / 4;
    const std::uint32_t rows_per_band = static_cast<std::uint32_t>(
        std::max<std::uint64_t>(1, kBlocksPerBand / blocks_wide));
    for (std::uint32_t row = 0; row < blocks_high; row += rows_per_band) {
      bands.push_back(
          {&job, row, std::min(rows_per_band, blocks_high - row)});
    }
    total_blocks += static_cast<std::uint64_t>(blocks_wide) * blocks_high;
  }

  const std::size_t threads =
      total_blocks < kParallelMinimumBlocks
          ? 1
          : std::min<std::size_t>(std::max(worker_count, 1U), bands.size());
  if (threads <= 1) {
    queue.Run();
  } else {
    static DecodeWorkerPool pool;
    pool.Run(&queue, static_cast<unsigned>(threads - 1));
  }
}

bool DecodeEtcImageBlockRows(EtcFormat format, const std::uint8_t* source,
                             std::size_t source_bytes, std::uint32_t width,
                             std::uint32_t height,
                             std::uint32_t first_block_row,
                             std::uint32_t block_row_count,
                             std::uint8_t* destination,
                             std::size_t destination_bytes) {
  return mocktail_rust_decode_etc_image_block_rows(
             static_cast<MocktailRustEtcFormat>(format), source, source_bytes,
             width, height, first_block_row, block_row_count, destination,
             destination_bytes) == 1;
}

}  // namespace mocktail::graphics
