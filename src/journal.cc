#include "internal.h"

namespace blockforge {

Journal::Journal(Limits limits) : limits_(limits) {}

bool Journal::begin(Error &error) {
  error.clear();
  if (active())
    return internal::fail(error, ErrorCode::transaction_error,
                          active_transaction_,
                          "journal transaction is already active");
  if (records_.size() >= limits_.max_journal_records)
    return internal::fail(error, ErrorCode::resource_limit, records_.size(),
                          "journal record limit reached");
  active_transaction_ = next_transaction_++;
  records_.push_back({JournalType::begin, next_sequence_++,
                      active_transaction_, 0, 0, {}, 0});
  return true;
}

bool Journal::append(JournalType type, uint64_t target,
                     std::vector<uint8_t> payload, Error &error) {
  error.clear();
  if (!active())
    return internal::fail(error, ErrorCode::transaction_error, 0,
                          "journal mutation requires active transaction");
  if (type == JournalType::begin || type == JournalType::commit ||
      type == JournalType::rollback || type == JournalType::checkpoint)
    return internal::fail(error, ErrorCode::journal_error,
                          static_cast<uint16_t>(type),
                          "control record cannot be appended as mutation");
  if (records_.size() >= limits_.max_journal_records ||
      payload.size() > limits_.max_file_bytes)
    return internal::fail(error, ErrorCode::resource_limit, payload.size(),
                          "journal record exceeds limit");
  records_.push_back({type, next_sequence_++, active_transaction_, target, 0,
                      std::move(payload), 0});
  return true;
}

bool Journal::commit(Error &error) {
  error.clear();
  if (!active())
    return internal::fail(error, ErrorCode::transaction_error, 0,
                          "no active transaction to commit");
  if (records_.size() >= limits_.max_journal_records)
    return internal::fail(error, ErrorCode::resource_limit, records_.size(),
                          "journal record limit reached");
  records_.push_back({JournalType::commit, next_sequence_++,
                      active_transaction_, 0, 0, {}, 0});
  active_transaction_ = 0;
  return true;
}

bool Journal::rollback(Error &error) {
  error.clear();
  if (!active())
    return internal::fail(error, ErrorCode::transaction_error, 0,
                          "no active transaction to roll back");
  if (records_.size() >= limits_.max_journal_records)
    return internal::fail(error, ErrorCode::resource_limit, records_.size(),
                          "journal record limit reached");
  records_.push_back({JournalType::rollback, next_sequence_++,
                      active_transaction_, 0, 0, {}, 0});
  active_transaction_ = 0;
  return true;
}

bool Journal::checkpoint(Error &error) {
  error.clear();
  if (active())
    return internal::fail(error, ErrorCode::transaction_error,
                          active_transaction_,
                          "cannot checkpoint an active transaction");
  if (records_.size() >= limits_.max_journal_records)
    return internal::fail(error, ErrorCode::resource_limit, records_.size(),
                          "journal record limit reached");
  records_.push_back(
      {JournalType::checkpoint, next_sequence_++, 0, 0, 0, {}, 0});
  return true;
}

bool Journal::load(std::vector<JournalRecord> records, Error &error) {
  error.clear();
  if (records.size() > limits_.max_journal_records)
    return internal::fail(error, ErrorCode::resource_limit, records.size(),
                          "loaded journal exceeds record limit");
  uint64_t previous = 0;
  uint64_t active_transaction = 0;
  uint64_t maximum_transaction = 0;
  for (const JournalRecord &record : records) {
    if (record.sequence <= previous)
      return internal::fail(error, ErrorCode::journal_error,
                            record.sequence,
                            "journal sequence is not increasing");
    if (record.type == JournalType::begin) {
      if (active_transaction != 0 || record.transaction == 0)
        return internal::fail(error, ErrorCode::journal_error,
                              record.sequence,
                              "journal BEGIN is inconsistent");
      active_transaction = record.transaction;
    } else if (record.type == JournalType::commit ||
               record.type == JournalType::rollback) {
      if (active_transaction == 0 ||
          record.transaction != active_transaction)
        return internal::fail(error, ErrorCode::journal_error,
                              record.sequence,
                              "journal completion has no matching BEGIN");
      active_transaction = 0;
    } else if (record.type != JournalType::checkpoint &&
               record.transaction != active_transaction) {
      return internal::fail(error, ErrorCode::journal_error,
                            record.sequence,
                            "journal mutation transaction is inconsistent");
    }
    previous = record.sequence;
    maximum_transaction =
        std::max(maximum_transaction, record.transaction);
  }
  records_ = std::move(records);
  next_sequence_ = previous + 1;
  next_transaction_ = maximum_transaction + 1;
  active_transaction_ = active_transaction;
  return true;
}

void Journal::clear() {
  records_.clear();
  active_transaction_ = 0;
}

} // namespace blockforge
