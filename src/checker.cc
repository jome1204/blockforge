#include "internal.h"

#include <iomanip>

namespace blockforge {
namespace {

void add_issue(CheckReport &report, IssueSeverity severity, IssueCode code,
               uint64_t inode, uint64_t block, std::string path,
               std::string message, bool repairable) {
  report.issues.push_back({severity, code, inode, block, std::move(path),
                           std::move(message), repairable});
}

std::string json_escape(std::string_view value) {
  std::ostringstream output;
  output << '"';
  for (unsigned char character : value) {
    switch (character) {
    case '"': output << "\\\""; break;
    case '\\': output << "\\\\"; break;
    case '\b': output << "\\b"; break;
    case '\f': output << "\\f"; break;
    case '\n': output << "\\n"; break;
    case '\r': output << "\\r"; break;
    case '\t': output << "\\t"; break;
    default:
      if (character < 0x20)
        output << "\\u" << std::hex << std::setw(4)
               << std::setfill('0') << static_cast<unsigned>(character)
               << std::dec;
      else
        output << character;
    }
  }
  output << '"';
  return output.str();
}

std::string severity_name(IssueSeverity severity) {
  switch (severity) {
  case IssueSeverity::information: return "information";
  case IssueSeverity::warning: return "warning";
  case IssueSeverity::error: return "error";
  case IssueSeverity::fatal: return "fatal";
  }
  return "unknown";
}
} // namespace

bool CheckReport::clean() const {
  return std::none_of(
      issues.begin(), issues.end(), [](const ConsistencyIssue &issue) {
        return issue.severity == IssueSeverity::error ||
               issue.severity == IssueSeverity::fatal;
      });
}

ConsistencyChecker::ConsistencyChecker(Limits limits) : limits_(limits) {}

CheckReport ConsistencyChecker::check(const Filesystem &filesystem) const {
  CheckReport report;
  const auto &superblock = filesystem.superblock();
  const auto &inodes = filesystem.inodes();
  const auto &directories = filesystem.directories();
  const auto &allocator = filesystem.allocator();
  Error error;
  uint64_t raw_device_bytes = 0;
  if (!checked_multiply(superblock.block_count, superblock.block_size,
                        raw_device_bytes) ||
      !superblock.validate(raw_device_bytes, limits_, error)) {
    add_issue(report, IssueSeverity::fatal,
              IssueCode::superblock_invalid, 0, 0, {}, error.message, false);
    return report;
  }

  std::map<uint64_t, uint64_t> block_owner;
  std::map<uint64_t, uint64_t> observed_links;
  std::set<uint64_t> reachable;
  for (const auto &table : directories.all()) {
    ++report.directories_scanned;
    const Inode *directory_inode = inodes.get(table.first);
    if (!directory_inode ||
        directory_inode->type != InodeType::directory) {
      add_issue(report, IssueSeverity::error,
                IssueCode::missing_inode, table.first, 0, {},
                "directory table has no matching directory inode", false);
      continue;
    }
    std::set<std::string> names;
    for (const DirectoryEntry &entry : table.second) {
      if (entry.deleted)
        continue;
      observed_links[entry.inode]++;
      if (entry.name != "." && entry.name != "..")
        reachable.insert(entry.inode);
      Error entry_error;
      if (!entry.validate(limits_, entry_error)) {
        add_issue(report, IssueSeverity::error,
                  IssueCode::invalid_directory_entry, entry.inode, 0, {},
                  entry_error.message, true);
        continue;
      }
      std::string normalized = internal::normalize_name(entry.name);
      if (!names.insert(normalized).second)
        add_issue(report, IssueSeverity::error,
                  IssueCode::invalid_directory_entry, entry.inode, 0, {},
                  "directory contains duplicate active names", true);
      const Inode *target = inodes.get(entry.inode);
      if (!target)
        add_issue(report, IssueSeverity::error,
                  IssueCode::missing_inode, entry.inode, 0, entry.name,
                  "directory entry refers to missing inode", true);
      else if (target->type != entry.type)
        add_issue(report, IssueSeverity::error,
                  IssueCode::invalid_directory_entry, entry.inode, 0,
                  entry.name,
                  "directory entry type does not match inode", true);
    }
  }

  reachable.insert(superblock.root_inode);
  std::set<uint64_t> physically_referenced;
  for (const auto &item : inodes.all()) {
    ++report.inodes_scanned;
    const Inode &inode = item.second;
    switch (inode.type) {
    case InodeType::regular: ++report.files; break;
    case InodeType::directory: ++report.directories; break;
    case InodeType::symbolic_link: ++report.symlinks; break;
    default: break;
    }
    Error inode_error;
    if (!inode.validate(superblock, limits_, inode_error))
      add_issue(report, IssueSeverity::error,
                inode_error.code == ErrorCode::invalid_extent
                    ? IssueCode::extent_out_of_range
                    : IssueCode::size_mismatch,
                inode.identifier, 0, {}, inode_error.message, true);
    auto blocks = ExtentResolver(limits_).physical_blocks(
        inode, superblock, inode_error);
    if (inode_error) {
      add_issue(report, IssueSeverity::error,
                IssueCode::extent_out_of_range, inode.identifier, 0, {},
                inode_error.message, true);
    } else {
      for (uint64_t block : blocks) {
        ++report.blocks_referenced;
        if (!physically_referenced.insert(block).second) {
          uint64_t other = block_owner[block];
          add_issue(report, IssueSeverity::fatal,
                    IssueCode::duplicate_block, inode.identifier, block, {},
                    "physical block is owned by more than one inode; first "
                    "owner is " +
                        std::to_string(other),
                    false);
        } else {
          block_owner[block] = inode.identifier;
        }
        if (!allocator.is_allocated(block))
          add_issue(report, IssueSeverity::error,
                    IssueCode::block_bitmap_mismatch, inode.identifier,
                    block, {},
                    "inode references a block marked free", true);
      }
    }
    uint64_t observed = observed_links[inode.identifier];
    if (inode.type == InodeType::directory) {
      if (observed < 2)
        observed = 2;
    }
    if (inode.link_count != observed &&
        inode.identifier != superblock.root_inode)
      add_issue(report, IssueSeverity::warning,
                IssueCode::invalid_link_count, inode.identifier, 0, {},
                "stored link count " + std::to_string(inode.link_count) +
                    " differs from observed count " +
                    std::to_string(observed),
                true);
    if (inode.identifier != superblock.root_inode &&
        reachable.count(inode.identifier) == 0)
      add_issue(report, IssueSeverity::warning,
                IssueCode::orphan_inode, inode.identifier, 0, {},
                "inode is not reachable from a directory entry", true);
    if (inode.type == InodeType::symbolic_link) {
      Error path_error;
      if (!PathResolver(limits_).normalize(inode.symlink_target,
                                           path_error))
        add_issue(report, IssueSeverity::warning,
                  IssueCode::invalid_symlink, inode.identifier, 0, {},
                  "symbolic-link target is malformed", false);
    }
  }

  for (uint64_t block = 0; block < allocator.block_count(); ++block) {
    if (!allocator.is_allocated(block))
      continue;
    if (block == 0)
      continue;
    if (physically_referenced.count(block) == 0)
      add_issue(report, IssueSeverity::warning,
                IssueCode::unreferenced_block, 0, block, {},
                "allocated block is not referenced by an inode", true);
  }

  std::set<uint64_t> active_transactions;
  uint64_t previous_sequence = 0;
  for (const JournalRecord &record : filesystem.journal().records()) {
    ++report.journal_records_scanned;
    if (record.sequence <= previous_sequence)
      add_issue(report, IssueSeverity::error,
                IssueCode::journal_sequence, 0, 0, {},
                "journal sequence numbers are not increasing", false);
    previous_sequence = record.sequence;
    if (record.type == JournalType::begin) {
      if (!active_transactions.insert(record.transaction).second)
        add_issue(report, IssueSeverity::error,
                  IssueCode::journal_transaction, 0, 0, {},
                  "journal transaction begins more than once", false);
    } else if (record.type == JournalType::commit ||
               record.type == JournalType::rollback) {
      if (active_transactions.erase(record.transaction) == 0)
        add_issue(report, IssueSeverity::error,
                  IssueCode::journal_transaction, 0, 0, {},
                  "journal completion has no active transaction", false);
    } else if (record.type != JournalType::checkpoint &&
               active_transactions.count(record.transaction) == 0) {
      add_issue(report, IssueSeverity::error,
                IssueCode::journal_transaction, 0, 0, {},
                "journal mutation belongs to inactive transaction", false);
    }
  }
  for (uint64_t transaction : active_transactions)
    add_issue(report, IssueSeverity::warning,
              IssueCode::journal_transaction, 0, 0, {},
              "journal transaction " + std::to_string(transaction) +
                  " is incomplete",
              true);
  return report;
}

CheckReport ConsistencyChecker::analyze_image(const uint8_t *data,
                                               size_t size) const {
  Filesystem filesystem(limits_);
  MountOptions options;
  options.read_only = true;
  options.allow_dirty = true;
  options.replay_journal = false;
  Error error;
  if (!filesystem.mount(data, size, options, error)) {
    CheckReport report;
    add_issue(report, IssueSeverity::fatal,
              error.code == ErrorCode::checksum_mismatch
                  ? IssueCode::checksum_failure
                  : IssueCode::superblock_invalid,
              0, 0, {}, error.message, false);
    return report;
  }
  return check(filesystem);
}

std::string ConsistencyChecker::text(const CheckReport &report) {
  std::ostringstream output;
  output << "Filesystem consistency report\n"
         << "  inodes scanned: " << report.inodes_scanned << '\n'
         << "  directories scanned: " << report.directories_scanned << '\n'
         << "  blocks referenced: " << report.blocks_referenced << '\n'
         << "  journal records: " << report.journal_records_scanned << '\n'
         << "  files: " << report.files << '\n'
         << "  directories: " << report.directories << '\n'
         << "  symbolic links: " << report.symlinks << '\n'
         << "  status: " << (report.clean() ? "clean" : "errors") << '\n';
  for (const auto &issue : report.issues) {
    output << "  [" << severity_name(issue.severity) << "] "
           << issue_code_name(issue.code);
    if (issue.inode)
      output << " inode=" << issue.inode;
    if (issue.block)
      output << " block=" << issue.block;
    if (!issue.path.empty())
      output << " path=" << issue.path;
    output << ": " << issue.message;
    if (issue.repairable)
      output << " (repairable)";
    output << '\n';
  }
  return output.str();
}

std::string ConsistencyChecker::json(const CheckReport &report) {
  std::ostringstream output;
  output << "{\"clean\":" << (report.clean() ? "true" : "false")
         << ",\"inodes_scanned\":" << report.inodes_scanned
         << ",\"directories_scanned\":" << report.directories_scanned
         << ",\"blocks_referenced\":" << report.blocks_referenced
         << ",\"journal_records\":" << report.journal_records_scanned
         << ",\"files\":" << report.files
         << ",\"directories\":" << report.directories
         << ",\"symlinks\":" << report.symlinks << ",\"issues\":[";
  for (size_t index = 0; index < report.issues.size(); ++index) {
    if (index)
      output << ',';
    const auto &issue = report.issues[index];
    output << "{\"severity\":" << json_escape(severity_name(issue.severity))
           << ",\"code\":" << json_escape(issue_code_name(issue.code))
           << ",\"inode\":" << issue.inode
           << ",\"block\":" << issue.block
           << ",\"path\":" << json_escape(issue.path)
           << ",\"message\":" << json_escape(issue.message)
           << ",\"repairable\":"
           << (issue.repairable ? "true" : "false") << '}';
  }
  output << "]}";
  return output.str();
}

RepairPlanner::RepairPlanner(Limits limits) : limits_(limits) {}

std::vector<RepairAction>
RepairPlanner::plan(const Filesystem &filesystem,
                    const CheckReport &report) const {
  std::vector<RepairAction> actions;
  std::set<std::pair<RepairAction::Kind, uint64_t>> unique;
  for (const auto &issue : report.issues) {
    if (!issue.repairable)
      continue;
    RepairAction action;
    action.inode = issue.inode;
    action.block = issue.block;
    action.path = issue.path;
    action.explanation = issue.message;
    switch (issue.code) {
    case IssueCode::unreferenced_block:
      action.kind = RepairAction::Kind::release_block;
      break;
    case IssueCode::block_bitmap_mismatch:
      action.kind = RepairAction::Kind::reserve_block;
      break;
    case IssueCode::invalid_directory_entry:
    case IssueCode::missing_inode:
      action.kind = RepairAction::Kind::remove_directory_entry;
      break;
    case IssueCode::invalid_link_count: {
      action.kind = RepairAction::Kind::update_link_count;
      uint64_t observed = 0;
      for (const auto &directory : filesystem.directories().all())
        for (const auto &entry : directory.second)
          if (!entry.deleted && entry.inode == issue.inode)
            ++observed;
      action.value = observed;
      break;
    }
    case IssueCode::extent_out_of_range:
    case IssueCode::extent_overlap:
    case IssueCode::size_mismatch:
      action.kind = RepairAction::Kind::truncate_extent;
      break;
    case IssueCode::orphan_inode:
      action.kind = RepairAction::Kind::reconnect_inode;
      action.path = "/lost+found";
      break;
    case IssueCode::journal_transaction:
      action.kind = RepairAction::Kind::clear_journal;
      break;
    default:
      continue;
    }
    uint64_t identity = action.block ? action.block : action.inode;
    if (unique.insert({action.kind, identity}).second)
      actions.push_back(std::move(action));
    if (actions.size() >= limits_.max_directory_entries)
      break;
  }
  return actions;
}

std::string RepairPlanner::text(const std::vector<RepairAction> &actions) {
  std::ostringstream output;
  output << "Repair plan: " << actions.size() << " action(s)\n";
  for (const auto &action : actions) {
    output << "  ";
    switch (action.kind) {
    case RepairAction::Kind::release_block: output << "release block"; break;
    case RepairAction::Kind::reserve_block: output << "reserve block"; break;
    case RepairAction::Kind::remove_directory_entry:
      output << "remove directory entry";
      break;
    case RepairAction::Kind::update_link_count:
      output << "update link count to " << action.value;
      break;
    case RepairAction::Kind::truncate_extent:
      output << "truncate invalid extent";
      break;
    case RepairAction::Kind::reconnect_inode:
      output << "reconnect inode";
      break;
    case RepairAction::Kind::clear_journal: output << "clear journal"; break;
    }
    if (action.inode)
      output << " inode=" << action.inode;
    if (action.block)
      output << " block=" << action.block;
    if (!action.path.empty())
      output << " path=" << action.path;
    output << " - " << action.explanation << '\n';
  }
  return output.str();
}

} // namespace blockforge
