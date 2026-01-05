# Imports
import os
import sqlite3
import threading
import time

# Local imports
import logger
import paths
import fileops

# Thread-local storage for connections
_thread_local = threading.local()

# Database class for managing SQLite connections
class Database:

    # Constructor
    def __init__(self, db_path, timeout = 30.0):
        self.db_path = db_path
        self.timeout = timeout
        self._lock = threading.Lock()

    # Context manager enter
    def __enter__(self):
        self.open()
        return self

    # Context manager exit
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    # Open database connection
    def open(self):
        if not hasattr(_thread_local, 'connections'):
            _thread_local.connections = {}
        if self.db_path not in _thread_local.connections:

            # Ensure parent directory exists
            parent_dir = paths.get_filename_directory(self.db_path)
            if parent_dir and not paths.does_path_exist(parent_dir):
                fileops.make_directory(src = parent_dir)
            conn = sqlite3.connect(self.db_path, timeout = self.timeout, check_same_thread = False)
            conn.row_factory = sqlite3.Row

            # Enable WAL mode for better concurrent access
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            _thread_local.connections[self.db_path] = conn
        return _thread_local.connections[self.db_path]

    # Close database connection
    def close(self):
        if hasattr(_thread_local, 'connections') and self.db_path in _thread_local.connections:
            _thread_local.connections[self.db_path].close()
            del _thread_local.connections[self.db_path]

    # Get connection for current thread
    def get_connection(self):
        if hasattr(_thread_local, 'connections') and self.db_path in _thread_local.connections:
            return _thread_local.connections[self.db_path]
        return self.open()

    # Execute a query
    def execute(self, query, params = None):
        conn = self.get_connection()
        cursor = conn.cursor()
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        return cursor

    # Execute many queries
    def execute_many(self, query, params_list):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.executemany(query, params_list)
        return cursor

    # Commit transaction
    def commit(self):
        conn = self.get_connection()
        conn.commit()

    # Rollback transaction
    def rollback(self):
        conn = self.get_connection()
        conn.rollback()

    # Fetch one row
    def fetch_one(self, query, params = None):
        cursor = self.execute(query, params)
        return cursor.fetchone()

    # Fetch all rows
    def fetch_all(self, query, params = None):
        cursor = self.execute(query, params)
        return cursor.fetchall()

    # Check if table exists
    def table_exists(self, table_name):
        result = self.fetch_one(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (table_name,))
        return result is not None

    # Create table if not exists
    def create_table(self, table_name, columns, primary_key = None):
        column_defs = []
        for col_name, col_type in columns.items():
            col_def = "%s %s" % (col_name, col_type)
            if primary_key and col_name == primary_key:
                col_def += " PRIMARY KEY"
            column_defs.append(col_def)
        query = "CREATE TABLE IF NOT EXISTS %s (%s)" % (table_name, ", ".join(column_defs))
        self.execute(query)
        self.commit()

    # Create index if not exists
    def create_index(self, index_name, table_name, columns, unique = False):
        unique_str = "UNIQUE " if unique else ""
        columns_str = ", ".join(columns) if isinstance(columns, list) else columns
        query = "CREATE %sINDEX IF NOT EXISTS %s ON %s (%s)" % (unique_str, index_name, table_name, columns_str)
        self.execute(query)
        self.commit()

    # Insert row
    def insert(self, table_name, data, or_replace = False):
        columns = ", ".join(data.keys())
        placeholders = ", ".join(["?" for _ in data])
        action = "INSERT OR REPLACE" if or_replace else "INSERT"
        query = "%s INTO %s (%s) VALUES (%s)" % (action, table_name, columns, placeholders)
        self.execute(query, tuple(data.values()))

    # Insert many rows
    def insert_many(self, table_name, columns, rows, or_replace = False):
        if not rows:
            return
        columns_str = ", ".join(columns)
        placeholders = ", ".join(["?" for _ in columns])
        action = "INSERT OR REPLACE" if or_replace else "INSERT"
        query = "%s INTO %s (%s) VALUES (%s)" % (action, table_name, columns_str, placeholders)
        self.execute_many(query, rows)

    # Update row
    def update(self, table_name, data, where_clause, where_params = None):
        set_clause = ", ".join(["%s = ?" % k for k in data.keys()])
        query = "UPDATE %s SET %s WHERE %s" % (table_name, set_clause, where_clause)
        params = list(data.values())
        if where_params:
            params.extend(where_params)
        self.execute(query, tuple(params))

    # Delete rows
    def delete(self, table_name, where_clause = None, where_params = None):
        if where_clause:
            query = "DELETE FROM %s WHERE %s" % (table_name, where_clause)
            self.execute(query, where_params)
        else:
            query = "DELETE FROM %s" % table_name
            self.execute(query)

    # Select rows
    def select(self, table_name, columns = "*", where_clause = None, where_params = None, order_by = None, limit = None):
        columns_str = ", ".join(columns) if isinstance(columns, list) else columns
        query = "SELECT %s FROM %s" % (columns_str, table_name)
        if where_clause:
            query += " WHERE %s" % where_clause
        if order_by:
            query += " ORDER BY %s" % order_by
        if limit:
            query += " LIMIT %d" % limit
        return self.fetch_all(query, where_params)

    # Count rows
    def count(self, table_name, where_clause = None, where_params = None):
        query = "SELECT COUNT(*) FROM %s" % table_name
        if where_clause:
            query += " WHERE %s" % where_clause
        result = self.fetch_one(query, where_params)
        return result[0] if result else 0

# Hash database class for file hash storage
class HashDatabase(Database):
    TABLE_NAME = "file_hashes"
    COLUMNS = {
        "file_path": "TEXT PRIMARY KEY",
        "hash": "TEXT NOT NULL",
        "size": "INTEGER",
        "mtime": "REAL",
        "updated_at": "REAL"
    }

    # Constructor
    def __init__(self, db_path, timeout = 30.0):
        super().__init__(db_path, timeout)

    # Initialize the hash table
    def initialize(self):
        self.create_table(self.TABLE_NAME, self.COLUMNS)
        self.create_index("idx_file_path_prefix", self.TABLE_NAME, "file_path")
        self.commit()

    # Set file hash
    def set_hash(self, file_path, hash_value, size = None, mtime = None):
        data = {
            "file_path": file_path,
            "hash": hash_value,
            "size": size,
            "mtime": mtime,
            "updated_at": time.time()
        }
        self.insert(self.TABLE_NAME, data, or_replace = True)

    # Set multiple file hashes (batch insert)
    def set_hashes(self, hash_entries):
        if not hash_entries:
            return
        columns = ["file_path", "hash", "size", "mtime", "updated_at"]
        now = time.time()
        rows = []
        for entry in hash_entries:
            rows.append((
                entry.get("file_path"),
                entry.get("hash"),
                entry.get("size"),
                entry.get("mtime"),
                now
            ))
        self.insert_many(self.TABLE_NAME, columns, rows, or_replace = True)
        self.commit()

    # Get file hash
    def get_hash(self, file_path):
        result = self.fetch_one(
            "SELECT * FROM %s WHERE file_path = ?" % self.TABLE_NAME,
            (file_path,))
        if result:
            return dict(result)
        return None

    # Get hashes by path prefix
    def get_hashes_by_prefix(self, prefix):
        results = self.fetch_all(
            "SELECT * FROM %s WHERE file_path LIKE ?" % self.TABLE_NAME,
            (prefix + "%",))
        return [dict(row) for row in results]

    # Get all hashes
    def get_all_hashes(self):
        results = self.fetch_all("SELECT * FROM %s" % self.TABLE_NAME)
        return [dict(row) for row in results]

    # Delete hash
    def delete_hash(self, file_path):
        self.delete(self.TABLE_NAME, "file_path = ?", (file_path,))

    # Delete hashes by prefix
    def delete_hashes_by_prefix(self, prefix):
        self.delete(self.TABLE_NAME, "file_path LIKE ?", (prefix + "%",))

    # Clear all hashes
    def clear_all(self):
        self.delete(self.TABLE_NAME)
        self.commit()

    # Check if file hash exists
    def has_hash(self, file_path):
        return self.get_hash(file_path) is not None

    # Get hash count
    def get_count(self):
        return self.count(self.TABLE_NAME)

    # Get hash count by prefix
    def get_count_by_prefix(self, prefix):
        return self.count(self.TABLE_NAME, "file_path LIKE ?", (prefix + "%",))

    # Export to dictionary (for compatibility)
    def export_to_dict(self, prefix = None):
        if prefix:
            entries = self.get_hashes_by_prefix(prefix)
        else:
            entries = self.get_all_hashes()
        result = {}
        for entry in entries:
            result[entry["file_path"]] = {
                "hash": entry["hash"],
                "size": entry["size"],
                "mtime": entry["mtime"]
            }
        return result

    # Import from dictionary (for migration)
    def import_from_dict(self, hash_dict):
        entries = []
        for file_path, data in hash_dict.items():
            entries.append({
                "file_path": file_path,
                "hash": data.get("hash"),
                "size": data.get("size"),
                "mtime": data.get("mtime")
            })
        self.set_hashes(entries)
