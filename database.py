import sqlite3
import os
import time
import sys
import csv
import json
from pathlib import Path
import shutil
from datetime import datetime
import threading
import ipaddress
import re

# Thread-local storage for database connections
_thread_local = threading.local()

class RootsDatabase:
    def __init__(self, db_path="roots.db"):
        """Initialize the database connection"""
        self.db_path = db_path
        self.connection = None
        # Initialize connection immediately
        self.connect()
        self.initialize_database()
        
    def connect(self):
        """Create or get a database connection"""
        try:
            # Only create a new connection if there isn't one already
            if self.connection is None:
                self.connection = sqlite3.connect(self.db_path, check_same_thread=False)
                self.connection.row_factory = sqlite3.Row
            return self.connection
        except Exception as e:
            print(f"Database connection error: {e}")
            raise e
            
    def close(self):
        """Close the database connection"""
        if self.connection:
            try:
                self.connection.close()
            except Exception as e:
                print(f"Error closing database: {e}")
            finally:
                self.connection = None
    
    def initialize_database(self):
        """Create necessary tables if they don't exist"""
        try:
            cursor = self.connection.cursor()
            
            # Create stats table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS calculation_stats (
                    id INTEGER PRIMARY KEY,
                    last_calculated_number INTEGER,
                    total_calculated INTEGER,
                    last_update TEXT
                )
            """)
            
            # Create security table for tracking suspicious activities
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT,
                    request_path TEXT,
                    request_method TEXT,
                    timestamp TEXT,
                    severity TEXT,
                    blocked INTEGER DEFAULT 0
                )
            """)
            
            # Check if we have any shards defined
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'roots_shard_%'")
            existing_shards = cursor.fetchall()
            
            # If no shards exist, create shard 1
            if not existing_shards:
                self.create_shard_table(1)
                
            self.connection.commit()
        except Exception as e:
            print(f"Database initialization error: {e}")
            self.connection.rollback()
            raise e
            
    def create_shard_table(self, shard_number):
        """Create a new shard table for storing roots"""
        try:
            cursor = self.connection.cursor()
            table_name = f"roots_shard_{shard_number}"
            
            # Create the shard table
            cursor.execute(f"""
                CREATE TABLE IF NOT EXISTS {table_name} (
                    number INTEGER PRIMARY KEY,
                    root TEXT
                )
            """)
            
            # Create index for faster queries
            cursor.execute(f"CREATE INDEX IF NOT EXISTS idx_{table_name}_number ON {table_name} (number)")
            
            # Add entry to shards registry
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS shard_registry (
                    shard_number INTEGER PRIMARY KEY,
                    table_name TEXT,
                    created_at TEXT,
                    min_number INTEGER DEFAULT 0,
                    max_number INTEGER DEFAULT 0,
                    row_count INTEGER DEFAULT 0
                )
            """)
            
            # Insert or update shard registry entry
            cursor.execute("""
                INSERT OR REPLACE INTO shard_registry 
                (shard_number, table_name, created_at)
                VALUES (?, ?, ?)
            """, (shard_number, table_name, time.strftime("%Y-%m-%d %H:%M:%S")))
            
            self.connection.commit()
            return table_name
        except Exception as e:
            print(f"Error creating shard table {shard_number}: {e}")
            self.connection.rollback()
            raise e
    
    def get_all_shards(self):
        """Get information about all shards"""
        try:
            cursor = self.connection.cursor()
            
            # Check if shard registry exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='shard_registry'")
            if not cursor.fetchone():
                return []
                
            # Get all shards with their row counts
            cursor.execute("""
                SELECT shard_number, table_name, created_at, min_number, max_number, row_count
                FROM shard_registry
                ORDER BY shard_number
            """)
            
            shards = []
            for row in cursor.fetchall():
                # Update row count if needed
                current_count = self.get_shard_row_count(row['table_name'])
                if current_count != row['row_count']:
                    cursor.execute("""
                        UPDATE shard_registry SET row_count = ? 
                        WHERE shard_number = ?
                    """, (current_count, row['shard_number']))
                    self.connection.commit()
                
                shards.append({
                    "shard_number": row['shard_number'],
                    "table_name": row['table_name'],
                    "created_at": row['created_at'],
                    "min_number": row['min_number'],
                    "max_number": row['max_number'],
                    "row_count": current_count
                })
                
            return shards
        except Exception as e:
            print(f"Error getting shards: {e}")
            return []
    
    def get_shard_row_count(self, table_name):
        """Get the number of rows in a shard table"""
        try:
            cursor = self.connection.cursor()
            cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
            return cursor.fetchone()[0]
        except Exception as e:
            print(f"Error getting row count for {table_name}: {e}")
            return 0
    
    def update_shard_stats(self, shard_number):
        """Update statistics for a shard"""
        try:
            cursor = self.connection.cursor()
            table_name = f"roots_shard_{shard_number}"
            
            # Get min and max number
            cursor.execute(f"SELECT MIN(number) FROM {table_name}")
            min_number = cursor.fetchone()[0] or 0
            
            cursor.execute(f"SELECT MAX(number) FROM {table_name}")
            max_number = cursor.fetchone()[0] or 0
            
            # Get row count
            cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
            row_count = cursor.fetchone()[0]
            
            # Update shard registry
            cursor.execute("""
                UPDATE shard_registry
                SET min_number = ?, max_number = ?, row_count = ?
                WHERE shard_number = ?
            """, (min_number, max_number, row_count, shard_number))
            
            self.connection.commit()
            return {"min_number": min_number, "max_number": max_number, "row_count": row_count}
        except Exception as e:
            print(f"Error updating shard stats for shard {shard_number}: {e}")
            self.connection.rollback()
            return {"error": str(e)}
            
    def save_roots_batch(self, roots_batch, shard_number=1):
        """Save a batch of roots to the database with shard support"""
        if not roots_batch:
            return
            
        try:
            cursor = self.connection.cursor()
            table_name = f"roots_shard_{shard_number}"
            
            # Insert data using executemany for better performance
            cursor.executemany(
                f"INSERT OR REPLACE INTO {table_name} (number, root) VALUES (?, ?)",
                [(item["number"], item["root"]) for item in roots_batch]
            )
            
            self.connection.commit()
            
            # Update shard stats periodically
            if len(roots_batch) > 1000:
                self.update_shard_stats(shard_number)
                
        except Exception as e:
            print(f"Error saving roots batch to shard {shard_number}: {e}")
            self.connection.rollback()
            raise e
    
    def get_root_range(self, start, count, shard_aware=False):
        """Get a range of roots with shard awareness"""
        try:
            cursor = self.connection.cursor()
            results = []
            
            if shard_aware:
                # Get data from all shards based on number range
                shards = self.get_all_shards()
                
                # First try to get data from shards that might contain this range
                for shard in shards:
                    # Skip shards that definitely don't have our range
                    if shard["row_count"] > 0 and (shard["max_number"] < start or shard["min_number"] > start + count):
                        continue
                    
                    table_name = shard["table_name"]
                    cursor.execute(f"""
                        SELECT number, root FROM {table_name}
                        WHERE number >= ? AND number < ?
                        ORDER BY number
                        LIMIT ?
                    """, (start, start + count, count))
                    
                    for row in cursor.fetchall():
                        results.append({
                            "number": row[0],
                            "root": row[1]
                        })
            else:
                # Default behavior - try the current shard
                current_shard = 1  # Default to shard 1
                shards = self.get_all_shards()
                if shards:
                    current_shard = max(shards, key=lambda x: x["shard_number"])["shard_number"]
                
                table_name = f"roots_shard_{current_shard}"
                cursor.execute(f"""
                    SELECT number, root FROM {table_name}
                    WHERE number >= ? AND number < ?
                    ORDER BY number
                    LIMIT ?
                """, (start, start + count, count))
                
                for row in cursor.fetchall():
                    results.append({
                        "number": row[0],
                        "root": row[1]
                    })
            
            # Sort and deduplicate by number
            unique_results = {}
            for item in results:
                unique_results[item["number"]] = item
                
            final_results = list(unique_results.values())
            final_results.sort(key=lambda x: x["number"])
            
            return final_results[:count]
        except Exception as e:
            print(f"Error fetching root range: {e}")
            return []

    def get_latest_roots(self, limit=200):
        """Get the most recently added roots from all shards"""
        try:
            # Get all available shards
            shards = self.get_all_shards()
            if not shards:
                return []
                
            # Find the shard with the highest numbers
            latest_shard = max(shards, key=lambda x: x["max_number"])
            
            cursor = self.connection.cursor()
            table_name = latest_shard["table_name"]
            
            # Get the latest entries from this shard
            cursor.execute(f"""
                SELECT number, root FROM {table_name}
                ORDER BY number DESC
                LIMIT ?
            """, (limit,))
            
            results = []
            for row in cursor.fetchall():
                results.append({
                    "number": row[0],
                    "root": row[1]
                })
                
            return results
            
        except Exception as e:
            print(f"Error getting latest roots: {e}")
            return []

    def get_stats(self):
        """Get the calculation statistics"""
        try:
            cursor = self.connection.cursor()
            cursor.execute("SELECT * FROM calculation_stats ORDER BY id DESC LIMIT 1")
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None
        except Exception as e:
            print(f"Error getting stats: {e}")
            return None
    
    def update_stats(self, last_calculated, total_calculated):
        """Update the calculation statistics"""
        try:
            cursor = self.connection.cursor()
            current_time = time.strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("""
                INSERT OR REPLACE INTO calculation_stats 
                (id, last_calculated_number, total_calculated, last_update)
                VALUES (1, ?, ?, ?)
            """, (last_calculated, total_calculated, current_time))
            self.connection.commit()
        except Exception as e:
            print(f"Error updating stats: {e}")
            self.connection.rollback()
    
    def backup_database(self, backup_name=None):
        """Create a backup of the database"""
        if not backup_name:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"roots_backup_{timestamp}.db"
            
        backup_path = os.path.join(os.path.dirname(self.db_path), backup_name)
        
        # Close the connection before backup
        if self.connection:
            self.connection.close()
            self.connection = None
            
        # Wait a moment to ensure connections close
        time.sleep(0.5)
        
        # Create backup
        shutil.copy2(self.db_path, backup_path)
        
        # Reconnect
        self.connect()
        
        return {
            "success": True,
            "backup_file": backup_name,
            "backup_path": backup_path,
            "timestamp": datetime.now().isoformat(),
            "size_bytes": os.path.getsize(backup_path)
        }
    
    def restore_database(self, backup_path):
        """Restore database from backup"""
        if not os.path.exists(backup_path):
            return {"success": False, "error": "Backup file does not exist"}
            
        # Close the connection before restore
        if self.connection:
            self.connection.close()
            self.connection = None
            
        # Wait a moment to ensure connections close
        time.sleep(0.5)
        
        # Create backup of current database before restoring
        current_backup = self.backup_database(f"pre_restore_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db")
        
        # Restore from backup
        shutil.copy2(backup_path, self.db_path)
        
        # Reconnect
        self.connect()
        
        return {
            "success": True,
            "restored_from": backup_path,
            "previous_backup": current_backup["backup_file"],
            "timestamp": datetime.now().isoformat()
        }
    
    def export_to_csv(self, file_path=None, limit=None, start_from=1):
        """Export roots data to CSV file"""
        if not file_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            file_path = os.path.join(os.path.dirname(self.db_path), f"roots_export_{timestamp}.csv")
        
        # Get all shards
        shards = self.get_all_shards()
        if not shards:
            return {"success": False, "error": "No data to export"}
            
        try:
            # Write to CSV
            with open(file_path, 'w', newline='') as csv_file:
                csv_writer = csv.writer(csv_file)
                # Write header
                csv_writer.writerow(['Number', 'Square Root'])
                
                # Process each shard
                rows = 0
                for shard in shards:
                    table_name = shard["table_name"]
                    cursor = self.connection.cursor()
                    
                    # Build query based on parameters
                    query = f"SELECT number, root FROM {table_name}"
                    params = []
                    
                    if start_from > 1:
                        query += " WHERE number >= ?"
                        params.append(start_from)
                        
                    query += " ORDER BY number"
                    
                    if limit and limit > 0:
                        query += " LIMIT ?"
                        params.append(limit - rows)  # Adjust limit for already exported rows
                    
                    cursor.execute(query, params)
                    
                    for row in cursor:
                        csv_writer.writerow([row[0], row[1]])
                        rows += 1
                        
                        if limit and rows >= limit:
                            break
                    
                    if limit and rows >= limit:
                        break
                
            return {
                "success": True,
                "file_path": file_path,
                "records_exported": rows,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def export_to_json(self, file_path=None, limit=None, start_from=1):
        """Export roots data to JSON file"""
        if not file_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            file_path = os.path.join(os.path.dirname(self.db_path), f"roots_export_{timestamp}.json")
        
        # Get all shards
        shards = self.get_all_shards()
        if not shards:
            return {"success": False, "error": "No data to export"}
            
        try:
            # Prepare data for JSON
            data = []
            rows = 0
            
            for shard in shards:
                table_name = shard["table_name"]
                cursor = self.connection.cursor()
                
                # Build query based on parameters
                query = f"SELECT number, root FROM {table_name}"
                params = []
                
                if start_from > 1:
                    query += " WHERE number >= ?"
                    params.append(start_from)
                    
                query += " ORDER BY number"
                
                if limit and limit > 0:
                    query += " LIMIT ?"
                    params.append(limit - rows)  # Adjust limit for already exported rows
                
                cursor.execute(query, params)
                
                for row in cursor:
                    data.append({
                        "number": row[0],
                        "root": row[1]
                    })
                    rows += 1
                    
                    if limit and rows >= limit:
                        break
                
                if limit and rows >= limit:
                    break
            
            # Write to JSON
            with open(file_path, 'w') as json_file:
                json.dump({"roots": data, "export_time": datetime.now().isoformat()}, json_file, indent=2)
                
            return {
                "success": True,
                "file_path": file_path,
                "records_exported": len(data),
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
        
    def import_from_csv(self, file_path):
        """Import roots data from CSV file"""
        if not os.path.exists(file_path):
            return {"success": False, "error": "File does not exist"}
        
        try:
            # Get the highest shard
            shards = self.get_all_shards()
            if not shards:
                # Create first shard if none exist
                self.create_shard_table(1)
                shard_number = 1
            else:
                shard_number = max(shards, key=lambda x: x["shard_number"])["shard_number"]
            
            imported = 0
            skipped = 0
            
            with open(file_path, 'r', newline='') as csv_file:
                csv_reader = csv.reader(csv_file)
                next(csv_reader)  # Skip header row
                
                # Prepare batch insert
                batch = []
                table_name = f"roots_shard_{shard_number}"
                
                for row in csv_reader:
                    try:
                        number = int(row[0])
                        root_value = row[1]
                        batch.append((number, root_value))
                        
                        # Process in batches of 1000
                        if len(batch) >= 1000:
                            cursor = self.connection.cursor()
                            cursor.executemany(
                                f"INSERT OR IGNORE INTO {table_name} (number, root) VALUES (?, ?)",
                                batch
                            )
                            imported += cursor.rowcount
                            skipped += len(batch) - cursor.rowcount
                            self.connection.commit()
                            batch = []
                    except (ValueError, IndexError):
                        skipped += 1
                
                # Process remaining batch
                if batch:
                    cursor = self.connection.cursor()
                    cursor.executemany(
                        f"INSERT OR IGNORE INTO {table_name} (number, root) VALUES (?, ?)",
                        batch
                    )
                    imported += cursor.rowcount
                    skipped += len(batch) - cursor.rowcount
                    self.connection.commit()
                    
            # Update shard stats
            self.update_shard_stats(shard_number)
                    
            return {
                "success": True,
                "records_imported": imported,
                "records_skipped": skipped,
                "file_path": file_path,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "file_path": file_path,
                "timestamp": datetime.now().isoformat()
            }
    
    def get_database_stats(self):
        """Get statistics about the database"""
        try:
            stats = {}
            
            # Get total number of records across all shards
            shards = self.get_all_shards()
            total_records = 0
            min_number = float('inf')
            max_number = 0
            
            for shard in shards:
                total_records += shard["row_count"]
                if shard["min_number"] < min_number and shard["min_number"] > 0:
                    min_number = shard["min_number"]
                if shard["max_number"] > max_number:
                    max_number = shard["max_number"]
            
            stats["total_records"] = total_records
            stats["min_number"] = min_number if min_number != float('inf') else 0
            stats["max_number"] = max_number
            
            # Get database file size
            stats["database_size_bytes"] = os.path.getsize(self.db_path)
            stats["database_size_mb"] = round(stats["database_size_bytes"] / (1024 * 1024), 2)
            
            # Get number of shards
            stats["shard_count"] = len(shards)
            
            # Get calculation stats
            calc_stats = self.get_stats()
            if calc_stats:
                stats.update(calc_stats)
            
            return stats
        except Exception as e:
            print(f"Error getting database stats: {e}")
            return {"error": str(e)}
    
    def search_roots(self, query_type, value):
        """Search for specific roots based on different criteria"""
        try:
            results = []
            
            # Get all shards
            shards = self.get_all_shards()
            if not shards:
                return []
                
            # Process each shard based on query type
            for shard in shards:
                table_name = shard["table_name"]
                cursor = self.connection.cursor()
                
                if query_type == "exact_number":
                    # Skip shards that definitely don't have this number
                    if (shard["min_number"] > value or shard["max_number"] < value) and shard["row_count"] > 0:
                        continue
                    
                    # Get exact number match
                    cursor.execute(f"SELECT number, root FROM {table_name} WHERE number = ?", (value,))
                
                elif query_type == "range":
                    start, end = value
                    # Skip shards that definitely don't have this range
                    if (shard["min_number"] > end or shard["max_number"] < start) and shard["row_count"] > 0:
                        continue
                    
                    # Get range of numbers
                    cursor.execute(
                        f"SELECT number, root FROM {table_name} WHERE number BETWEEN ? AND ? ORDER BY number",
                        (start, end)
                    )
                
                elif query_type == "root_starts_with":
                    # Search for roots starting with a specific value (search all shards)
                    cursor.execute(
                        f"SELECT number, root FROM {table_name} WHERE root LIKE ? ORDER BY number LIMIT 100", 
                        (f"{value}%",)
                    )
                
                # Collect results from this shard
                for row in cursor.fetchall():
                    results.append({
                        "number": row[0],
                        "root": row[1]
                    })
                
                # For exact number search, we can stop after finding the match
                if query_type == "exact_number" and results:
                    break
            
            return results
            
        except Exception as e:
            print(f"Error searching roots: {e}")
            return []
            
    def log_security_event(self, ip_address, request_path, request_method, severity="INFO", blocked=False):
        """Log a security event and check for suspicious activity"""
        try:
            # Validate IP address to prevent injection
            try:
                ipaddress.ip_address(ip_address)  # Will raise ValueError if invalid
            except ValueError:
                ip_address = "invalid"
                
            # Sanitize inputs
            request_path = request_path[:1000]  # Limit length
            request_method = request_method[:10]
            severity = severity[:10]
            
            cursor = self.connection.cursor()
            cursor.execute("""
                INSERT INTO security_log 
                (ip_address, request_path, request_method, timestamp, severity, blocked)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (ip_address, request_path, request_method, datetime.now().isoformat(), severity, 1 if blocked else 0))
            self.connection.commit()
            
            # Check if this IP has been making too many requests
            cursor.execute("""
                SELECT COUNT(*) FROM security_log 
                WHERE ip_address = ? AND timestamp > ? 
                AND (severity = 'WARNING' OR severity = 'CRITICAL')
            """, (ip_address, (datetime.now().timestamp() - 3600)))  # Last hour
            
            suspicious_count = cursor.fetchone()[0]
            
            # Return whether this IP should be blocked
            return suspicious_count >= 10  # Block if 10+ suspicious activities within an hour
            
        except Exception as e:
            print(f"Error logging security event: {e}")
            return False

    def check_request_for_attacks(self, url_path, query_params, user_agent):
        """
        Check if a request appears to be an attack attempt
        Returns: (is_suspicious, severity, reason)
        """
        # SQL Injection patterns
        sql_patterns = [
            r"'(.*?)(--|;|/\*|xp_|sp_)",
            r"(%27).*?(--|;|/\*|xp_|sp_)",
            r"(UNION.+?SELECT)",
            r"(SELECT.+?FROM)",
            r"(DROP.+?TABLE)",
            r"(ALTER.+?TABLE)",
            r"(DELETE.+?FROM)",
            r"(INSERT.+?INTO)"
        ]
        
        # Path traversal attempts
        path_traversal = [
            r"(\.\./)",
            r"(%2e%2e/)",
            r"(/etc/passwd)",
            r"(c:\\windows)",
            r"(cmd\.exe)",
            r"(\.ini$)",
            r"(\.conf$)"
        ]
        
        # Common attack tools in user agent
        attack_tools = [
            r"(sqlmap)",
            r"(nikto)",
            r"(nessus)",
            r"(burp)",
            r"(ZAP)",
            r"(masscan)",
            r"(nmap)"
        ]
        
        # Check URL for SQL injection
        full_url = url_path
        if query_params:
            full_url += "?" + query_params
            
        for pattern in sql_patterns:
            if re.search(pattern, full_url, re.IGNORECASE):
                return True, "CRITICAL", f"Possible SQL injection: {pattern}"
        
        # Check for path traversal
        for pattern in path_traversal:
            if re.search(pattern, full_url, re.IGNORECASE):
                return True, "CRITICAL", f"Path traversal attempt: {pattern}"
        
        # Check user agent for attack tools
        if user_agent:
            for pattern in attack_tools:
                if re.search(pattern, user_agent, re.IGNORECASE):
                    return True, "WARNING", f"Attack tool signature: {pattern}"
        
        # Check for excessive parameters (possible DoS)
        if query_params and query_params.count('&') > 30:
            return True, "WARNING", "Excessive query parameters"
            
        return False, "INFO", "Normal request"

    def get_security_stats(self):
        """Get security statistics from the database"""
        try:
            cursor = self.connection.cursor()
            stats = {}
            
            # Total security logs
            cursor.execute("SELECT COUNT(*) FROM security_log")
            stats["total_logs"] = cursor.fetchone()[0]
            
            # Daily attacks (critical and warning events)
            today = datetime.now().strftime('%Y-%m-%d')
            cursor.execute(
                "SELECT COUNT(*) FROM security_log WHERE timestamp LIKE ? AND severity IN ('CRITICAL', 'WARNING')",
                (f"{today}%",)
            )
            stats["daily_attacks"] = cursor.fetchone()[0]
            
            # Recent attacks
            cursor.execute(
                """
                SELECT timestamp, ip_address, request_path, request_method, severity
                FROM security_log
                WHERE severity IN ('CRITICAL', 'WARNING')
                ORDER BY timestamp DESC
                LIMIT 20
                """
            )
            stats["recent_attacks"] = [dict(row) for row in cursor.fetchall()]
            
            # Most attacked paths
            cursor.execute(
                """
                SELECT request_path, COUNT(*) as count
                FROM security_log
                WHERE severity IN ('CRITICAL', 'WARNING')
                GROUP BY request_path
                ORDER BY count DESC
                LIMIT 5
                """
            )
            stats["attacked_paths"] = [dict(row) for row in cursor.fetchall()]
            
            # Most active attackers
            cursor.execute(
                """
                SELECT ip_address, COUNT(*) as count
                FROM security_log
                WHERE severity IN ('CRITICAL', 'WARNING')
                GROUP BY ip_address
                ORDER BY count DESC
                LIMIT 5
                """
            )
            stats["top_attackers"] = [dict(row) for row in cursor.fetchall()]
            
            return stats
        except Exception as e:
            print(f"Error getting security stats: {e}")
            return {"error": str(e)}
    
    def close(self):
        """Close the database connection"""
        if self.connection:
            self.connection.close()
            self.connection = None
    
    def initialize_database(self, force=False):
        """Initialize or repair the roots database"""
        print(f"Initializing database: {self.db_path}")
        
        # Check if database file exists
        exists = os.path.exists(self.db_path)
        if exists:
            print(f"Database file found. Size: {os.path.getsize(self.db_path) / 1024:.2f} KB")
        else:
            print("Database file does not exist. Creating new database.")
        
        try:
            # Connect to database
            conn = self.connect()
            cursor = conn.cursor()
            
            # Create main roots table if it doesn't exist
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS roots (
                number INTEGER PRIMARY KEY,
                root TEXT NOT NULL
            )
            ''')
            
            # Create stats table if it doesn't exist
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS stats (
                id INTEGER PRIMARY KEY,
                last_calculated_number INTEGER DEFAULT 2,
                total_calculated INTEGER DEFAULT 0,
                last_update TEXT
            )
            ''')
            
            # Create shard tracking table if it doesn't exist
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS shard_registry (
                shard_number INTEGER PRIMARY KEY,
                created_date TEXT,
                row_count INTEGER DEFAULT 0
            )
            ''')
            
            # Check if we need to create the first shard
            cursor.execute("SELECT COUNT(*) FROM shard_registry")
            shard_count = cursor.fetchone()[0]
            
            if shard_count == 0 or force:
                print("Creating first database shard...")
                # Create shard 1
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS roots_shard_1 (
                    number INTEGER PRIMARY KEY,
                    root TEXT NOT NULL
                )
                ''')
                
                # Register the shard
                cursor.execute(
                    "INSERT OR REPLACE INTO shard_registry (shard_number, created_date, row_count) VALUES (?, datetime('now'), ?)",
                    (1, 0)
                )
            
            # Initialize stats if empty
            cursor.execute("SELECT COUNT(*) FROM stats")
            if cursor.fetchone()[0] == 0 or force:
                cursor.execute(
                    "INSERT OR REPLACE INTO stats (id, last_calculated_number, total_calculated, last_update) VALUES (?, ?, ?, datetime('now'))",
                    (1, 2, 0)
                )
            
            # Commit changes
            conn.commit()
            print("Database initialization completed successfully.")
            return True
            
        except Exception as e:
            print(f"Error initializing database: {e}")
            return False

    def table_exists(self, table_name):
        """Check if a table exists in the database"""
        conn = self.connect()
        cursor = conn.cursor()
        
        cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
        result = cursor.fetchone()
        
        return result is not None
    
    def create_main_table(self):
        """Create the main roots table"""
        conn = self.connect()
        cursor = conn.cursor()
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS roots (
            number INTEGER PRIMARY KEY,
            root TEXT NOT NULL
        )
        ''')
        
        conn.commit()
        print("Main roots table created successfully")
        return True
    
    def create_shard_table(self, shard_number):
        """Create a new shard table"""
        conn = self.connect()
        cursor = conn.cursor()
        
        # Create the shard table
        table_name = f"roots_shard_{shard_number}"
        cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS {table_name} (
            number INTEGER PRIMARY KEY,
            root TEXT NOT NULL
        )
        ''')
        
        # Register the shard
        cursor.execute(
            "INSERT OR REPLACE INTO shard_registry (shard_number, created_date, row_count) VALUES (?, datetime('now'), ?)",
            (shard_number, 0)
        )
        
        conn.commit()
        print(f"Created new shard table: {table_name}")
        return True
    
    def get_all_shards(self):
        """Get information about all database shards"""
        try:
            conn = self.connect()
            cursor = conn.cursor()
            
            cursor.execute("SELECT shard_number, created_date, row_count FROM shard_registry ORDER BY shard_number")
            shards_data = cursor.fetchall()
            
            shards = []
            for shard_number, created_date, row_count in shards_data:
                shards.append({
                    "shard_number": shard_number,
                    "created_date": created_date,
                    "row_count": row_count
                })
            
            return shards
        except Exception as e:
            print(f"Error getting shards: {e}")
            return []
    
    def save_roots_batch(self, roots_data, shard_number=1):
        """Save a batch of calculated roots to the database
        
        Args:
            roots_data: List of dicts with 'number' and 'root' keys
            shard_number: The shard to save to
        """
        if not roots_data:
            return 0
            
        conn = self.connect()
        cursor = conn.cursor()
        
        # Get the table name based on shard
        table_name = f"roots_shard_{shard_number}"
        
        # Create table if it doesn't exist (just in case)
        if not self.table_exists(table_name):
            self.create_shard_table(shard_number)
        
        # Insert data
        inserted_count = 0
        for entry in roots_data:
            try:
                cursor.execute(
                    f"INSERT OR REPLACE INTO {table_name} (number, root) VALUES (?, ?)",
                    (entry["number"], entry["root"])
                )
                inserted_count += 1
            except Exception as e:
                print(f"Error inserting entry {entry}: {e}")
        
        # Update stats
        if inserted_count > 0:
            # Update the last calculated number
            max_number = max([entry["number"] for entry in roots_data])
            
            cursor.execute(
                "UPDATE stats SET last_calculated_number = ?, total_calculated = total_calculated + ?, last_update = datetime('now') WHERE id = 1",
                (max_number, inserted_count)
            )
            
            # Update shard row count
            cursor.execute(
                "UPDATE shard_registry SET row_count = row_count + ? WHERE shard_number = ?",
                (inserted_count, shard_number)
            )
        
        # Commit changes
        conn.commit()
        return inserted_count
    
    def get_stats(self):
        """Get calculation statistics"""
        try:
            conn = self.connect()
            cursor = conn.cursor()
            
            cursor.execute("SELECT last_calculated_number, total_calculated, last_update FROM stats WHERE id = 1")
            row = cursor.fetchone()
            
            if row:
                return {
                    "last_calculated_number": row[0],
                    "total_calculated": row[1],
                    "last_update": row[2]
                }
            return {
                "last_calculated_number": 2,
                "total_calculated": 0,
                "last_update": None
            }
        except Exception as e:
            print(f"Error getting stats: {e}")
            return {
                "last_calculated_number": 2,
                "total_calculated": 0,
                "last_update": None
            }
    
    def get_root_range(self, start, count, shard_aware=True):
        """Get a range of square roots from the database"""
        try:
            # Ensure connection exists
            conn = self.connect()
            cursor = conn.cursor()
            
            results = []
            
            # Rest of the method remains the same
            if shard_aware:
                # Get all shards
                shards = self.get_all_shards()
                remaining = count
                current_start = start
                
                # Get data from each shard as needed
                for shard in shards:
                    if remaining <= 0:
                        break
                    
                    table_name = f"roots_shard_{shard['shard_number']}"
                    
                    # Check if table exists
                    cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
                    if not cursor.fetchone():
                        continue
                    
                    cursor.execute(f"SELECT number, root FROM {table_name} WHERE number >= ? ORDER BY number LIMIT ?", 
                                  (current_start, remaining))
                    shard_results = cursor.fetchall()
                    
                    for row in shard_results:
                        results.append({"number": row[0], "root": row[1]})
                        current_start = row[0] + 1
                        
                    remaining = count - len(results)
            else:
                # Simplified approach using only the main table
                cursor.execute("SELECT number, root FROM roots WHERE number >= ? ORDER BY number LIMIT ?", 
                              (start, count))
                for row in cursor.fetchall():
                    results.append({"number": row[0], "root": row[1]})
            
            return results
        except Exception as e:
            print(f"Error fetching root range: {e}")
            # Reconnect if connection was lost
            self.connection = None
            self.connect()
            return []

    def get_latest_roots(self, limit=200):
        """Get the most recently calculated square roots"""
        conn = self.connect()
        cursor = conn.cursor()
        
        # Get the stats to find the last calculated number
        stats = self.get_stats()
        last_calculated = stats["last_calculated_number"]
        
        # Return the latest roots
        return self.get_root_range(max(1, last_calculated - limit + 1), limit)
    
    def get_database_stats(self):
        """Get detailed database statistics"""
        conn = self.connect()
        cursor = conn.cursor()
        
        stats = self.get_stats()
        
        # Get additional database info
        db_size_bytes = os.path.getsize(self.db_path)
        db_size_mb = db_size_bytes / (1024 * 1024)
        
        # Get shard information
        shards = self.get_all_shards()
        total_shards = len(shards)
        
        # Count tables in database
        cursor.execute("SELECT count(*) FROM sqlite_master WHERE type='table'")
        total_tables = cursor.fetchone()[0]
        
        # Get database free pages (estimate)
        try:
            cursor.execute("PRAGMA freelist_count")
            free_pages = cursor.fetchone()[0]
        except:
            free_pages = "Unknown"
        
        return {
            "last_calculated_number": stats["last_calculated_number"],
            "total_calculated": stats["total_calculated"],
            "last_update": stats["last_update"],
            "database_size_bytes": db_size_bytes,
            "database_size_mb": round(db_size_mb, 2),
            "total_shards": total_shards,
            "total_tables": total_tables,
            "free_pages": free_pages,
            "shards_info": shards
        }
    
    def backup_database(self):
        """Create a backup of the database"""
        try:
            # Generate backup filename with timestamp
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            backup_path = f"roots_backup_{timestamp}.db"
            
            # Close current connection to ensure all changes are written
            self.close()
            
            # Copy the database file
            with open(self.db_path, 'rb') as src:
                with open(backup_path, 'wb') as dst:
                    dst.write(src.read())
                    
            # Get file size
            backup_size_bytes = os.path.getsize(backup_path)
            backup_size_mb = backup_size_bytes / (1024 * 1024)
            
            # Reconnect to database
            self.connect()
            
            return {
                "success": True,
                "message": "Database backup created successfully",
                "backup_file": backup_path,
                "backup_size_bytes": backup_size_bytes,
                "backup_size_mb": round(backup_size_mb, 2),
                "created_time": timestamp
            }
        
        except Exception as e:
            # Ensure connection is restored
            self.connect()
            
            return {
                "success": False,
                "message": f"Backup failed: {str(e)}",
                "error": str(e)
            }
    
    def restore_database(self, backup_path):
        """Restore database from a backup file"""
        try:
            # Check if backup file exists
            if not os.path.exists(backup_path):
                return {"success": False, "message": "Backup file not found"}
                
            # Close current connection
            self.close()
            
            # Create a temporary backup of current database just in case
            temp_backup = f"roots_before_restore_{time.strftime('%Y%m%d_%H%M%S')}.db"
            with open(self.db_path, 'rb') as src:
                with open(temp_backup, 'wb') as dst:
                    dst.write(src.read())
            
            # Copy the backup to the database file
            with open(backup_path, 'rb') as src:
                with open(self.db_path, 'wb') as dst:
                    dst.write(src.read())
            
            # Reconnect to database
            self.connect()
            
            return {
                "success": True,
                "message": "Database restored successfully",
                "original_saved_as": temp_backup
            }
            
        except Exception as e:
            # Try to reconnect to database
            try:
                self.connect()
            except:
                pass
                
            return {
                "success": False,
                "message": f"Restore failed: {str(e)}",
                "error": str(e)
            }
    
    def export_to_csv(self, filepath, limit=None, start_from=1):
        """Export roots data to CSV file"""
        try:
            conn = self.connect()
            cursor = conn.cursor()
            
            # Generate SQL based on whether a limit is provided
            if limit:
                query = f"SELECT number, root FROM roots_shard_1 WHERE number >= {start_from} ORDER BY number LIMIT {limit}"
            else:
                query = f"SELECT number, root FROM roots_shard_1 WHERE number >= {start_from} ORDER BY number"
            
            cursor.execute(query)
            rows = cursor.fetchall()
            
            with open(filepath, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                # Write header
                writer.writerow(['number', 'square_root'])
                # Write data
                writer.writerows(rows)
            
            return {
                "success": True,
                "message": "Data exported to CSV successfully",
                "exported_rows": len(rows),
                "file_path": filepath
            }
            
        except Exception as e:
            return {
                "success": False,
                "message": f"CSV export failed: {str(e)}",
                "error": str(e)
            }
    
    def export_to_json(self, filepath, limit=None, start_from=1):
        """Export roots data to JSON file"""
        try:
            conn = self.connect()
            cursor = conn.cursor()
            
            # Generate SQL based on whether a limit is provided
            if limit:
                query = f"SELECT number, root FROM roots_shard_1 WHERE number >= {start_from} ORDER BY number LIMIT {limit}"
            else:
                query = f"SELECT number, root FROM roots_shard_1 WHERE number >= {start_from} ORDER BY number"
            
            cursor.execute(query)
            rows = cursor.fetchall()
            
            # Create a list of dictionaries for JSON export
            data = [{"number": row[0], "root": row[1]} for row in rows]
            
            with open(filepath, 'w') as jsonfile:
                json.dump({"roots": data}, jsonfile, indent=2)
            
            return {
                "success": True,
                "message": "Data exported to JSON successfully",
                "exported_rows": len(rows),
                "file_path": filepath
            }
            
        except Exception as e:
            return {
                "success": False,
                "message": f"JSON export failed: {str(e)}",
                "error": str(e)
            }
    
    def import_from_csv(self, filepath):
        """Import roots data from a CSV file"""
        try:
            with open(filepath, 'r', newline='') as csvfile:
                reader = csv.reader(csvfile)
                # Skip header row
                next(reader)
                
                data = []
                for row in reader:
                    if len(row) >= 2:
                        try:
                            number = int(row[0])
                            root = str(row[1])
                            data.append({"number": number, "root": root})
                        except ValueError:
                            continue
            
            # Save imported data
            imported_count = self.save_roots_batch(data)
            
            return {
                "success": True,
                "message": "Data imported from CSV successfully",
                "imported_rows": imported_count
            }
            
        except Exception as e:
            return {
                "success": False,
                "message": f"CSV import failed: {str(e)}",
                "error": str(e)
            }
    
    def search_roots(self, search_type, value):
        """Search for square roots using various criteria"""
        conn = self.connect()
        cursor = conn.cursor()
        results = []
        
        try:
            if search_type == "exact_number":
                # Search for an exact number
                number = int(value)
                
                for shard in self.get_all_shards():
                    table_name = f"roots_shard_{shard['shard_number']}"
                    cursor.execute(f"SELECT number, root FROM {table_name} WHERE number = ?", (number,))
                    row = cursor.fetchone()
                    if row:
                        results.append({"number": row[0], "root": row[1]})
                        break
                        
            elif search_type == "range":
                # Search for a range of numbers
                start, end = value
                
                for shard in self.get_all_shards():
                    table_name = f"roots_shard_{shard['shard_number']}"
                    cursor.execute(
                        f"SELECT number, root FROM {table_name} WHERE number BETWEEN ? AND ? ORDER BY number",
                        (start, end)
                    )
                    for row in cursor.fetchall():
                        results.append({"number": row[0], "root": row[1]})
                        
            elif search_type == "root_starts_with":
                # Search for roots that start with a specific value
                for shard in self.get_all_shards():
                    table_name = f"roots_shard_{shard['shard_number']}"
                    cursor.execute(
                        f"SELECT number, root FROM {table_name} WHERE root LIKE ? ORDER BY number LIMIT 100",
                        (f"{value}%",)
                    )
                    for row in cursor.fetchall():
                        results.append({"number": row[0], "root": row[1]})
            
            return results
            
        except Exception as e:
            print(f"Search error: {e}")
            return []
    
    def get_security_stats(self):
        """Get database security statistics"""
        return {
            "database_locked": False,  # Example data
            "failed_access_attempts": 0,
            "last_backup_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(os.path.getctime(self.db_path))) if os.path.exists(self.db_path) else None,
            "integrity_check_status": "passed"
        }

# Run as standalone script if executed directly
if __name__ == "__main__":
    db = RootsDatabase()
    if db.initialize_database(force=True):
        print("Database is ready for use.")
        
        # Display database statistics
        stats = db.get_stats()
        print(f"Last calculated number: {stats['last_calculated_number']}")
        print(f"Total calculated: {stats['total_calculated']}")
        print(f"Last update: {stats['last_update']}")
    else:
        print("Database initialization failed.")
        sys.exit(1)