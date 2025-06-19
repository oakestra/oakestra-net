import time
import csv
import threading
import functools
import os
from typing import Callable
from contextlib import contextmanager

# Thread-local storage for timing traces
_thread_local = threading.local()

def _get_trace_data():
    """Get or initialize thread-local trace data."""
    if not hasattr(_thread_local, 'trace_start_time'):
        _thread_local.trace_start_time = None
        _thread_local.nesting_level = 0
    return _thread_local

class TimingLogger:
    """
    A thread-safe timing logger that records function entry/exit timestamps to CSV with timing traces.
    """
    
    def __init__(self, log_file: str = "/metrics/timing_log.csv", buffer_size: int = 100):
        self.log_file = log_file
        self.buffer_size = buffer_size
        self.buffer = []
        self.lock = threading.Lock()
        self._ensure_csv_headers()
    
    def _ensure_csv_headers(self):
        """Ensure CSV file has proper headers."""
        if not os.path.exists(self.log_file):
            with open(self.log_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'timestamp', 'function_name', 'event_type', 
                    'duration_ms', 'elapsed_ms', 'nesting_level'
                ])
    
    def _write_to_csv(self, entry: dict):
        """Thread-safe write to CSV buffer."""
        with self.lock:
            self.buffer.append(entry)
            if len(self.buffer) >= self.buffer_size:
                self._flush_buffer()
    
    def _flush_buffer(self):
        """Flush buffer to CSV file."""
        if not self.buffer:
            return
            
        with open(self.log_file, 'a', newline='') as f:
            writer = csv.writer(f)
            for entry in self.buffer:
                writer.writerow([
                    entry['timestamp'],
                    entry['function_name'],
                    entry['event_type'],
                    entry['duration_ms'],
                    entry['elapsed_ms'],
                    entry['nesting_level'],
                ])
        self.buffer.clear()
    
    def flush(self):
        """Manually flush buffer to file."""
        with self.lock:
            self._flush_buffer()
    
    def log_entry(self, func_name: str, args: tuple = (), kwargs: dict = None):
        """Log function entry with trace timing."""
        trace_data = _get_trace_data()
        current_time = time.time() * 1000
        
        # Initialize trace if this is the first timed function
        if trace_data.trace_start_time is None:
            trace_data.trace_start_time = current_time
            trace_elapsed_ms = 0.0
        else:
            trace_elapsed_ms = current_time - trace_data.trace_start_time
        
        entry = {
            'timestamp': current_time,
            'function_name': func_name,
            'event_type': 'ENTRY',
            'duration_ms': 0.0,  # Will be filled on exit
            'elapsed_ms': round(trace_elapsed_ms, 3),
            'nesting_level': trace_data.nesting_level,
        }
        self._write_to_csv(entry)
        
        # Increment nesting level
        trace_data.nesting_level += 1
    
    def log_exit(self, func_name: str, duration_ms: float, args: tuple = (), kwargs: dict = None):
        """Log function exit with duration and trace timing."""
        trace_data = _get_trace_data()
        current_time = time.time() * 1000
        
        # Decrement nesting level
        trace_data.nesting_level -= 1
        
        # Calculate trace elapsed time
        trace_elapsed_ms = current_time - trace_data.trace_start_time if trace_data.trace_start_time else 0.0
        
        entry = {
            'timestamp': current_time,
            'function_name': func_name,
            'event_type': 'EXIT',
            'duration_ms': round(duration_ms, 3),
            'elapsed_ms': round(trace_elapsed_ms, 3),
            'nesting_level': trace_data.nesting_level,
        }
        self._write_to_csv(entry)
        
        # Reset trace if we've exited all timed functions
        if trace_data.nesting_level == 0:
            trace_data.trace_start_time = None

# Global timing logger instance
timing_logger = TimingLogger()

def timed(log_args: bool = False, log_kwargs: bool = False):
    """
    Decorator to time function execution and log to CSV with timing traces.
    
    Args:
        log_args: Whether to log function arguments
        log_kwargs: Whether to log keyword arguments
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            func_name = f"{func.__module__}.{func.__qualname__}"
            
            # Log entry
            timing_logger.log_entry(func_name)
            
            # Execute function and measure time
            start_time = time.time() * 1000
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                end_time = time.time() * 1000
                duration_ms = end_time - start_time
                
                # Log exit
                timing_logger.log_exit(func_name, duration_ms)
        
        return wrapper
    return decorator

@contextmanager
def time_block(block_name: str):
    """
    Context manager to time code blocks with timing traces.
    
    Usage:
        with time_block("database_query"):
            # your code here
            pass
    """
    timing_logger.log_entry(block_name)
    start_time = time.perf_counter()
    try:
        yield
    finally:
        end_time = time.perf_counter()
        duration_ms = (end_time - start_time) * 1000
        timing_logger.log_exit(block_name, duration_ms)

def reset_trace():
    """Manually reset the current timing trace."""
    trace_data = _get_trace_data()
    trace_data.trace_start_time = None
    trace_data.nesting_level = 0

# Cleanup function to ensure buffer is flushed
import atexit
atexit.register(timing_logger.flush)