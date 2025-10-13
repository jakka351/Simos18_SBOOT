#!/usr/bin/env python3
"""
seed_key_bruteforce.py - Python wrapper for twister with enhanced features
"""
import subprocess
import sys
import time
from datetime import datetime, timedelta
import argparse

class SeedKeyBruteforcer:
    def __init__(self, twister_path='./twister'):
        self.twister_path = twister_path
        self.start_time = None
        self.last_seed_checked = None
        
    def estimate_remaining_time(self, current_seed, start_seed, target_seed=None):
        """Estimate remaining time based on progress"""
        if not self.start_time or not self.last_seed_checked:
            return None
            
        elapsed = time.time() - self.start_time
        seeds_checked = current_seed - start_seed
        
        if seeds_checked == 0:
            return None
            
        rate = seeds_checked / elapsed
        
        if target_seed:
            remaining_seeds = target_seed - current_seed
            remaining_time = remaining_seeds / rate
            return timedelta(seconds=int(remaining_time))
        
        return rate
    
    def bruteforce_with_ranges(self, seed_first_bytes, start_seed=0x01D00000, 
                               max_seed=0x02000000, chunk_size=0x100000):
        """
        Bruteforce in chunks with progress reporting
        
        Args:
            seed_first_bytes: First 4 bytes of seed as hex string
            start_seed: Starting seed value
            max_seed: Maximum seed value to check
            chunk_size: Size of each chunk to process
        """
        self.start_time = time.time()
        current_seed = start_seed
        
        print(f"Starting bruteforce for seed: {seed_first_bytes}")
        print(f"Range: 0x{start_seed:08X} to 0x{max_seed:08X}")
        print(f"Chunk size: 0x{chunk_size:X}")
        print("-" * 60)
        
        while current_seed < max_seed:
            chunk_end = min(current_seed + chunk_size, max_seed)
            
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Checking range: "
                  f"0x{current_seed:08X} - 0x{chunk_end:08X}")
            
            try:
                result = subprocess.run(
                    [self.twister_path, f"{current_seed:08X}", seed_first_bytes, "1"],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                if "**** FOUND ****" in result.stdout:
                    print("\n" + "=" * 60)
                    print("SUCCESS! Seed/Key pair found!")
                    print("=" * 60)
                    print(result.stdout)
                    return True
                    
            except subprocess.TimeoutExpired:
                print(f"  Warning: Chunk timed out, moving to next range")
            except Exception as e:
                print(f"  Error: {e}")
            
            current_seed = chunk_end
            
            rate = self.estimate_remaining_time(current_seed, start_seed, max_seed)
            if rate and isinstance(rate, timedelta):
                print(f"  Estimated time remaining: {rate}")
            elif rate:
                print(f"  Current rate: {rate:.0f} seeds/sec")
        
        print("\nSeed not found in specified range")
        return False

    def adaptive_search(self, seed_first_bytes, initial_seed=0x01D00000, 
                       step_sizes=[0x10000, 0x100000, 0x1000000]):
        """
        Adaptive search starting narrow then expanding
        """
        for step in step_sizes:
            print(f"\nTrying step size: 0x{step:X}")
            start = max(0, initial_seed - step)
            end = min(0xFFFFFFFF, initial_seed + step)
            
            if self.bruteforce_with_ranges(seed_first_bytes, start, end, step // 4):
                return True
        
        return False


def main():
    parser = argparse.ArgumentParser(description='Enhanced Seed/Key bruteforcer')
    parser.add_argument('seed_bytes', help='First 4 bytes of seed (hex)')
    parser.add_argument('--start', default='01D00000', 
                       help='Starting seed value (hex)')
    parser.add_argument('--end', default='02000000',
                       help='Ending seed value (hex)')
    parser.add_argument('--twister', default='./twister',
                       help='Path to twister binary')
    parser.add_argument('--adaptive', action='store_true',
                       help='Use adaptive search strategy')
    
    args = parser.parse_args()
    
    bruteforcer = SeedKeyBruteforcer(args.twister)
    
    start_seed = int(args.start, 16)
    end_seed = int(args.end, 16)
    
    if args.adaptive:
        bruteforcer.adaptive_search(args.seed_bytes, start_seed)
    else:
        bruteforcer.bruteforce_with_ranges(args.seed_bytes, start_seed, end_seed)


if __name__ == '__main__':
    main()
