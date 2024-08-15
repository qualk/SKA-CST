## FIXME
import struct
import sys

import numpy as np
from numpy.typing import NDArray
from scapy.all import UDP, rdpcap
from tabulate import tabulate

capture_file = "pss.pcap"

class PulsarPacket:
   """Representation of a PSR-formatted packet."""
   packet_dest_map = {
      0: "Low PSS",
      1: "Mid PSS",
      2: "Low PST",
      3: "Mid PST"
   }

   def __init__(self, payload: bytes):
      # Convert bytes to a NumPy array
      data = np.frombuffer(payload, dtype=np.int8)

      # Metadata
      self._payload = payload
      self.n_sequence = np.frombuffer(payload[0:8], dtype=np.uint64)[0]
      self.timestamp_attoseconds = np.frombuffer(payload[8:16], dtype=np.uint64)[0]
      self.timestamp_seconds = np.frombuffer(payload[16:20], dtype=np.uint32)[0]
      self.channel_separation = np.frombuffer(payload[20:24], dtype=np.uint32)[0]
      self.first_channel_freq = np.frombuffer(payload[24:32], dtype=np.uint64)[0]
      self.scale1 = np.frombuffer(payload[32:36], dtype=np.float32)[0]
      self.scale2 = np.frombuffer(payload[36:40], dtype=np.float32)[0]
      self.scale3 = np.frombuffer(payload[40:44], dtype=np.float32)[0]
      self.scale4 = np.frombuffer(payload[44:48], dtype=np.float32)[0]
      self.n_first_channel = np.frombuffer(payload[48:52], dtype=np.uint32)[0]
      self.n_channels = np.frombuffer(payload[52:54], dtype=np.uint16)[0]
      self.valid_channels = np.frombuffer(payload[54:56], dtype=np.uint16)[0]
      self.n_time_samples = np.frombuffer(payload[56:58], dtype=np.uint16)[0]
      self.n_beam = np.frombuffer(payload[58:60], dtype=np.uint16)[0]
      self.magic_word = hex(np.frombuffer(payload[60:64], dtype=np.uint32)[0])
      self.packet_dest = self.packet_dest_map.get(data[64], "Unknown Destination")
      self.data_precision = data[65]
      self.n_power_samples_averaged = data[66]
      self.samples_per_weight = data[67]
      self.oversampling_ratio_numerator = data[68]
      self.oversampling_ratio_denominator = data[69]
      self.beamformer_ver = np.frombuffer(payload[70:72], dtype=np.uint16)[0]
      self.scan_id = np.frombuffer(payload[72:80], dtype=np.uint64)[0]
      self.offset1 = np.frombuffer(payload[80:84], dtype=np.float32)[0]
      self.offset2 = np.frombuffer(payload[84:88], dtype=np.float32)[0]
      self.offset3 = np.frombuffer(payload[88:92], dtype=np.float32)[0]
      self.offset4 = np.frombuffer(payload[92:96], dtype=np.float32)[0]

      metadata_offset = 96
      self._data_bytes = int(self.n_time_samples * 2 * self.n_channels * 2)
      weight_data_bytes = len(data) - metadata_offset - self._data_bytes
      self._data_offset = metadata_offset + weight_data_bytes

def extract_time_samples(self, payload: bytes):
   # Calculate the number of time samples (M) and frequency channels (N)
   M = self.n_time_samples
   N = self.n_channels

   # Initialize the complex sample array
   complex_samples = np.empty((N, M, 2), dtype=np.complex64)

   # Iterate over channels and polarizations
   for channel_idx in range(N):
      for pol_idx in range(2):  # Polarization A and B
         # Calculate the byte offset for this channel and polarization
         offset = (channel_idx * 4 * M) + (pol_idx * 2 * M)

         # Extract I and Q samples for this channel and polarization
         i_samples = np.frombuffer(payload[offset:offset+M*2], dtype=np.int8)
         q_samples = np.frombuffer(payload[offset+M*2:offset+2*M*2], dtype=np.int8)

         # Combine I and Q samples into a complex array
         complex_samples[channel_idx, :, pol_idx] = i_samples + 1j * q_samples

   # Zero-pad to an integer number of 128-bit words
   padding_bytes = 16 - np.mod(M * 2 * N + 1, 16)
   complex_samples = np.pad(complex_samples, ((0, 0), (0, 0), (0, padding_bytes // 2)))

   return complex_samples

def extract_udp_payloads(pcap_file):
   try:
      with open(pcap_file, "rb") as file:
         packets = rdpcap(file)
   except FileNotFoundError:
      print(f"Error: File '{pcap_file}' does not exist.")
      sys.exit(1)
   except PermissionError:
      print(f"Error: File '{pcap_file}' cannot be read due to insufficient permissions.")
      sys.exit(1)
   except Exception as e:
      print(f"Error reading pcap file: {e}")
      sys.exit(1)
      
   payloads = [
      bytes(packet[UDP].payload) for packet in packets if UDP in packet
   ]

   if not payloads:
      print("No UDP packets found")
      sys.exit(1)

   return payloads

payloads = extract_udp_payloads(capture_file)
for payload in payloads:
   packet = PulsarPacket(payload)
   complex_samples = packet.extract_time_samples(payload)

   # # Calculate the average power per channel
   # avg_power = packet.calculate_average_power(complex_samples)

   # # Print the average power per channel
   # print("Average power per channel:")
   # print(avg_power)
