import sys
from typing import List, Tuple

import numpy as np
from numpy.typing import NDArray
from scapy.all import UDP, rdpcap

capture_file = "pss-5beam.pcap"

class PulsarPacket:
   """Represents a PSR-formatted packet."""

   packet_dest_map = {
      0: "Low PSS",
      1: "Mid PSS",
      2: "Low PST",
      3: "Mid PST"
   }

   def __init__(self, payload: bytes):
      self._payload = payload
      self._data = np.frombuffer(payload, dtype=np.int8)
      
      self.METADATA_OFFSET = 96
      self._parse_metadata()

   def _parse_metadata(self) -> None:
      """Extract metadata from the payload."""
      self.n_sequence = np.frombuffer(self._payload[0:8], dtype=np.uint64)[0]
      self.timestamp_attoseconds = np.frombuffer(self._payload[8:16], dtype=np.uint64)[0]
      self.timestamp_seconds = np.frombuffer(self._payload[16:20], dtype=np.uint32)[0]
      self.channel_separation = np.frombuffer(self._payload[20:24], dtype=np.uint32)[0]
      self.first_channel_freq = np.frombuffer(self._payload[24:32], dtype=np.uint64)[0]
      self.scale1 = np.frombuffer(self._payload[32:36], dtype=np.float32)[0]
      self.scale2 = np.frombuffer(self._payload[36:40], dtype=np.float32)[0]
      self.scale3 = np.frombuffer(self._payload[40:44], dtype=np.float32)[0]
      self.scale4 = np.frombuffer(self._payload[44:48], dtype=np.float32)[0]
      self.n_first_channel = np.frombuffer(self._payload[48:52], dtype=np.uint32)[0]
      self.n_channels = np.frombuffer(self._payload[52:54], dtype=np.uint16)[0]
      self.valid_channels = np.frombuffer(self._payload[54:56], dtype=np.uint16)[0]
      self.n_time_samples = np.frombuffer(self._payload[56:58], dtype=np.uint16)[0]
      self.n_beam = np.frombuffer(self._payload[58:60], dtype=np.uint16)[0]
      self.magic_word = hex(np.frombuffer(self._payload[60:64], dtype=np.uint32)[0])
      self.packet_dest = self.packet_dest_map.get(self._data[64], "Unknown Destination")
      self.data_precision = self._data[65]
      self.n_power_samples_averaged = self._data[66]
      self.samples_per_weight = self._data[67]
      self.oversampling_ratio_numerator = self._data[68]
      self.oversampling_ratio_denominator = self._data[69]
      self.beamformer_ver = np.frombuffer(self._payload[70:72], dtype=np.uint16)[0]
      self.scan_id = np.frombuffer(self._payload[72:80], dtype=np.uint64)[0]
      self.offset1 = np.frombuffer(self._payload[80:84], dtype=np.float32)[0]
      self.offset2 = np.frombuffer(self._payload[84:88], dtype=np.float32)[0]
      self.offset3 = np.frombuffer(self._payload[88:92], dtype=np.float32)[0]
      self.offset4 = np.frombuffer(self._payload[92:96], dtype=np.float32)[0]
      
      # Calculate the offset where the data starts
      self._data_bytes = int(self.n_time_samples * 2 * self.n_channels * 2)
      weight_data_bytes = len(self._data) - self.METADATA_OFFSET - self._data_bytes
      self._data_offset = self.METADATA_OFFSET + weight_data_bytes

   @property
   def data(self) -> NDArray[np.int8]:
      """Returns the raw data array."""
      return np.frombuffer(self._payload[self._data_offset:], dtype=np.int8)

def extract_udp_payloads(pcap_file: str) -> List[bytes]:
   """Extracts UDP payloads from a PCAP file."""
   try:
      packets = rdpcap(pcap_file)
   except FileNotFoundError:
      print(f"Error: File '{pcap_file}' does not exist.")
      sys.exit(1)
   except PermissionError:
      print(f"Error: File '{pcap_file}' cannot be read due to insufficient permissions.")
      sys.exit(1)
   except Exception as e:
      print(f"Error reading '{pcap_file}': {e}")
      sys.exit(1)

   payloads = [bytes(packet[UDP].payload) for packet in packets if UDP in packet]

   if not payloads:
      print("No UDP packets found")
      sys.exit(1)

   return payloads

def extract_time_samples(packet: PulsarPacket) -> NDArray[np.complex64]:
   """Extracts time sample data from a Pulsar packet."""
   n_time_samples = packet.n_time_samples
   n_channels = packet.n_channels

   time_samples = np.zeros((n_time_samples, n_channels, 2), dtype=np.complex64)

   payload = packet.data
   
   for channel in range(n_channels):
      for polarisation in range(2):  # 0 for A, 1 for B
         start_index = (channel * 2 * n_time_samples + polarisation * n_time_samples) * 2
         end_index = start_index + n_time_samples * 2

         I_bytes = payload[start_index:end_index:2]
         Q_bytes = payload[start_index + 1:end_index:2]

         time_samples[:, channel, polarisation] = I_bytes + 1j * Q_bytes

   return time_samples

def calculate_statistics(time_samples: NDArray[np.complex64]) -> Tuple[NDArray[np.float64], NDArray[np.float64], NDArray[np.float64]]:
   """Calculates min, max, and standard deviation for each frequency channel."""
   min_values = np.min(time_samples, axis=0)
   max_values = np.max(time_samples, axis=0)
   std_devs = np.std(time_samples, axis=0)
   
   # Aggregate results across polarisation
   min_values = np.min(min_values, axis=1)
   max_values = np.max(max_values, axis=1)
   std_devs = np.mean(std_devs, axis=1)
   
   return min_values, max_values, std_devs

def print_packet_statistics(packet: PulsarPacket) -> None:
   """Prints the min, max, and standard deviation for each channel in a packet."""
   min_values, max_values, std_devs = calculate_statistics(extract_time_samples(packet))
   
   print(f"Results for Packet {packet.n_sequence + 1}:")
   for channel in range(packet.n_channels):
      print(f"  ├─ Channel {channel + 1}:")
      print(f"  │   ├─ Min Value: {min_values[channel]}")
      print(f"  │   ├─ Max Value: {max_values[channel]}")
      print(f"  │   └─ Standard Deviation: {std_devs[channel]}")
      print("  │")
   print()

# Extract UDP payloads from the capture file and process each one
payloads = extract_udp_payloads(capture_file)
for payload in payloads:
   packet = PulsarPacket(payload)
   print_packet_statistics(packet)
