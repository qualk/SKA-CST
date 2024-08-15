import sys
from typing import List, Tuple

import matplotlib.pyplot as plt
import numpy as np
from numpy.typing import NDArray
from scapy.all import UDP, rdpcap

sys.stdout.reconfigure(encoding='utf-8') # Set UTF-8 encoding for stdout, because NT is dumb

capture_file = "pss-5beam.pcap"

class PulsarPacket:
   """Represents a PSR-formatted packet with metadata extraction and data parsing."""

   # Mapping of packet destinations
   packet_dest_map = {
      0: "Low PSS",
      1: "Mid PSS",
      2: "Low PST",
      3: "Mid PST"
   }

   def __init__(self, payload: bytes):
      self._payload = payload
      self._data = np.frombuffer(payload, dtype=np.int8)
      self._parse_metadata()

   def _parse_metadata(self) -> None:
      """Extract metadata from the payload."""
      # Use numpy to read and parse metadata fields
      self.n_sequence = np.frombuffer(self._payload[0:8], dtype=np.uint64)[0]
      self.timestamp_attoseconds = np.frombuffer(self._payload[8:16], dtype=np.uint64)[0]
      self.timestamp_seconds = np.frombuffer(self._payload[16:20], dtype=np.uint32)[0]
      self.channel_separation = np.frombuffer(self._payload[20:24], dtype=np.uint32)[0]
      self.first_channel_freq = np.frombuffer(self._payload[24:32], dtype=np.uint64)[0]
      self.scale1, self.scale2, self.scale3, self.scale4 = np.frombuffer(self._payload[32:48], dtype=np.float32)
      self.n_first_channel = np.frombuffer(self._payload[48:52], dtype=np.uint32)[0]
      self.n_channels = np.frombuffer(self._payload[52:54], dtype=np.uint16)[0]
      self.valid_channels = np.frombuffer(self._payload[54:56], dtype=np.uint16)[0]
      self.n_time_samples = np.frombuffer(self._payload[56:58], dtype=np.uint16)[0]
      self.n_beam = np.frombuffer(self._payload[58:60], dtype=np.uint16)[0]
      self.magic_word = hex(np.frombuffer(self._payload[60:64], dtype=np.uint32)[0])
      self.packet_dest = self.packet_dest_map.get(self._data[64], "Unknown Destination")
      self.data_precision, self.n_power_samples_averaged, self.samples_per_weight = self._data[65:68]
      self.oversampling_ratio_numerator, self.oversampling_ratio_denominator = self._data[68:70]
      self.beamformer_ver = np.frombuffer(self._payload[70:72], dtype=np.uint16)[0]
      self.scan_id = np.frombuffer(self._payload[72:80], dtype=np.uint64)[0]
      self.offset1, self.offset2, self.offset3, self.offset4 = np.frombuffer(self._payload[80:96], dtype=np.float32)

      # Calculate the offset where the data starts
      METADATA_OFFSET = 96
      self._data_bytes = int(self.n_time_samples * 2 * self.n_channels * 2)
      weight_data_bytes = len(self._data) -METADATA_OFFSET - self._data_bytes
      self._data_offset = METADATA_OFFSET + weight_data_bytes

   @property
   def data(self) -> NDArray[np.int8]:
      """Returns the raw data array."""
      return np.frombuffer(self._payload[self._data_offset:], dtype=np.int8)


def extract_udp_payloads(pcap_file: str) -> List[bytes]:
   """Extracts UDP payloads from a PCAP file."""
   try:
      packets = rdpcap(pcap_file)
   except (FileNotFoundError, PermissionError) as e:
      print(f"Error: {e}")
      sys.exit(1)
   except Exception as e:
      print(f"Error reading '{pcap_file}': {e}")
      sys.exit(1)

   payloads = [bytes(packet[UDP].payload) for packet in packets if UDP in packet]
   
   if not payloads:
      print("No UDP packets found")
      sys.exit(1)
   
   return payloads


def check_magic_words(payloads: List[bytes]) -> bool:
   """Checks if the magic words in all payloads are matching."""
   magic_words = [PulsarPacket(payload).magic_word for payload in payloads]
   all_match = all(word == "0xbeadfeed" for word in magic_words)

   if all_match:
      print("Magic Words matching!")
   else:
      print("Magic Words are not matching!")
      for word in magic_words:
         print(f"Magic Word: {word}")

   return all_match


def extract_time_samples(packet: PulsarPacket) -> NDArray[np.complex64]:
   """Extracts time sample data from a Pulsar packet."""
   n_time_samples, n_channels = packet.n_time_samples, packet.n_channels
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
   magnitudes = np.abs(time_samples)
   min_values = np.min(magnitudes, axis=0)
   max_values = np.max(magnitudes, axis=0)
   std_devs = np.std(magnitudes, axis=0)

   return (np.min(min_values, axis=1),
         np.max(max_values, axis=1),
         np.mean(std_devs, axis=1))


def print_packet_statistics(packet: PulsarPacket) -> None:
   """Prints the min, max, and standard deviation for each channel in a packet."""
   min_values, max_values, std_devs = calculate_statistics(extract_time_samples(packet))

   print(f"Results for Packet {packet.n_sequence + 1}:")
   for channel, (min_val, max_val, std_dev) in enumerate(zip(min_values, max_values, std_devs), start=1):
      print(f"  ├─ Channel {channel}:")
      print(f"  │   ├─ Min Value: {min_val}")
      print(f"  │   ├─ Max Value: {max_val}")
      print(f"  │   └─ Standard Deviation: {std_dev}")
      print("  │")
   print()


def plot_statistics(packet: PulsarPacket) -> None:
   """Plots the min, max, and standard deviation for each channel in a packet."""
   min_values, max_values, std_devs = calculate_statistics(extract_time_samples(packet))
   channels = np.arange(1, packet.n_channels + 1)

   with plt.style.context("ggplot"):
      plt.figure(figsize=(10, 6))
      plt.plot(channels, min_values, label='Min Value', marker='o')
      plt.plot(channels, max_values, label='Max Value', marker='o')
      plt.plot(channels, std_devs, label='Standard Deviation', marker='o')

      plt.xlabel('Channel')
      plt.ylabel('Value')
      plt.title(f'Statistics for Packet {packet.n_sequence + 1}')
      plt.legend()
      plt.grid(True)
      plt.show()


# Extract UDP payloads from the capture file and process each one
udp_payloads = extract_udp_payloads(capture_file)

if check_magic_words(udp_payloads):
   for payload in udp_payloads:
      packet = PulsarPacket(payload)
      # print_packet_statistics(packet)
      print(f"Scale Values: {packet.scale1}, {packet.scale2}, {packet.scale3}, {packet.scale4}")
else:
   sys.exit(1)
