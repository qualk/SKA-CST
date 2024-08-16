import sys
from typing import List, Tuple

import matplotlib.pyplot as plt
import numpy as np
from numpy.typing import NDArray
from scapy.all import UDP, rdpcap

sys.stdout.reconfigure(encoding='utf-8')  # Ensure UTF-8 encoding for stdout

capture_file = "pss_4stn_4ch_fw-4a37b74c.pcap" # Change this to the path of the PCAP file


class PulsarPacket:
   """Represents a PSR-formatted packet with metadata extraction and data parsing."""

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

      METADATA_OFFSET = 96
      self._data_bytes = int(self.n_time_samples * 2 * self.n_channels * 2)
      weight_data_bytes = len(self._data) - METADATA_OFFSET - self._data_bytes
      self._data_offset = METADATA_OFFSET + weight_data_bytes

   @property
   def data(self) -> NDArray[np.int8]:
      """Returns the raw data array."""
      return np.frombuffer(self._payload[self._data_offset:], dtype=np.int8)


def extract_udp_payload(pcap_file: str) -> List[bytes]:
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


def accumulate_data(packets: List[PulsarPacket]) -> Tuple[NDArray[np.complex64], NDArray[np.float32]]:
   """Accumulates data from all packets."""
   all_time_samples = [extract_time_samples(packet) for packet in packets]
   accumulated_time_samples = np.concatenate(all_time_samples, axis=0)

   return accumulated_time_samples


def calculate_statistics(time_samples: NDArray[np.complex64], per_packet: bool = False) -> Tuple[NDArray[np.float64], NDArray[np.float64], NDArray[np.float64]]:
   """Calculates min, max, and standard deviation for each frequency channel."""
   magnitudes = np.abs(time_samples)
   min_values = np.min(magnitudes, axis=0)
   max_values = np.max(magnitudes, axis=0)
   std_devs = np.std(magnitudes, axis=0)

   if per_packet:
      return (np.min(min_values, axis=1), np.max(max_values, axis=1), np.mean(std_devs, axis=1))
   return (min_values.min(axis=1), max_values.max(axis=1), std_devs.mean(axis=1))


def print_statistics(packets: List[PulsarPacket], per_packet: bool = False) -> None:
   """Prints the min, max, and standard deviation for each channel in the packets."""
   if per_packet:
      for packet in packets:
         min_values, max_values, std_devs = calculate_statistics(extract_time_samples(packet), per_packet=True)
         print(f"Results for Packet {packet.n_sequence + 1}:")
         for channel, (min_val, max_val, std_dev) in enumerate(zip(min_values, max_values, std_devs), start=1):
               print(f"  ├─ Channel {channel}:")
               print(f"  │   ├─ Min Value: {min_val}")
               print(f"  │   ├─ Max Value: {max_val}")
               print(f"  │   └─ Standard Deviation: {std_dev}")
               print("  │")
         print()
   else:
      time_samples = accumulate_data(packets)
      min_values, max_values, std_devs = calculate_statistics(time_samples)
      print("Results Across All Packets:")
      for channel, (min_val, max_val, std_dev) in enumerate(zip(min_values, max_values, std_devs), start=1):
         print(f"  ├─ Channel {channel}:")
         print(f"  │   ├─ Min Value: {min_val}")
         print(f"  │   ├─ Max Value: {max_val}")
         print(f"  │   └─ Standard Deviation: {std_dev}")
         print("  │")
      print()


def plot_statistics(packets: List[PulsarPacket], per_packet: bool = False) -> None:
   """Plots the min, max, and standard deviation for each channel in the packets."""
   if per_packet:
      for packet in packets:
         min_values, max_values, std_devs = calculate_statistics(extract_time_samples(packet), per_packet=True)
         channels = np.arange(1, packet.n_channels + 1)

         with plt.style.context("default"):
               _, ax1 = plt.subplots(figsize=(10, 6))
               ax2 = ax1.twinx()  # Create a second y-axis

               ax1.plot(channels, min_values, label='Min Value', marker='o', color='b')
               ax1.plot(channels, max_values, label='Max Value', marker='o', color='g')
               ax2.plot(channels, std_devs, label='Standard Deviation', marker='o', linestyle='--', color='r')

               ax1.set_xlabel('Channel')
               ax1.set_ylabel('Value')
               ax2.set_ylabel('Standard Deviation', color='r')

               ax1.set_title(f'Statistics for Packet {packet.n_sequence + 1}')
               ax1.legend(loc='upper right')
               ax2.legend(loc='upper left')
               ax1.grid(False)
               plt.show()
   else:
      time_samples = accumulate_data(packets)
      min_values, max_values, std_devs = calculate_statistics(time_samples)
      channels = np.arange(1, packets[0].n_channels + 1)

      with plt.style.context("default"):
         _, ax1 = plt.subplots(figsize=(10, 6))
         ax2 = ax1.twinx()  # Create a second y-axis

         ax1.plot(channels, min_values, label='Min Value', marker='o', color='b')
         ax1.plot(channels, max_values, label='Max Value', marker='o', color='g')
         ax2.plot(channels, std_devs, label='Standard Deviation', marker='o', linestyle='--', color='r')

         ax1.set_xlabel('Channel')
         ax1.set_ylabel('Value')
         ax2.set_ylabel('Standard Deviation', color='r')

         ax1.set_title('Statistics Across All Packets')
         ax1.legend(loc='upper right')
         ax2.legend(loc='upper left')
         ax1.grid(False)
         plt.show()

def plot_scale1_across_packets(packets: List[PulsarPacket]) -> None:
   """Plots `scale1` values for each packet."""
   packet_indices = np.arange(1, len(packets) + 1)
   scale1_values = [packet.scale1 for packet in packets]

   with plt.style.context("ggplot"):
      _, ax = plt.subplots(figsize=(12, 8))
      ax.plot(packet_indices, scale1_values, label='Scale Values', marker='o', linestyle='-', color='b')

      ax.set_xlabel('Packet Index')
      ax.set_ylabel('Scale Value')
      ax.set_title('Scale Values Across All Packets')
      ax.legend()
      ax.grid(True)
      plt.show()


def plot_std_devs_across_packets(packets: List[PulsarPacket]) -> None:
   """Plots the standard deviation of each packet."""
   packet_indices = np.arange(1, len(packets) + 1)
   std_devs_per_packet = [calculate_statistics(extract_time_samples(packet), per_packet=True)[2] for packet in packets]
   mean_std_devs = np.mean(std_devs_per_packet, axis=1)

   with plt.style.context("ggplot"):
      _, ax = plt.subplots(figsize=(12, 8))
      ax.plot(packet_indices, mean_std_devs, label='Standard Deviation', marker='o', linestyle='-', color='r')

      ax.set_xlabel('Packet Index')
      ax.set_ylabel('Standard Deviation')
      ax.set_title('Standard Deviation Across All Packets')
      ax.legend()
      ax.grid(True)
      plt.show()




udp_payloads = extract_udp_payload(capture_file)

if check_magic_words(udp_payloads):
   pulsar_packets = [PulsarPacket(payload) for payload in udp_payloads]

   # Print and plot statistics per packet
   # print_statistics(pulsar_packets, per_packet=True)
   # plot_statistics(pulsar_packets, per_packet=True)

   # Print and plot cumulative statistics across all packets
   # print_statistics(pulsar_packets, per_packet=False)
   plot_std_devs_across_packets(pulsar_packets)
   # print_statistics(pulsar_packets, per_packet=True)

