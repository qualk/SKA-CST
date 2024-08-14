##FIXME

import numpy as np
import struct
import sys
from scapy.all import UDP, rdpcap
from tabulate import tabulate

capture_file = "pss.pcap"

class PulsarPacket:
   packet_dest_map = {
      0: "Low PSS",
      1: "Mid PSS",
      2: "Low PST",
      3: "Mid PST"
   }

   def __init__(self, payload: bytes):
      # Convert bytes to a NumPy array
      data = np.frombuffer(payload, dtype=np.uint8)
      
      # Metadata
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
      self.channels_per_packet = np.frombuffer(payload[52:54], dtype=np.uint16)[0]
      self.valid_channels_per_packet = np.frombuffer(payload[54:56], dtype=np.uint16)[0]
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
      data_bytes = int(self.n_time_samples * 2 * self.channels_per_packet * 2)
      weight_data_bytes = len(data) - metadata_offset - data_bytes
      self._data_offset = metadata_offset + weight_data_bytes
      print(self._data_offset)
      print(weight_data_bytes)
      print(data_bytes)
      print(self.n_time_samples, self.channels_per_packet)

   def extract_time_samples(self, payload: bytes):
      # Convert the relevant part of the payload to a NumPy array
      data = np.frombuffer(payload[self._data_offset:], dtype=np.int8)
      
      # Print debugging information
      print(f"Extracted data length: {len(data)}")
      print(f"Expected data length: {self.n_time_samples * 2 * self.channels_per_packet * 2}")
      print(f"Payload size: {len(payload)}")
      print(f"Data offset: {self._data_offset}")

      # Calculate the number of bytes for the data (2 bytes per sample)
      data_length = self.n_time_samples * 2 * self.channels_per_packet * 2 # I and Q samples, 2 polarizations
   

      # Reshape data into a 3D array (channels, time samples, polarizations)
      data = data[:data_length].reshape((self.channels_per_packet, self.n_time_samples, 2))  # 4 = 2 time samples * 2 polarizations (I and Q)

      # Extract I and Q samples
      i_samples = data[:, :, ::2]  # Select I samples
      q_samples = data[:, :, 1::2]  # Select Q samples
      
      return i_samples, q_samples

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
