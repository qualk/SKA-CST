import sys
from typing import List

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
      
      METADATA_OFFSET = 96

      # Extract metadata
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
      self.packet_dest = self.packet_dest_map.get(self._data[64], "Unknown Destination")
      self.data_precision = self._data[65]
      self.n_power_samples_averaged = self._data[66]
      self.samples_per_weight = self._data[67]
      self.oversampling_ratio_numerator = self._data[68]
      self.oversampling_ratio_denominator = self._data[69]
      self.beamformer_ver = np.frombuffer(payload[70:72], dtype=np.uint16)[0]
      self.scan_id = np.frombuffer(payload[72:80], dtype=np.uint64)[0]
      self.offset1 = np.frombuffer(payload[80:84], dtype=np.float32)[0]
      self.offset2 = np.frombuffer(payload[84:88], dtype=np.float32)[0]
      self.offset3 = np.frombuffer(payload[88:92], dtype=np.float32)[0]
      self.offset4 = np.frombuffer(payload[92:96], dtype=np.float32)[0]
      
      # Calculate the offset where the data starts
      self._data_bytes = int(self.n_time_samples * 2 * self.n_channels * 2)
      weight_data_bytes = len(self._data) - METADATA_OFFSET - self._data_bytes
      self._data_offset = METADATA_OFFSET + weight_data_bytes

def extract_time_samples(packet: PulsarPacket) -> NDArray[np.complex64]:
   """Extracts time sample data from a Pulsar packet."""
   time_samples = np.zeros((packet.n_time_samples, packet.n_channels, 2), dtype=np.complex64)

   payload = packet._payload[packet._data_offset:]
   
   for channel in range(packet.n_channels):
      for polarisation in range(2):  # 0 for A, 1 for B
         for time_sample in range(packet.n_time_samples):
               index = (
                  channel * 4 * packet.n_time_samples + 
                  polarisation * 2 * packet.n_time_samples + 
                  time_sample * 2
               )
               I_byte = payload[index]
               Q_byte = payload[index + 1]
               
               time_samples[time_sample, channel, polarisation] = complex(I_byte, Q_byte)

   return time_samples

def extract_udp_payloads(pcap_file: str) -> List[bytes]:
   """Extracts UDP payloads from a PCAP file."""
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

   payloads = [bytes(packet[UDP].payload) for packet in packets if UDP in packet]

   if not payloads:
      print("No UDP packets found")
      sys.exit(1)

   return payloads

# Extract UDP payloads from the capture file and process each one
payloads = extract_udp_payloads(capture_file)
for payload in payloads:
   packet = PulsarPacket(payload)
   print(extract_time_samples(packet))
