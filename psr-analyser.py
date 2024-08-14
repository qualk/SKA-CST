import math
import struct
import sys

from scapy.all import UDP, rdpcap
from tabulate import tabulate

capture_file = "pss.pcap"

class PulsarPacketFormat:
   packet_dest_map = {
      0: "Low PSS",
      1: "Mid PSS",
      2: "Low PST",
      3: "Mid PST"
   }
   
   def __init__(self, payload: bytes):
      # Metadata
      self.n_sequence = struct.unpack("<Q", payload[0:8])[0]  # Little-endian unsigned long long
      self.timestamp_attoseconds = struct.unpack("<Q", payload[8:16])[0]  # Little-endian unsigned long long
      self.timestamp_seconds = struct.unpack("<I", payload[16:20])[0]  # Little-endian unsigned int
      self.channel_separation = struct.unpack("<I", payload[20:24])[0]  # Little-endian unsigned int
      self.first_channel_freq = struct.unpack("<Q", payload[24:32])[0]  # Little-endian unsigned long long
      self.scale1 = struct.unpack("<f", payload[32:36])[0]  # Little-endian float
      self.scale2 = struct.unpack("<f", payload[36:40])[0]  # Little-endian float
      self.scale3 = struct.unpack("<f", payload[40:44])[0]  # Little-endian float
      self.scale4 = struct.unpack("<f", payload[44:48])[0]  # Little-endian float
      self.n_first_channel = struct.unpack("<I", payload[48:52])[0]  # Little-endian unsigned int
      self.channels_per_packet = struct.unpack("<H", payload[52:54])[0]  # Little-endian unsigned short
      self.valid_channels_per_packet = struct.unpack("<H", payload[54:56])[0]  # Little-endian unsigned short
      self.n_time_samples = struct.unpack("<H", payload[56:58])[0]  # Little-endian unsigned short
      self.n_beam = struct.unpack("<H", payload[58:60])[0]  # Little-endian unsigned short
      self.magic_word = hex(struct.unpack("<I", payload[60:64])[0]) # Little-endian unsigned int to hex
      self.packet_dest = self.packet_dest_map.get(payload[64], int) # Unsigned int to str from mapping
      self.data_precision = payload[65]  # Unsigned char
      self.n_power_samples_averaged = payload[66]  # Unsigned char
      self.samples_per_weight = payload[67]  # Unsigned char
      self.oversampling_ratio_numerator = payload[68]  # Unsigned char
      self.oversampling_ratio_denominator = payload[69]  # Unsigned char
      self.beamformer_ver = struct.unpack("<H", payload[70:72])[0]  # Little-endian unsigned short
      self.scan_id = struct.unpack("<Q", payload[72:80])[0]  # Little-endian unsigned long long
      self.offset1 = struct.unpack("<f", payload[80:84])[0]  # Little-endian float
      self.offset2 = struct.unpack("<f", payload[84:88])[0]  # Little-endian float
      self.offset3 = struct.unpack("<f", payload[88:92])[0]  # Little-endian float
      self.offset4 = struct.unpack("<f", payload[92:96])[0]  # Little-endian float
      
      weight_data_offset = 96
      weight_data_bytes = int(self.n_time_samples / self.samples_per_weight * 2 * self.channels_per_packet)
      self._data_offset = len(payload) - weight_data_offset - weight_data_bytes

def extract_udp_payloads(pcap_file):
   try:
      with open(pcap_file, "rb") as file:
         packets = rdpcap(file)
   except FileNotFoundError:
      print(f"Error: File '{pcap_file}' does not exist.")
      sys.exit(1)
   except PermissionError:
      print(f"Error: File '{pcap_file}' cannot be read due to insufficient permissoins.")
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

def check_magic_words(payloads):
   magic_words = []
   for payload in payloads:
      packet = PulsarPacketFormat(payload)
      magic_words.append(packet.magic_word)

   if all(magic_word == "0xbeadfeed" for magic_word in magic_words):
      print("Magic Words matching!")
      return True
   else:
      print("Magic Words are not matching!")
      for magic_word in magic_words:
         print(f"Magic Words: {magic_words}")
      return False

def print_metadata(payloads):
   counter = 0
   for payload in payloads:
      counter += 1
      packet = PulsarPacketFormat(payload)
      data = [
         ("Sequence Number", packet.n_sequence),
         ("Timestamp Attoseconds", packet.timestamp_attoseconds),
         ("Timestamp Seconds", packet.timestamp_seconds),
         ("Channel Separation", packet.channel_separation),
         ("First Channel Frequency", packet.first_channel_freq),
         ("Scale 1", packet.scale1),
         ("Scale 2", packet.scale2),
         ("Scale 3", packet.scale3),
         ("Scale 4", packet.scale4),
         ("First Channel Number", packet.n_first_channel),
         ("Channels per Packet", packet.channels_per_packet),
         ("Valid Channels per Packet", packet.valid_channels_per_packet),
         ("n Time Samples per Packet", packet.n_time_samples),
         ("Beam Number", packet.n_beam),
         ("Magic Word", packet.magic_word),
         ("Packet Destination", packet.packet_dest),
         ("Data Precision", packet.data_precision),
         ("n Power Samples Avg", packet.n_power_samples_averaged),
         ("Samples per Weight", packet.samples_per_weight),
         ("Oversampling Ratio", f"{packet.oversampling_ratio_numerator}/{packet.oversampling_ratio_denominator}"),
         ("Beamformer Version", packet.beamformer_ver),
         ("Scan ID", packet.scan_id),
         ("Offset 1", packet.offset1),
         ("Offset 2", packet.offset2),
         ("Offset 3", packet.offset3),
         ("Offset 4", packet.offset4),
      ]
      print(f"Packet Number #{counter}:")
      if "--plain" in sys.argv:
         for item in data:
            print(f"{item[0]}: {item[1]}")
         for item in data:
            print(f"{item[0]}: {item[1]}")
      else:
         print(tabulate(data, tablefmt="grid"))
      print()
      print()

payloads = extract_udp_payloads(capture_file)
if check_magic_words(payloads) == True:
   print()
   print_metadata(payloads)
elif check_magic_words(payloads) == False:
   sys.exit(1)
