import struct
import sys

from scapy.all import UDP, rdpcap

class MetadataFormat:
   packet_dest_mapping = {
      0: "Low PSS",
      1: "Mid PSS",
      2: "Low PST",
      3: "Mid PST"
   }
   
   def __init__(self, payload: bytes):
      self.sequence_number = struct.unpack("<Q", payload[0:8])[0]  # Little-endian unsigned long long
      self.timestamp_attoseconds = struct.unpack("<Q", payload[8:16])[0]  # Little-endian unsigned long long
      self.timestamp_seconds = struct.unpack("<I", payload[16:20])[0]  # Little-endian unsigned int
      self.channel_separation = struct.unpack("<I", payload[20:24])[0]  # Little-endian unsigned int
      self.first_channel_frequency = struct.unpack("<Q", payload[24:32])[0]  # Little-endian unsigned long long
      self.scale1 = struct.unpack("<f", payload[32:36])[0]  # Little-endian float
      self.scale2 = struct.unpack("<f", payload[36:40])[0]  # Little-endian float
      self.scale3 = struct.unpack("<f", payload[40:44])[0]  # Little-endian float
      self.scale4 = struct.unpack("<f", payload[44:48])[0]  # Little-endian float
      self.first_channel_number = struct.unpack("<I", payload[48:52])[0]  # Little-endian unsigned int
      self.channels_per_packet = struct.unpack("<H", payload[52:54])[0]  # Little-endian unsigned short
      self.valid_channels_per_packet = struct.unpack("<H", payload[54:56])[0]  # Little-endian unsigned short
      self.number_of_time_samples = struct.unpack("<H", payload[56:58])[0]  # Little-endian unsigned short
      self.beam_number = struct.unpack("<H", payload[58:60])[0]  # Little-endian unsigned short
      self.magic_word = hex(struct.unpack("<I", payload[60:64])[0]) # Little-endian unsigned int to hex
      self.packet_destination = self.packet_dest_mapping.get(payload[64], int) # Unsigned int to str from mapping
      self.data_precision = payload[65]  # Unsigned char
      self.number_power_samples_averaged = payload[66]  # Unsigned char
      self.samples_per_weight = payload[67]  # Unsigned char
      self.oversampling_ratio_numerator = payload[68]  # Unsigned char
      self.oversampling_ratio_denominator = payload[69]  # Unsigned char
      self.beamformer_version = struct.unpack("<H", payload[70:72])[0]  # Little-endian unsigned short
      self.scan_id = struct.unpack("<Q", payload[72:80])[0]  # Little-endian unsigned long long
      self.offset1 = struct.unpack("<f", payload[80:84])[0]  # Little-endian float
      self.offset2 = struct.unpack("<f", payload[84:88])[0]  # Little-endian float
      self.offset3 = struct.unpack("<f", payload[88:92])[0]  # Little-endian float
      self.offset4 = struct.unpack("<f", payload[92:96])[0]  # Little-endian float

def extract_udp_payloads(pcap_file):
   packets = rdpcap(pcap_file)
   payloads = []

   for packet in packets:
      if UDP in packet and packet[UDP].payload:
         payload = bytes(packet[UDP].payload) 
         payloads.append(payload)
   
      if not payloads:
         print("No UDP packets found")
         sys.exit(1)

   return payloads

def check_magic_words(payloads):
   magic_words = []
   for payload in payloads:
      metadata = payload[:96]
      packet = MetadataFormat(metadata)
      magic_words.append(packet.magic_word)
   
   if all(magic_word == "0xbeadfeed" for magic_word in magic_words):
      print("Magic Numbers matching!")
      return True
   else:
      print("Magic Numbers are not matching!")
      for magic_word in magic_words:
         print(f"Magic Number: {magic_words}")
      return False

def print_metadata(payloads):
   for payload in payloads:
      metadata = payload[:96]
      packet = MetadataFormat(metadata)
      print(f"Sequence Number: {packet.sequence_number}")
      print(f"Timestamp Attoseconds: {packet.timestamp_attoseconds}")
      print(f"Timestamp Seconds: {packet.timestamp_seconds}")
      print(f"Channel Separation: {packet.channel_separation}")
      print(f"First Channel Frequency: {packet.first_channel_frequency}")
      print(f"Scale 1: {packet.scale1}")
      print(f"Scale 2: {packet.scale2}")
      print(f"Scale 3: {packet.scale3}")
      print(f"Scale 4: {packet.scale4}")
      print(f"First Channel Number: {packet.first_channel_number}")
      print(f"Channels per Packet: {packet.channels_per_packet}")
      print(f"Valid Channels per Packet: {packet.valid_channels_per_packet}")
      print(f"Number of Time Samples per Packet: {packet.number_of_time_samples}")
      print(f"Beam Number: {packet.beam_number}")
      print(f"Magic Word: {packet.magic_word}")
      print(f"Packet Destination: {packet.packet_destination}")
      print(f"Data Precision: {packet.data_precision}")
      print(f"Number Power Samples Averaged: {packet.number_power_samples_averaged}")
      print(f"Samples per Weight: {packet.samples_per_weight}")
      print(f"Oversampling Ratio: {packet.oversampling_ratio_numerator}/{packet.oversampling_ratio_denominator}")
      print(f"Beamformer Version: {packet.beamformer_version}")
      print(f"Scan ID: {packet.scan_id}")
      print(f"Offset 1: {packet.offset1}")
      print(f"Offset 2: {packet.offset2}")
      print(f"Offset 3: {packet.offset3}")
      print(f"Offset 4: {packet.offset4}")
      print()

payloads = extract_udp_payloads("pss.pcap")
if check_magic_words(payloads) == True:
   print()
   print_metadata(payloads)
elif check_magic_words(payloads) == False:
   sys.exit(1)
