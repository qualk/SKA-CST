# -*- coding: utf-8 -*-
#
# This file is part of the SKA Low CBF Connector project
#
# Copyright (c) 2023 CSIRO
#
# Distributed under the terms of the CSIRO Open Source Software Licence
# Agreement. See LICENSE for more info.
#
"""PSR Traffic Analyser."""
import math
import struct
from collections import defaultdict
from typing import Iterable

import numpy as np
from numpy.typing import NDArray
from scapy.all import UDP, rdpcap


def summarise(payloads: Iterable[bytes]) -> None:
   """Print a summary of PSR packets."""
   beam_chans = defaultdict(set)
   for payload in payloads:
      packet = PulsarPacket(payload)
      n_beam = packet.beam_id
      channels = packet.channels
      beam_chans[n_beam].update(channels)
   for bm_id, chans in beam_chans.items():
      ch_sorted = sorted(list(chans))
      start_idx = 0
      val = ch_sorted[0]
      txt = f"{ch_sorted[0]}"
      for idx in range(1, len(ch_sorted)):
         if ch_sorted[idx] == val + 1:
               val = ch_sorted[idx]
               continue
         if idx == start_idx + 1:
               val = ch_sorted[idx]
               start_idx = idx
               txt += f", {val}"
         else:
               val = ch_sorted[idx]
               start_idx = idx
               txt += f"-{ch_sorted[idx]}, {val}"

      if start_idx != idx:
         txt += f"-{ch_sorted[-1]}"
      print(f"beam_{bm_id} channels: {txt} ({len(ch_sorted)} chans)")


N_POL = 2
N_VALS_PER_CPLX = 2
N_BYES_PER_VAL = 2
N_BYTES_PER_SAMPLE = N_POL * N_VALS_PER_CPLX * N_BYES_PER_VAL


class PulsarPacket:  # pylint: disable=too-many-instance-attributes
   """Representation of a PSR-formatted packet."""

   def __init__(self, payload: bytes):
      """Decode UDP payload bytes into a PulsarPacket."""
      self._payload = payload
      self.n_sequence = struct.unpack("Q", payload[0:8])[0]
      self.scale = struct.unpack("f", payload[32:36])[0]
      self.first_channel = struct.unpack("I", payload[48:52])[0]
      self.n_channels = struct.unpack("H", payload[52:54])[0]
      self.valid_channels = struct.unpack("H", payload[54:56])[0]
      self.n_samples = struct.unpack("H", payload[56:58])[0]
      self.beam_id = struct.unpack("H", payload[58:60])[0]
      self.samples_per_weight = struct.unpack("B", payload[67:68])[0]

      weights_offset = 96  # multiple of 16bytes=128 bits
      n_weight_bytes = self.n_samples / self.samples_per_weight * 2 * self.n_channels
      # weights padded to multiple of 128 bits = 16 bytes
      self._data_offset = weights_offset + math.ceil(n_weight_bytes // 16) * 16
      """Offset of sample data within payload bytes."""

   @property
   def channels(self) -> [int]:
      """Channels contained in this packet."""
      return list(range(self.first_channel, self.first_channel + self.n_channels))

   def _channel_offset(self, channel: int) -> int:
      """Offset of channel data within payload bytes."""
      return self._data_offset + (
         channel * self.n_samples * N_BYES_PER_VAL * N_VALS_PER_CPLX * N_POL
      )

   def power_per_sample(self) -> NDArray[np.floating]:
      """Sum total power (sum of all channels) for each sample in this packet."""
      power_sum = np.zeros(self.n_samples)
      for channel in range(self.valid_channels):
         ch_offset = self._channel_offset(channel)
         # sum sample power for both polarisations
         for pol in range(N_POL):
               pol_base = (
                  ch_offset + pol * self.n_samples * N_BYES_PER_VAL * N_VALS_PER_CPLX
               )
               for sample_idx in range(self.n_samples):
                  loc_x = pol_base + sample_idx * 4
                  x_i, x_q = struct.unpack("hh", self._payload[loc_x : loc_x + 4])
                  sample_pwr = x_i * x_i + x_q * x_q
                  power_sum[sample_idx] += sample_pwr

      return power_sum / (self.scale * self.scale)

   def channel_power(self) -> NDArray[np.floating]:
      """Calculate average power per-complex-sample per channel."""
      channel_power = np.zeros(self.n_channels)
      for channel in range(self.valid_channels):
         ch_offset = self._channel_offset(channel)
         # sum sample power for both polarisations
         for pol in range(N_POL):
               pol_base = (
                  ch_offset + pol * self.n_samples * N_BYES_PER_VAL * N_VALS_PER_CPLX
               )
               for sample_idx in range(self.n_samples):
                  loc_x = pol_base + sample_idx * 4
                  x_i, x_q = struct.unpack("hh", self._payload[loc_x : loc_x + 4])
                  sample_pwr = x_i * x_i + x_q * x_q
                  channel_power[channel] += sample_pwr
      # average power per-complex-sample per channel
      channel_power = (
         channel_power
         / (self.scale * self.scale)
         / self.valid_channels
         / self.n_channels
      )

      return channel_power


# Unused calculations, left as reference for future incorporation into the class above
#
# def get_chanl_data(chan, beam, payload):
#     """Get PSR channel data."""
#     seq_no = struct.unpack("Q", payload[0:8])[0]
#     scale1 = struct.unpack("f", payload[32:36])[0]
#     first_chan = struct.unpack("I", payload[48:52])[0]
#     num_chan = struct.unpack("H", payload[52:54])[0]
#     valid_chan = struct.unpack("H", payload[54:56])[0]
#     num_sample = struct.unpack("H", payload[56:58])[0]
#     beam_id = struct.unpack("H", payload[58:60])[0]
#     sample_per_weight = struct.unpack("B", payload[67:68])[0]
#     channel = chan - first_chan  # chan number relative to this packet first channel
#     if beam_id != beam or channel < 0 or channel >= valid_chan:
#         return None, None, None, None
#     weights_offset = 96  # multiple of 16bytes=128 bits
#     n_weight_bytes = num_sample / sample_per_weight * 2 * num_chan
#     # weights padded to multiple of 128 bits = 16 bytes
#     data_offset = weights_offset + math.ceil(n_weight_bytes // 16) * 16
#     ch_offset = (
#         data_offset + channel * num_sample * N_BYES_PER_VAL * N_VALS_PER_CPLX * N_POL
#     )
#     dat_i = []
#     dat_q = []
#     for idx in range(0, num_sample):
#         loc = ch_offset + idx * 4
#         sample_iq = struct.unpack("hh", payload[loc : loc + 4])
#         dat_i.append(sample_iq[0] / scale1)
#         dat_q.append(sample_iq[1] / scale1)
#
#     return seq_no, dat_i, dat_q, [scale1] * num_sample
#
#
# def get_channel_voltage(beam, payload, chan):
#     """Get PSR channel voltage."""
#     seq_no = struct.unpack("Q", payload[0:8])[0]
#     scale1 = struct.unpack("f", payload[32:36])[0]
#     first_chan = struct.unpack("I", payload[48:52])[0]
#     num_chan = struct.unpack("H", payload[52:54])[0]
#     valid_chan = struct.unpack("H", payload[54:56])[0]
#     num_sample = struct.unpack("H", payload[56:58])[0]
#     beam_id = struct.unpack("H", payload[58:60])[0]
#     sample_per_weight = struct.unpack("B", payload[67:68])[0]
#     if beam_id != beam or chan < first_chan or chan >= first_chan + valid_chan:
#         return None, None, None
#     weights_offset = 96  # multiple of 16bytes=128 bits
#     n_weight_bytes = num_sample / sample_per_weight * 2 * num_chan
#     # weights padded to multiple of 128 bits = 16 bytes
#     data_offset = weights_offset + math.ceil(n_weight_bytes // 16) * 16
#
#     channel = chan - first_chan
#     ch_offset = data_offset + (
#         channel * num_sample * N_BYES_PER_VAL * N_VALS_PER_CPLX * N_POL
#     )
#
#     np_chanl_x = np.zeros(num_sample, dtype=complex)
#     np_chanl_y = np.zeros(num_sample, dtype=complex)
#     for channel in range(0, valid_chan):
#         ch_offset = data_offset + (
#             channel * num_sample * N_BYES_PER_VAL * N_VALS_PER_CPLX * N_POL
#         )
#         # sample power for both polarisations
#         for pol in range(0, 2):
#             pol_base = ch_offset + pol * num_sample * N_BYES_PER_VAL * N_VALS_PER_CPLX
#             for sample_idx in range(0, num_sample):
#                 loc_x = pol_base + sample_idx * 4
#                 x_i, x_q = struct.unpack("hh", payload[loc_x : loc_x + 4])
#                 sample = x_i / scale1 + 1j * x_q / scale1
#                 if pol == 0:
#                     np_chanl_x[sample_idx] = sample
#                 else:
#                     np_chanl_y[sample_idx] = sample
#
#     return seq_no, np_chanl_x, np_chanl_y

def extract_udp_payloads(pcap_file):
   packets = rdpcap(pcap_file)
   payloads = []

   for packet in packets:
      if UDP in packet and packet[UDP].payload:
         payload = bytes(packet[UDP].payload) 
         payloads.append(payload)
   
      if not payloads:
         print("No UDP packets found")

   return payloads

payloads = extract_udp_payloads("pss.pcap")
summarise(payloads)
