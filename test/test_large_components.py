#!/usr/bin/env python3
# Copyright 2026 OpenDroidOS
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import io
import os
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from create_hashdata import CreateHash, HashType
from create_update_package import CreatePackage, COPY_BLOCK_SIZE
from image_class import FullUpdateImage
from update_package import PkgComponent
from unpack_updater_package import UnpackPackage
from utils import OPTIONS_MANAGER


class Source:
    def __init__(self, count):
        self.remaining = count

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def read(self, count=-1):
        if count <= 0 or count > COPY_BLOCK_SIZE:
            raise AssertionError("unbounded component read")
        count = min(count, self.remaining)
        self.remaining -= count
        return bytes(count)


class Sink:
    def seek(self, position):
        self.position = position

    def write(self, data):
        self.position += len(data)
        return len(data)


class LargeComponents(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        OPTIONS_MANAGER.not_l2 = False
        OPTIONS_MANAGER.stream_update = False

    def component(self, size):
        value = PkgComponent()
        value.component_addr = b"/system"
        value.version = b"1"
        value.file_path = b"fixture"
        value.size = size
        return value

    def package(self, version):
        return CreatePackage(SimpleNamespace(update_file_version=version), [], "fixture", "key")

    def test_v3_size_crosses_uint32_boundary(self):
        component = self.component(2 ** 32 + 4096)
        output = io.BytesIO()
        package = self.package(3)
        self.assertTrue(package.write_component_info(component, output))
        self.assertEqual(struct.unpack_from("<Q", output.getvalue(), 47)[0], 2 ** 32 + 4096)
        self.assertEqual(len(output.getvalue()), 87)

    def test_legacy_small_component_bytes_are_unchanged(self):
        component = self.component(12345)
        component.original_size = 5678
        output = io.BytesIO()
        self.assertTrue(self.package(2).write_component_info(component, output))
        self.assertEqual(output.getvalue()[47:55], struct.pack("iI", 12345, 5678))

    def test_legacy_large_component_fails_without_wrapping(self):
        with patch("create_update_package.UPDATE_LOGGER.print_log"):
            self.assertFalse(self.package(2).write_component_info(self.component(2 ** 32), io.BytesIO()))

    def test_component_copy_never_requests_an_unbounded_read(self):
        size = 2 ** 32 + 17
        package = self.package(3)
        sink = Sink()
        with patch("builtins.open", return_value=Source(size)):
            self.assertTrue(package.write_component(self.component(size), sink))
        self.assertEqual(package.component_offset, size)
        self.assertEqual(sink.position, size)

    def test_truncated_input_does_not_claim_expected_size(self):
        package = self.package(3)
        with patch("builtins.open", return_value=Source(2)), patch("create_update_package.UPDATE_LOGGER.print_log"):
            self.assertFalse(package.write_component(self.component(3), Sink()))

    def test_normal_full_package_reuses_read_only_input(self):
        path = self.root / "system.img"
        path.write_bytes(b"payload")
        target = FullUpdateImage(str(self.root), ["system"], ["system.img"],
                                SimpleNamespace(full_image_update=lambda _: "write", add_command=lambda **_: None),
                                [str(path)])
        with patch.object(target, "get_full_image_content", side_effect=AssertionError("whole-image read")):
            sizes, files = target.update_full_image()
        try:
            self.assertEqual(sizes, [7])
            self.assertEqual(files[0].name, str(path))
            self.assertFalse(files[0].writable())
        finally:
            for stream in files:
                stream.close()
        self.assertEqual(path.read_bytes(), b"payload")

    def test_hash_layout_selects_u64_header_and_ranges(self):
        old, new = CreateHash(HashType.SHA256, 1, 2), CreateHash(HashType.SHA256, 1, 3)
        self.assertEqual((old.header_size, old.address_size), (38, 8))
        self.assertEqual((new.header_size, new.address_size), (42, 16))
        large = 2 ** 32 + 123
        payload = struct.pack(new.header_fmt, b"/system", 1, large)
        payload += struct.pack(new.address_fmt, 2 ** 32, large - 1) + bytes(32)
        self.assertTrue(new.parse_hashdata(payload))
        self.assertEqual(new.hashdata_list[0][2], large)
        self.assertEqual(new.hashdata_list[1][:2], (2 ** 32, large - 1))

    def test_unpacked_v3_component_size_is_not_truncated(self):
        package = UnpackPackage()
        package.file_version = 3
        data = bytearray(267)
        data[180:187] = b"/system"
        struct.pack_into("<Q", data, package.size_offset, 2 ** 32 + 4096)
        self.assertEqual(package.parse_component(io.BytesIO(data))[2], 2 ** 32 + 4096)


if __name__ == "__main__":
    unittest.main()
