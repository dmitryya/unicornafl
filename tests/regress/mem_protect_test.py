import collections
import enum
import unittest

from unicornafl import *
from unicornafl.arm_const import *
from unicornafl.unicorn_const import *


class ErrNo(enum.IntEnum):
    OK = 0  # No error: everything was fine
    NOMEM = 1  # Out-Of-Memory error: uc_open() =  uc_emulate()
    ARCH = 2  # Unsupported architecture: uc_open()
    HANDLE = 3  # Invalid handle
    MODE = 4  # Invalid/unsupported mode: uc_open()
    VERSION = 5  # Unsupported version (bindings)
    READ_UNMAPPED = 6  # Quit emulation due to READ on unmapped memory: uc_emu_start()
    WRITE_UNMAPPED = 7  # Quit emulation due to WRITE on unmapped memory: uc_emu_start()
    FETCH_UNMAPPED = 8  # Quit emulation due to FETCH on unmapped memory: uc_emu_start()
    HOOK = 9  # Invalid hook type: uc_hook_add()
    INSN_INVALID = 10  # Quit emulation due to invalid instruction: uc_emu_start()
    MAP = 11  # Invalid memory mapping: uc_mem_map()
    WRITE_PROT = 12  # Quit emulation due to UC_MEM_WRITE_PROT violation: uc_emu_start()
    READ_PROT = 13  # Quit emulation due to UC_MEM_READ_PROT violation: uc_emu_start()
    FETCH_PROT = 14  # Quit emulation due to UC_MEM_FETCH_PROT violation: uc_emu_start()
    ARG = 15  # Inavalid argument provided to uc_xxx function (See specific function API)
    READ_UNALIGNED = 16  # Unaligned read
    WRITE_UNALIGNED = 17  # Unaligned write
    FETCH_UNALIGNED = 18  # Unaligned fetch
    HOOK_EXIST = 19  # hook for this event already existed
    RESOURCE = 20  # Insufficient resource: uc_emu_start()
    EXCEPTION = 21  # Unhandled CPU exception


MemRegion = collections.namedtuple('MemRegion', ['begin', 'end', 'perm'])


class TestMemProtect(unittest.TestCase):
  # code to be emulated
  ARM_CODE_LDR   = b"\x00\x00\x91\xe5"
  ARM_CODE_STR   = b"\x00\x00\x81\xe5"
  # memory address where emulation starts
  ADDRESS    = 0xF0000000
  SIZE = 0x1000

  def setUp(self):
    unittest.TestCase.setUp(self)
    # Initialize emulator in ARM mode
    self.uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)

  def get_mem_regions(self):
    out = []
    for begin, end, perm in self.uc.mem_regions():
      out.append(MemRegion(begin, end, perm))
    return out

  def get_mem_perm_regions(self):
    out = []
    for begin, end, perm in self.uc.mem_perm_regions():
      out.append(MemRegion(begin, end, perm))
    return out

  def hook_mem_op(self, uc, access, address, size, value, user_data, phys_addr):
    print(f"ACCESS {access}, address 0x{address:x}, size {size}, value {value}")

  def test_no_exec_access(self):
    self.uc.mem_map(self.ADDRESS, self.SIZE, UC_PROT_NONE)
    regs = self.get_mem_regions()
    self.assertEqual(len(regs), 1)
    self.assertEqual(regs[0].perm, UC_PROT_UNK)
    regs = self.get_mem_perm_regions()
    self.assertEqual(len(regs), 1)
    self.uc.mem_write(self.ADDRESS, self.ARM_CODE_LDR)
    with self.assertRaises(UcError) as ctx:
      self.uc.emu_start(self.ADDRESS, self.ADDRESS + len(self.ARM_CODE_LDR))
    self.assertEqual(ctx.exception.errno, ErrNo.FETCH_PROT)

  def test_read_from_only_exec_access(self):
    # do nothing memory hook as a workaround for issue that READ access is not checked for
    # executed memory range.
    self.uc.hook_add(UC_HOOK_MEM_WRITE, lambda a, b, c, d, e, f, g: b + c)

    self.uc.mem_map(self.ADDRESS, self.SIZE, UC_PROT_NONE)
    regs = self.get_mem_regions()
    self.assertEqual(len(regs), 1)
    regs = self.get_mem_perm_regions()
    self.assertEqual(len(regs), 1)

    self.uc.mem_protect(self.ADDRESS, 0x400, UC_PROT_EXEC)
    regs = self.get_mem_regions()
    self.assertEqual(len(regs), 1)
    regs = self.get_mem_perm_regions()
    self.assertEqual(len(regs), 2)

    self.uc.reg_write(UC_ARM_REG_R1, self.ADDRESS + 0x20)
    self.uc.mem_write(self.ADDRESS, self.ARM_CODE_LDR)

    with self.assertRaises(UcError) as ctx:
      self.uc.emu_start(self.ADDRESS, self.ADDRESS + len(self.ARM_CODE_LDR))
    self.assertEqual(ctx.exception.errno, ErrNo.READ_PROT)

  def test_write_to_only_exec_access(self):
    self.uc.mem_map(self.ADDRESS, self.SIZE, UC_PROT_NONE)
    self.uc.mem_protect(self.ADDRESS, 0x400, UC_PROT_EXEC)
    self.uc.reg_write(UC_ARM_REG_R1, self.ADDRESS + 0x20)
    self.uc.mem_write(self.ADDRESS, self.ARM_CODE_STR)
    with self.assertRaises(UcError) as ctx:
      self.uc.emu_start(self.ADDRESS, self.ADDRESS + len(self.ARM_CODE_LDR))
    self.assertEqual(ctx.exception.errno, ErrNo.WRITE_PROT)

  def test_no_write_access(self):
    self.uc.mem_map(self.ADDRESS, self.SIZE, UC_PROT_NONE)
    self.uc.mem_protect(self.ADDRESS, 0x400, UC_PROT_EXEC)
    self.uc.reg_write(UC_ARM_REG_R1, self.ADDRESS + 0x200)
    self.uc.mem_write(self.ADDRESS, self.ARM_CODE_STR)
    with self.assertRaises(UcError) as ctx:
      self.uc.emu_start(self.ADDRESS, self.ADDRESS + len(self.ARM_CODE_LDR))
    self.assertEqual(ctx.exception.errno, ErrNo.WRITE_PROT)

  def test_split_regions(self):
    self.uc.mem_map(self.ADDRESS, self.SIZE, UC_PROT_NONE)
    self.uc.mem_protect(self.ADDRESS + 0x200, 0x400, UC_PROT_EXEC)

    regs = self.get_mem_perm_regions()
    self.assertEqual(len(regs), 3)
    regs = self.get_mem_regions()
    self.assertEqual(len(regs), 1)

    self.uc.mem_unmap(self.ADDRESS + 0x400, 0x400)

    regs = self.get_mem_perm_regions()
    self.assertEqual(len(regs), 3)
    self.assertEqual(regs[0].begin, self.ADDRESS)
    self.assertEqual(regs[0].end, self.ADDRESS + 0x1ff)
    self.assertEqual(regs[0].perm, UC_PROT_NONE)
    self.assertEqual(regs[1].begin, self.ADDRESS + 0x200)
    self.assertEqual(regs[1].end, self.ADDRESS + 0x3ff)
    self.assertEqual(regs[1].perm, UC_PROT_EXEC)
    self.assertEqual(regs[2].begin, self.ADDRESS + 0x800)
    self.assertEqual(regs[2].end, self.ADDRESS + 0xfff)
    self.assertEqual(regs[2].perm, UC_PROT_NONE)

    regs = self.get_mem_regions()
    self.assertEqual(len(regs), 2)
    self.assertEqual(regs[0].begin, self.ADDRESS)
    self.assertEqual(regs[0].end, self.ADDRESS + 0x3ff)
    self.assertEqual(regs[0].perm, UC_PROT_UNK)
    self.assertEqual(regs[1].begin, self.ADDRESS + 0x800)
    self.assertEqual(regs[1].end, self.ADDRESS + 0xfff)
    self.assertEqual(regs[1].perm, UC_PROT_UNK)

  def test_mem_protect_splitting(self):
    self.uc.mem_map(self.ADDRESS, self.SIZE, UC_PROT_NONE)
    regs = self.get_mem_regions()
    self.assertEqual(len(regs), 1)
    self.assertEqual(regs[0].perm, UC_PROT_UNK)
    regs = self.get_mem_perm_regions()
    self.assertEqual(len(regs), 1)
    self.assertEqual(regs[0].perm, UC_PROT_NONE)

    self.uc.mem_protect(self.ADDRESS + 0x400, 0x800, UC_PROT_EXEC)
    regs = self.get_mem_regions()
    self.assertEqual(len(regs), 1)
    regs = self.get_mem_perm_regions()
    self.assertEqual(len(regs), 3)
    self.assertEqual(regs[0].perm, UC_PROT_NONE)
    self.assertEqual(regs[1].perm, UC_PROT_EXEC)
    self.assertEqual(regs[2].perm, UC_PROT_NONE)

    self.uc.mem_unmap(self.ADDRESS + 0x400, 0x800)
    regs = self.get_mem_regions()
    self.assertEqual(len(regs), 2)
    regs = self.get_mem_perm_regions()
    self.assertEqual(len(regs), 2)

    self.uc.mem_unmap(self.ADDRESS + 0xc00, 0x400)
    regs = self.get_mem_regions()
    self.assertEqual(len(regs), 1)
    regs = self.get_mem_perm_regions()
    self.assertEqual(len(regs), 1)

    self.uc.mem_unmap(self.ADDRESS, 0x400)
    regs = self.get_mem_regions()
    self.assertEqual(len(regs), 0)
    regs = self.get_mem_perm_regions()
    self.assertEqual(len(regs), 0)

  def test_perm_protect_slicing_simple(self):
    self.uc.mem_map(self.ADDRESS, self.SIZE, UC_PROT_NONE)
    self.uc.mem_protect(self.ADDRESS + 0x100, 0x400, UC_PROT_EXEC)
    regs = self.get_mem_perm_regions()
    self.assertEqual(len(regs), 3)

    self.uc.mem_protect(self.ADDRESS + 0x21, 0x102, UC_PROT_WRITE)
    regs = self.get_mem_perm_regions()
    self.assertEqual(len(regs), 4)
    for i, (b, e, p) in enumerate([(self.ADDRESS, self.ADDRESS + 0x20, UC_PROT_NONE),
                                 (self.ADDRESS + 0x21, self.ADDRESS + 0x122, UC_PROT_WRITE),
                                 (self.ADDRESS + 0x123, self.ADDRESS + 0x4ff, UC_PROT_EXEC),
                                 (self.ADDRESS + 0x500, self.ADDRESS + self.SIZE -1, UC_PROT_NONE)
                                 ]):
      self.assertEqual(regs[i].begin, b)
      self.assertEqual(regs[i].end, e)
      self.assertEqual(regs[i].perm, p)

  def test_perm_protect_slicing_extended(self):
    self.uc.mem_map(self.ADDRESS, self.SIZE, UC_PROT_NONE)
    self.uc.mem_protect(self.ADDRESS, 0x400, UC_PROT_EXEC)
    regs = self.get_mem_perm_regions()
    self.assertEqual(len(regs), 2)

    m_ranges = [(self.ADDRESS + 0x311, 0x1f, UC_PROT_WRITE),
                (self.ADDRESS + 0x395, 0x1b, UC_PROT_EXEC | UC_PROT_WRITE),
                (self.ADDRESS + 0x879, 0x19, UC_PROT_WRITE),
                (self.ADDRESS + 0x332, 0x1e, UC_PROT_READ),
                (self.ADDRESS + 0x330, 0x20, UC_PROT_READ),
                (self.ADDRESS + 0x353, 0x1f, UC_PROT_WRITE | UC_PROT_READ),
                (self.ADDRESS + 0x374, 0x1c, UC_PROT_EXEC),
                (self.ADDRESS + 0x36f, 0x1d, UC_PROT_READ),
                (self.ADDRESS + 0x416, 0x1a,
                 UC_PROT_WRITE | UC_PROT_EXEC | UC_PROT_READ),
               ]
    for r in m_ranges:
      self.uc.mem_protect(r[0], r[1], r[2])

    expected_ranges = [(self.ADDRESS,        self.ADDRESS + 0x310, UC_PROT_EXEC),
                       (self.ADDRESS + 0x311, self.ADDRESS + 0x32f, UC_PROT_WRITE),
                       (self.ADDRESS + 0x330, self.ADDRESS + 0x34f, UC_PROT_READ),
                       (self.ADDRESS + 0x350, self.ADDRESS + 0x352, UC_PROT_EXEC),
                       (self.ADDRESS + 0x353, self.ADDRESS + 0x36e, UC_PROT_WRITE | UC_PROT_READ),
                       (self.ADDRESS + 0x36f, self.ADDRESS + 0x38b, UC_PROT_READ),
                       (self.ADDRESS + 0x38c, self.ADDRESS + 0x38f, UC_PROT_EXEC),
                       (self.ADDRESS + 0x390, self.ADDRESS + 0x394, UC_PROT_EXEC),
                       (self.ADDRESS + 0x395, self.ADDRESS + 0x3af, UC_PROT_EXEC | UC_PROT_WRITE),
                       (self.ADDRESS + 0x3b0, self.ADDRESS + 0x3ff, UC_PROT_EXEC),
                       (self.ADDRESS + 0x400, self.ADDRESS + 0x415, UC_PROT_NONE),
                       (self.ADDRESS + 0x416, self.ADDRESS + 0x42f, UC_PROT_EXEC | UC_PROT_WRITE | UC_PROT_READ),
                       (self.ADDRESS + 0x430, self.ADDRESS + 0x878, UC_PROT_NONE),
                       (self.ADDRESS + 0x879, self.ADDRESS + 0x891, UC_PROT_WRITE),
                       (self.ADDRESS + 0x892, self.ADDRESS + 0xfff, UC_PROT_NONE),
                      ]
    regs = self.get_mem_regions()
    self.assertEqual(len(regs), 1)
    regs = self.get_mem_perm_regions()
    self.assertEqual(len(regs), len(expected_ranges))

    for i in range(len(expected_ranges)):
      self.assertEqual(regs[i].begin, expected_ranges[i][0])
      self.assertEqual(regs[i].end, expected_ranges[i][1])
      self.assertEqual(regs[i].perm, expected_ranges[i][2])

    expected_ranges = [(self.ADDRESS,        self.ADDRESS + 0x310, UC_PROT_EXEC),
                       (self.ADDRESS + 0x311, self.ADDRESS + 0x31f, UC_PROT_WRITE),
                       (self.ADDRESS + 0x320, self.ADDRESS + 0x3ab, UC_PROT_READ),
                       (self.ADDRESS + 0x3ac, self.ADDRESS + 0x3af, UC_PROT_EXEC | UC_PROT_WRITE),
                       (self.ADDRESS + 0x3b0, self.ADDRESS + 0x3ff, UC_PROT_EXEC),
                       (self.ADDRESS + 0x400, self.ADDRESS + 0x415, UC_PROT_NONE),
                       (self.ADDRESS + 0x416, self.ADDRESS + 0x42f, UC_PROT_EXEC | UC_PROT_WRITE | UC_PROT_READ),
                       (self.ADDRESS + 0x430, self.ADDRESS + 0x878, UC_PROT_NONE),
                       (self.ADDRESS + 0x879, self.ADDRESS + 0x891, UC_PROT_WRITE),
                       (self.ADDRESS + 0x892, self.ADDRESS + 0xfff, UC_PROT_NONE),
                      ]

    self.uc.mem_protect(self.ADDRESS + 0x320, 140, UC_PROT_READ)
    regs = self.get_mem_perm_regions()
    self.assertEqual(len(regs), len(expected_ranges))

    for i in range(len(expected_ranges)):
      self.assertEqual(regs[i].begin, expected_ranges[i][0])
      self.assertEqual(regs[i].end, expected_ranges[i][1])
      self.assertEqual(regs[i].perm, expected_ranges[i][2])

  def test_range_permissins(self):
    # do nothing memory hook as a workaround for issue that READ access is not checked for
    # executed memory range.
    self.uc.hook_add(UC_HOOK_MEM_WRITE, lambda a, b, c, d, e, f, g: b + c)

    self.uc.mem_map(self.ADDRESS, self.SIZE, UC_PROT_NONE)
    self.uc.mem_write(self.ADDRESS + 4, self.ARM_CODE_LDR)
    regs = self.get_mem_perm_regions()
    self.assertEqual(len(regs), 1)
    regs = self.get_mem_regions()
    self.assertEqual(len(regs), 1)

    with self.assertRaises(UcError) as ctx:
      self.uc.emu_start(self.ADDRESS + 4,
                        self.ADDRESS + 4 + len(self.ARM_CODE_LDR))
    self.assertEqual(ctx.exception.errno, ErrNo.FETCH_PROT)

    self.uc.mem_protect(self.ADDRESS + 4, 10, UC_PROT_EXEC)
    regs = self.get_mem_perm_regions()
    self.assertEqual(len(regs), 3)

    self.uc.reg_write(UC_ARM_REG_R1, self.ADDRESS + 4)
    with self.assertRaises(UcError) as ctx:
      self.uc.emu_start(self.ADDRESS + 4,
                        self.ADDRESS + 4 + len(self.ARM_CODE_LDR))
    self.assertEqual(ctx.exception.errno, ErrNo.READ_PROT)


    self.uc.reg_write(UC_ARM_REG_R1, self.ADDRESS + 0x120)
    with self.assertRaises(UcError) as ctx:
      self.uc.emu_start(self.ADDRESS + 4,
                        self.ADDRESS + 4 + len(self.ARM_CODE_LDR))
    self.assertEqual(ctx.exception.errno, ErrNo.READ_PROT)

    self.uc.mem_protect(self.ADDRESS + 0x120, 10, UC_PROT_WRITE)
    regs = self.get_mem_perm_regions()
    self.assertEqual(len(regs), 5)

    with self.assertRaises(UcError) as ctx:
      self.uc.emu_start(self.ADDRESS + 4,
                        self.ADDRESS + 4 + len(self.ARM_CODE_LDR))
    self.assertEqual(ctx.exception.errno, ErrNo.READ_PROT)

    self.uc.mem_protect(self.ADDRESS + 0x120, 10, UC_PROT_READ)
    regs = self.get_mem_perm_regions()
    self.assertEqual(len(regs), 5)
    self.assertEqual(regs[3].begin, self.ADDRESS + 0x120)
    self.assertEqual(regs[3].end, self.ADDRESS + 0x129)
    self.assertEqual(regs[3].perm, UC_PROT_READ)

    self.uc.emu_start(self.ADDRESS + 4,
                      self.ADDRESS + 4 + len(self.ARM_CODE_LDR))

    self.uc.mem_write(self.ADDRESS + 4, self.ARM_CODE_STR)
    with self.assertRaises(UcError) as ctx:
      self.uc.emu_start(self.ADDRESS + 4,
                        self.ADDRESS + 4 + len(self.ARM_CODE_STR))
    self.assertEqual(ctx.exception.errno, ErrNo.WRITE_PROT)

    self.uc.mem_protect(self.ADDRESS + 0x133, 10, UC_PROT_WRITE)
    regs = self.get_mem_perm_regions()
    self.assertEqual(len(regs), 7)

    self.uc.reg_write(UC_ARM_REG_R1, self.ADDRESS + 0x137)
    self.uc.emu_start(self.ADDRESS + 4,
                      self.ADDRESS + 4 + len(self.ARM_CODE_STR))

  def test_per_word_permissions(self):
    # do nothing memory hook as a workaround for issue that READ access is not checked for
    # executed memory range.
    self.uc.hook_add(UC_HOOK_MEM_WRITE, lambda a, b, c, d, e, f, g: b + c)

    self.uc.mem_map(self.ADDRESS, self.SIZE, UC_PROT_NONE)
    self.uc.mem_write(self.ADDRESS + 4, self.ARM_CODE_LDR)
    regs = self.get_mem_perm_regions()
    self.assertEqual(len(regs), 1)
    regs = self.get_mem_regions()
    self.assertEqual(len(regs), 1)

    self.uc.mem_protect(self.ADDRESS + 4, 10, UC_PROT_EXEC)
    regs = self.get_mem_perm_regions()
    self.assertEqual(len(regs), 3)

    self.uc.mem_protect(self.ADDRESS + 0x110, 4, UC_PROT_READ)
    self.uc.mem_protect(self.ADDRESS + 0x114, 4, UC_PROT_WRITE)
    self.uc.mem_protect(self.ADDRESS + 0x118, 4, UC_PROT_READ)

    self.uc.reg_write(UC_ARM_REG_R1, self.ADDRESS + 0x110)
    self.uc.emu_start(self.ADDRESS + 4,
                      self.ADDRESS + 4 + len(self.ARM_CODE_LDR))
    self.uc.reg_write(UC_ARM_REG_R1, self.ADDRESS + 0x114)
    with self.assertRaises(UcError) as ctx:
      self.uc.emu_start(self.ADDRESS + 4,
                        self.ADDRESS + 4 + len(self.ARM_CODE_LDR))
    self.assertEqual(ctx.exception.errno, ErrNo.READ_PROT)
    self.uc.reg_write(UC_ARM_REG_R1, self.ADDRESS + 0x118)
    self.uc.emu_start(self.ADDRESS + 4,
                      self.ADDRESS + 4 + len(self.ARM_CODE_LDR))

    self.uc.mem_write(self.ADDRESS + 4, self.ARM_CODE_STR)

    self.uc.reg_write(UC_ARM_REG_R1, self.ADDRESS + 0x110)
    with self.assertRaises(UcError) as ctx:
      self.uc.emu_start(self.ADDRESS + 4,
                        self.ADDRESS + 4 + len(self.ARM_CODE_STR))
    self.assertEqual(ctx.exception.errno, ErrNo.WRITE_PROT)
    self.uc.reg_write(UC_ARM_REG_R1, self.ADDRESS + 0x114)
    self.uc.emu_start(self.ADDRESS + 4,
                      self.ADDRESS + 4 + len(self.ARM_CODE_STR))
    self.uc.reg_write(UC_ARM_REG_R1, self.ADDRESS + 0x118)
    with self.assertRaises(UcError) as ctx:
      self.uc.emu_start(self.ADDRESS + 4,
                        self.ADDRESS + 4 + len(self.ARM_CODE_STR))
    self.assertEqual(ctx.exception.errno, ErrNo.WRITE_PROT)


if __name__ == '__main__':
  unittest.main()

