'''
Patch for Elpis CB_B 7378

CB_B 9188 fails on Elpis systems with Samsung RAMs, the CPU will crash and reboot during hwinit
even if the glitch attack succeeds. The reason: CB_B simply doesn't support it.

The Elpis CB_B 7378 loader also can't be used in a glitch attack as is because it
expects a different CD than the one normally used for glitching. Also, the Glitch2
9188 loads the CD as plaintext, while 7378 has to decrypt it first. There are other
code differences here and there, but one of the more important ones is that POST codes
don't get output (typical retail CB_B behavior), which throws off glitch attempts and
provides no useful information.

This file patches 7378 so that it can load the normal unsigned CD,
and also adds POST codes back.
'''

import struct

class FreeSpaceArea():
    def __init__(self, start_address: int, end_address: int):
        self._start_address = start_address
        self._end_address = end_address
        self._head = start_address

        # function_name -> address
        self._function_map = {}
    
    def head(self):
        return self._head
    
    def func(self, name: str):
        return self._function_map[name]

    def create_func_and_set_head(self, name: str, end_head: int):
        '''
        Assigns a function name at the current head position, then
        sets the head position to `end_head`.
        '''
        if end_head > self._end_address:
            raise RuntimeError("end_head went out of bounds")

        self._function_map[name] = self._head

        print(f"create_func_and_set_head: {name} 0x{self._head:04x} -> 0x{end_head:04x}")
        self._head = end_head



def assert_address_32bit_aligned(address: int):
    if (address & 3) != 0:
        raise RuntimeError(f"address not 32-bit aligned: {address:08x}")

def assemble_post_function(cbb_image: bytes, address: int) -> tuple:
    '''
    Common POST function. Takes POST code in r4. r3 will be destroyed.
    '''
    assert_address_32bit_aligned(address)

    post_fcn = bytes([
        # set r3 = 0x8000020000061010 (POST output)
        0x38, 0x60, 0x02, 0x00,  # li r3,0x200
        0x64, 0x63, 0x80, 0x00,  # oris r3,r3,0x8000
        0x78, 0x63, 0x07, 0xc6,  # rldicr r3,r3,0x20,0x1f
        0x64, 0x63, 0x00, 0x06,  # oris r3,r3,0x6

        # write (postcode << 56) (in r4) to r3
        0x78, 0x84, 0xc1, 0xc6, # rldicr r4,r4,0x38,0x7
        0xf8, 0x83, 0x10, 0x10, # std r4,(r3)

        # return
        0x4e, 0x80, 0x00, 0x20  # blr
    ])

    end_addr = address + len(post_fcn)
    cbb_image[address:end_addr] = post_fcn

    return cbb_image, end_addr

def assemble_nop(cbb_image: bytes, address: int) -> tuple:
    '''
    `nop` (=`ori r0,r0,0`)
    '''
    assert_address_32bit_aligned(address)

    nopcode = bytes([
        0x60, 0x00, 0x00, 0x00 # ori r0,r0,0 - does nothing
    ])
    cbb_image[address:address+4] = nopcode
    return (cbb_image, address + 4)

def assemble_li_r4(cbb_image: bytes, address: int, imm8: int) -> tuple:
    '''
    `li r4,imm8`
    '''
    assert_address_32bit_aligned(address)

    if (0 <= imm8 <= 0xFF) is False:
        raise RuntimeError("li r4 takes imm8 argument (sorry, 16-bit likers)")
    cbb_image[address:address+4] = struct.pack(">BBBB", 0x38, 0x80, 0x00, imm8)
    return (cbb_image, address + 4)

def assemble_branch_to_link_register(cbb_image: bytes, address: int) -> tuple:
    assert_address_32bit_aligned(address)
    
    opcode = bytes([
        0x4E, 0x80, 0x00, 0x20
    ])
    cbb_image[address:address+4] = opcode
    return (cbb_image, address + 4)

def assemble_branch_generic(cbb_image: bytes, address: int, destination_address: int, with_link: False) -> tuple:
    assert_address_32bit_aligned(address)
    assert_address_32bit_aligned(destination_address)
    
    address_diff = destination_address - address
    if (-0x1FFFFFFF <= address_diff <= 0x1FFFFFFF) is False:
        raise RuntimeError("branch imm26 out of range")
    
    address_encoded = struct.unpack(">I", struct.pack(">i", address_diff))[0]
    address_encoded &= 0x03FFFFFC
    address_encoded |= 0x48000000
    if with_link is True:
        address_encoded |= 1

    cbb_image[address:address+4] = struct.pack(">I", address_encoded)
    return (cbb_image, address+4)

def assemble_branch_with_link(cbb_image: bytes, address: int, destination_address: int) -> tuple:
    '''
    Assemble `bl` opcode.

    DANGER: Remember that this is RISC! If you use `bl`, it WILL overwrite the contents of `lr`.
    If you don't preserve `lr` correctly your code will crash!
    '''
    return assemble_branch_generic(cbb_image, address, destination_address, True)

def assemble_branch(cbb_image: bytes, address: int, destination_address: int) -> tuple:
    return assemble_branch_generic(cbb_image, address, destination_address, False)

def assemble_panic(cbb_image: bytes, address: int, post_code: int, panic_fcn_address: int) -> tuple:
    assert_address_32bit_aligned(address)

    next_ptr = address
    cbb_image, next_ptr = assemble_li_r4(cbb_image, next_ptr, post_code)
    cbb_image, next_ptr = assemble_branch(cbb_image, next_ptr, panic_fcn_address)
    return cbb_image, next_ptr

def assemble_panic_function(cbb_image: bytes, address: int, post_fcn_address: int) -> tuple:
    assert_address_32bit_aligned(address)

    cur_address = address

    cbb_image, cur_address = assemble_branch_with_link(cbb_image, address, post_fcn_address)

    infinite_death_spiral = bytes([
        0x38, 0x00, 0x00, 0x00,  # li r0,0x00
        0x7c, 0x18, 0x23, 0xa6,  # mtspr CMPE,r0
        0x4b, 0xff, 0xff, 0xf8,  # b -8 - loop forever
    ])

    end_address = cur_address+len(infinite_death_spiral)
    cbb_image[cur_address:end_address] = infinite_death_spiral

    return cbb_image, end_address

def assemble_post_call(cbb_image: bytes, address: int, post_fcn_address: int, post_code: int):
    assert_address_32bit_aligned(address)

    cur_address = address
    cbb_image, cur_address = assemble_li_r4(cbb_image, cur_address, post_code)
    cbb_image, cur_address = assemble_branch_with_link(cbb_image, cur_address, post_fcn_address)

    return cbb_image, cur_address

def fill_nops_between(cbb_image: bytes, address: int, until_address: int):
    assert_address_32bit_aligned(address)
    assert_address_32bit_aligned(until_address)

    if address > until_address:
        raise RuntimeError("address already past until_address")
    
    pos = address
    while pos < until_address:
        cbb_image, pos = assemble_nop(cbb_image, pos)

    return cbb_image, pos

# ------------------------------------------------------------------------------------------------

def make_post_codecave(cbb_image: bytes,
                       free_space_area: FreeSpaceArea,
                       insert_address: int,
                       post_code: int) -> bytes:
    assert_address_32bit_aligned(insert_address)
    post_fcn_address = free_space_area.func("post")

    # read instruction we're about to overwrite
    old_instruction = cbb_image[insert_address:insert_address+4]

    # assemble codecave in free space area
    pos = free_space_area.head()
    codecave_pos = pos
    cbb_image, pos = assemble_post_call(cbb_image, pos, post_fcn_address, post_code)
    cbb_image[pos:pos+4] = old_instruction
    pos += 4
    cbb_image, pos = assemble_branch(cbb_image, pos, insert_address + 4)
    free_space_area.create_func_and_set_head(f"post_{post_code:02x}_codecave", pos)
    cbb_image, _ = assemble_branch(cbb_image, insert_address, codecave_pos)

    return cbb_image

def patch_entry_point(cbb_image: bytes, free_space_area: FreeSpaceArea) -> bytes:
    # 0x4E8: call to fusechecks and security engine init
    # we remove the call to fusechecks and instead use this area to POST 0x22 and 0x2F.
    # also, we move the call to init_seceng (at 0x6EE8) up a bit.
    pos = 0x4E8
    cbb_image, pos = assemble_post_call(cbb_image, pos, free_space_area.func("post"), 0x22)
    cbb_image, pos = assemble_branch_with_link(cbb_image, pos, 0x6ee8)
    cbb_image, pos = assemble_post_call(cbb_image, pos, free_space_area.func("post"), 0x2F)

    # fill NOPs until 0x500, where execution picks up again (code is about to relocate itself)
    fill_nops_between(cbb_image, pos, 0x500)

    return cbb_image

def patch_after_relocation_steps(cbb_image: bytes, free_space_area: FreeSpaceArea) -> bytes:
    '''
    Patch post-relocation steps at 0x06C0.
    '''
    post_addr = free_space_area.func("post")
    panic_fcn_address = free_space_area.func("panic")

    # create new function that POSTs 0x23, 0x2E before running hwinit_proxy (at 0x7110)
    post_23_2e_trampoline = free_space_area.head()
    pos = post_23_2e_trampoline
    # `mfspr r28,LR` - need to preserve LR or bad things happen.
    # r28 is normally used by CB_A to pass us decryption keys, now unused,
    # so we should be safe using it
    cbb_image[pos:pos+4] = bytes([0x7f, 0x88, 0x02, 0xa6])
    pos += 4
    cbb_image, pos = assemble_post_call(cbb_image, pos, post_addr, 0x23)
    cbb_image, pos = assemble_post_call(cbb_image, pos, post_addr, 0x2E)
    # `mtspr r28,LR` - restore return address to LR
    cbb_image[pos:pos+4] = bytes([0x7f, 0x88, 0x03, 0xa6])
    pos += 4
    # `or r3,r31,r31`` must be put here because calls to the POST function overwrote r3.
    cbb_image[pos:pos+4] = bytes([0x7f, 0xe3, 0xfb, 0x78])
    pos += 4
    cbb_image, pos = assemble_branch(cbb_image, pos, 0x7110)
    free_space_area.create_func_and_set_head("hwinitproxy_trampoline", pos)

    # change call at 0x6D0 to point to this rerouted function
    # instead of calling hwinit_proxy directly
    assemble_branch_with_link(cbb_image, 0x06D0, post_23_2e_trampoline)

    # 0x768 is a panic case - it's where execution ends up if RAM size is bad
    assemble_panic(cbb_image, 0x768, 0xAF, panic_fcn_address)

    return cbb_image

def patch_cd_load_and_jump(cbb_image: bytes, free_space_area: FreeSpaceArea) -> bytes:
    '''
    Patch CD load/verify/jump routine at 0x6FA8
    '''
    post_fcn_address  = free_space_area.func("post")
    panic_fcn_address = free_space_area.func("panic")

    # put POST 0x30 (VERIFY_OFFSET_4BL) at 0x7388
    # this isn't always validated, so it may be normal if you don't see 0x30 before 0x31
    cbb_image = make_post_codecave(cbb_image, free_space_area, 0x7388, 0x30)

    # 0x73a4: panic because of invalid offset (POST 0xAA)
    # build function stub in free space then put a branch at 0x73A4
    pos = free_space_area.head()
    panic_aa_stub = pos
    cbb_image, pos = assemble_panic(cbb_image, pos, 0xAA, panic_fcn_address)
    cbb_image, _ = assemble_branch(cbb_image, 0x73A4, panic_aa_stub)
    free_space_area.create_func_and_set_head("panic_aa_stub", pos)

    # create codecave so we can POST 0x31
    cbb_image = make_post_codecave(cbb_image, free_space_area, 0x73A8, 0x31)

    # put POST 0x32 at 0x73c0
    assemble_post_call(cbb_image, 0x73c0, post_fcn_address, 0x32)

    # 0x73EC: the typical "CD" exploit code has its entrypoint at 0x270,
    # which is invalid on 7378 (expects at least 0x310).
    # so let's restore 0x270 as the minimum value.
    cbb_image[0x73EE:0x73F0] = bytes([0x02, 0x70])

    # 0x7430: panic because CD header is invalid
    pos = free_space_area.head()
    panic_ab_stub = pos
    cbb_image, pos = assemble_panic(cbb_image, pos, 0xAB, panic_fcn_address)
    cbb_image, _ = assemble_branch(cbb_image, 0x7430, panic_ab_stub)
    free_space_area.create_func_and_set_head("panic_ab_stub", pos)

    # create codecave so we can POST 0x33
    cbb_image = make_post_codecave(cbb_image, free_space_area, 0x7434, 0x33)

    # at 0x745c, CD has been copied to RAM.
    # all we need to do is count POSTs 34-37,39 and then go directly to PCI init
    # because HMAC/SHA verification is no longer necessary
    pos = 0x745C
    cbb_image, pos = assemble_post_call(cbb_image, pos, post_fcn_address, 0x34)
    cbb_image, pos = assemble_post_call(cbb_image, pos, post_fcn_address, 0x35)
    cbb_image, pos = assemble_post_call(cbb_image, pos, post_fcn_address, 0x36)
    cbb_image, pos = assemble_post_call(cbb_image, pos, post_fcn_address, 0x37)
    cbb_image, pos = assemble_post_call(cbb_image, pos, post_fcn_address, 0x39)
    cbb_image, pos = assemble_post_call(cbb_image, pos, post_fcn_address, 0x3B)
    cbb_image, pos = assemble_branch_with_link(cbb_image, pos, 0x71a0) # call pci_init
    cbb_image, pos = assemble_branch(cbb_image, pos, 0x75cc) # return to code below

    # 0x75cc - 0x762c follows pci_init and is useless for our purposes.
    # it's useful if you're calling a normal CD, but we're calling the exploit
    # payload instead, so it's gotta go.
    # so let's skip directly to 0x762C, where we'll put POST 0x3A.
    # (we won't be using r5/r6 when patching cd_jump.)
    cbb_image, _ = assemble_branch(cbb_image, 0x75CC, 0x762C)
    cbb_image, _ = assemble_post_call(cbb_image, 0x762C, post_fcn_address, 0x3A)


    return cbb_image

def patch_cd_jump(cbb_image: bytes):
    # 0xE20 is cd_jump
    # inputs are:
    # r3 - entry point, gets futzed about and ends up in CMPE
    # r4 - gets moved to r31
    # r5 - does something, useless
    # r6 - jump target, goes into LR
    #
    # on 9188:
    # r3 - entry point
    # r4 - gets moved to r31
    #
    # so this is basically obfuscated/fucked around with.

    # assemble 9188 preamble
    cdjump_9188_preamble = [
        0x54, 0x63, 0x04, 0x3e, # rlwinm 3,r3,0x0,0x10,0x1f
        0x3c, 0x63, 0x04, 0x00, # addis r3,r3,0x400
        0x7c, 0x68, 0x03, 0xa6, # mtspr LR,r3
        0x7c, 0x9f, 0x23, 0x78, # or r31,r4,r4
    ]

    # cd_jump identical past 0xE54, so we'll land there
    cdjump_preamble_inject_end_point = 0xE54
    cdjump_preamble_inject_point = cdjump_preamble_inject_end_point - len(cdjump_9188_preamble)
    cbb_image[cdjump_preamble_inject_point:cdjump_preamble_inject_end_point] = cdjump_9188_preamble

    # add immediate branch at 0xE20 to skip past now-useless opcodes
    assemble_branch(cbb_image, 0xE20, cdjump_preamble_inject_point)

def patch_exception_handler(cbb_image: bytes):
    # basically duplicates the "unexpected IRQ" handler, but with POST code 0x81 ("machine check")
    new_exception_handler = [
        0x38, 0x60, 0x00, 0x81, # li r3, 0x81 - this is our POST code
        0x78, 0x63, 0xc1, 0xc6, # rldicr r3,r3,0x38,0x7
        0x38, 0x80, 0x02, 0x00, # li r4,0x200
        0x64, 0x84, 0x80, 0x00, # oris r4,r4,0x8000
        0x78, 0x84, 0x07, 0xc6, # rldicr r4,r4,0x20,0x1f
        0x64, 0x84, 0x00, 0x06, # oris r4,r4,r6
        0xf8, 0x64, 0x10, 0x10, # std r3,(r4)
        0x38, 0x00, 0x00, 0x00, # li r0,0x00
        0x7c, 0x18, 0x23, 0xa6, # mtspr CMPE,r0
        0x4b, 0xff, 0xff, 0xf8, # b -8
    ]

    cbb_image[0x780:0x780+len(new_exception_handler)] = new_exception_handler


def do_patches(cbb_image: bytes) -> bytes:
    # first thing:
    # 0x4f8 calls a big function that's patched out on CB_B 9188, and it's responsible for
    # doing fusechecks and other undesirable stuff. so NOP that out
    assemble_nop(cbb_image, 0x4f8)

    # 0x4f8 called 0x6b58, which is no longer used.
    # create our free space area and put two important functions (post and panic) there.
    # we'll continue creating stubs in this free space area for other patches later on.
    free_space_area = FreeSpaceArea(0x6B58, 0x6EE4)
    head = free_space_area.head()
    post_fcn_address = head
    cbb_image, head = assemble_post_function(cbb_image, head)
    free_space_area.create_func_and_set_head("post", head)
    cbb_image, head = assemble_panic_function(cbb_image, head, post_fcn_address)
    free_space_area.create_func_and_set_head("panic", head)

    # now let's patch some functions
    patch_entry_point(cbb_image, free_space_area)
    patch_after_relocation_steps(cbb_image, free_space_area)
    patch_exception_handler(cbb_image)
    patch_cd_load_and_jump(cbb_image, free_space_area)
    patch_cd_jump(cbb_image)

    # vanity string at end of free space
    vanity_string = b"wurthless elektroniks presents elpiss v2\x00"
    head = free_space_area.head()
    cbb_image[head:head+len(vanity_string)] = vanity_string

    return cbb_image

def main():
    # load cbb_7378_clean.bin
    cbb_image = None
    with open("cbb_7378_clean.bin", "rb") as f:
        cbb_image = f.read()

    cbb_image = bytearray(cbb_image)

    # apply patches
    cbb_image = do_patches(cbb_image)

    # write patched file to cbb_7378_patched.bin
    with open("cbb_7378_patched.bin", "wb") as f:
        f.write(cbb_image)

if __name__ == '__main__':
    main()
