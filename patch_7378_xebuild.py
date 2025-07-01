'''
Build xeBuild-compatible patched version of CB_B 7378

Unsurprisingly the set of patches generated only works if CD is decrypted, and it isn't
when using a xeBuild image. While patch_7378.py is more useful for getting to XeLL, this
is more useful for running an actual NAND build.

We can't skip the fusecheck and decryption functions like patch_7378.py does,
and we need to add in POST cases for fusecheck failures, so we need to be much
more aggressive with how we manage code space.

Status: Can boot the system to XeLL, but crashes when trying to start the kernel.
'''

from patcher import *

def patch_entry_point(cbb_image: bytes, free_space_area: FreeSpaceArea) -> bytes:
    # POST 0x20 as we start code execution
    cbb_image = make_post_codecave(cbb_image, free_space_area, 0x3ec, 0x20)

    # POST 0x2F at 0x500
    cbb_image = make_post_codecave(cbb_image, free_space_area, 0x500, 0x2F)

    return cbb_image

def patch_fuse_check(cbb_image: bytes, free_space_area: FreeSpaceArea) -> bytes:
    # fusecheck @ 0x6b58

    panic_fcn_address = free_space_area.func("panic")

    # POST 0x21 at 0x6B80 once r4/r3 (passed as arguments) are safe
    cbb_image = make_post_codecave(cbb_image, free_space_area, 0x6b80, 0x21)

    # this is where the 2BL revocation check normally lives,
    # but we'll be skipping over it. instead, put some panic cases there
    quintet_of_panics_area = FreeSpaceArea(0x6D1C, 0x6D44)

    # panic @ 0x6BF4 - 0x9B
    pos = quintet_of_panics_area.head()
    panic_9b_address = pos
    cbb_image, pos = assemble_panic(cbb_image, pos, 0x9B, panic_fcn_address)
    cbb_image, _ = assemble_branch(cbb_image, 0x6BF4, panic_9b_address)
    quintet_of_panics_area.create_func_and_set_head("panic_9b", pos)

    # panic @ 0x6C38  - 0x9C
    panic_9c_address = pos
    cbb_image, pos = assemble_panic(cbb_image, pos, 0x9C, panic_fcn_address)
    cbb_image, _ = assemble_branch(cbb_image, 0x6C38, panic_9c_address)
    quintet_of_panics_area.create_func_and_set_head("panic_9c", pos)

    # panic @ 0x6C70 - 0x9E
    panic_9e_address = pos
    cbb_image, pos = assemble_panic(cbb_image, pos, 0x9E, panic_fcn_address)
    cbb_image, _ = assemble_branch(cbb_image, 0x6C70, panic_9e_address)
    quintet_of_panics_area.create_func_and_set_head("panic_9e", pos)

    # panic @ 0x6C98 - 0x9F
    panic_9f_address = pos
    cbb_image, pos = assemble_panic(cbb_image, pos, 0x9F, panic_fcn_address)
    cbb_image, _ = assemble_branch(cbb_image, 0x6C98, panic_9f_address)
    quintet_of_panics_area.create_func_and_set_head("panic_9f", pos)

    # panic @ 0x6CC8 - 0x9D
    panic_9d_address = pos
    cbb_image, pos = assemble_panic(cbb_image, pos, 0x9D, panic_fcn_address)
    cbb_image, _ = assemble_branch(cbb_image, 0x6CC8, panic_9d_address)
    quintet_of_panics_area.create_func_and_set_head("panic_9d", pos)

    # 0x6D0C: NOP out this bne instruction to skip the 2BL revocation fusecheck
    cbb_image, _ = assemble_nop(cbb_image, 0x6D0C)

    # store a couple more panics in code space we're about to free up
    duet_of_panics_area = FreeSpaceArea(0x6e40, 0x6e54)
    pos = duet_of_panics_area.head()

    # panic @ 0x6D78 - 0xB0
    panic_b0_address = pos
    cbb_image, pos = assemble_panic(cbb_image, pos, 0xB0, panic_fcn_address)
    cbb_image, _ = assemble_branch(cbb_image, 0x6D78, panic_b0_address)
    duet_of_panics_area.create_func_and_set_head("panic_b0", pos)

    # panic @ 0x6DEC - 0xA1
    panic_a1_address = pos
    cbb_image, pos = assemble_panic(cbb_image, pos, 0xA1, panic_fcn_address)
    cbb_image, _ = assemble_branch(cbb_image, 0x6DEC, panic_a1_address)
    duet_of_panics_area.create_func_and_set_head("panic_a1", pos)

    # 0x6E3C: skip straight to offset validation function
    # so we don't prematurely panic verifying the secure ROM
    cbb_image, _ = assemble_branch(cbb_image, 0x6e3c, 0x6e54)

    pos = free_space_area.head()

    # panic @ 0x6e6c - 0xA3
    panic_a3_address = pos
    cbb_image, pos = assemble_panic(cbb_image, pos, 0xA3, panic_fcn_address)
    cbb_image, _ = assemble_branch(cbb_image, 0x6E6C, panic_a3_address)
    free_space_area.create_func_and_set_head("panic_a3", pos)

    # panic @ 0x6ecc - 0xA4
    panic_a4_address = pos
    cbb_image, pos = assemble_panic(cbb_image, pos, 0xA4, panic_fcn_address)
    cbb_image, _ = assemble_branch(cbb_image, 0x6ECC, panic_a4_address)
    free_space_area.create_func_and_set_head("panic_a4", pos)

    return cbb_image

def patch_init_seceng(cbb_image: bytes, free_space_area: FreeSpaceArea) -> bytes:
    # init_seceng function at 0x6ee8
    # POST 0x22 at 0x6ef4
    cbb_image = make_post_codecave(cbb_image, free_space_area, 0x6ef4, 0x22)
    return cbb_image

def patch_after_relocation_steps(cbb_image: bytes, free_space_area: FreeSpaceArea) -> bytes:
    # after_relocation_steps @ 0x6C0, relocated to another memory space before execution
    panic_fcn_address = free_space_area.func("panic")

    # 0x768 is a panic case - it's where execution ends up if RAM size is bad
    assemble_panic(cbb_image, 0x768, 0xAF, panic_fcn_address)

    return cbb_image

def patch_hwinit_proxy(cbb_image: bytes, free_space_area: FreeSpaceArea) -> bytes:
    # hwinit_proxy @ 0x7110
    post_fcn_address = free_space_area.func("post")

    # create codecave that POSTs 0x23, 0x2E
    post_23_2e_codecave = free_space_area.head()
    pos = post_23_2e_codecave
    cbb_image, pos = assemble_post_call(cbb_image, pos, post_fcn_address, 0x23)
    cbb_image, pos = assemble_post_call(cbb_image, pos, post_fcn_address, 0x2E)
    cbb_image, pos = assemble_li_r4(cbb_image, pos, 0x00)
    cbb_image, pos = assemble_branch(cbb_image, pos, 0x7128)
    free_space_area.create_func_and_set_head("hwinitproxy_trampoline", pos)
    cbb_image, _ = assemble_branch(cbb_image, 0x7124, post_23_2e_codecave)

    return cbb_image

def patch_cd_load_and_jump(cbb_image: bytes, free_space_area: FreeSpaceArea) -> bytes:
    '''
    Patch CD load/verify/jump routine at 0x7318
    '''
    post_fcn_address  = free_space_area.func("post")
    panic_fcn_address = free_space_area.func("panic")

    # first off, there's a completely useless function at 0x7820.
    # while it looks like it's doing RC4 decryption, it's just looping
    # through the same addresses every time and not producing anything
    # useful. this is probably a "random" delay function. so stub it out
    cbb_image, _ = assemble_branch_to_link_register(cbb_image, 0x7820)

    # we can put about 9 panic stubs in here
    panics_area = FreeSpaceArea(0x7824,0x7870)

    # much of what follows here is the same as patch_7378.py

    # put POST 0x30 (VERIFY_OFFSET_4BL) at 0x7388
    # this isn't always validated, so it may be normal if you don't see 0x30 before 0x31
    cbb_image = make_post_codecave(cbb_image, free_space_area, 0x7388, 0x30)

    # 0x73a4: panic because of invalid offset (POST 0xAA)
    # build function stub in free space then put a branch at 0x73A4
    pos = panics_area.head()
    panic_aa_stub = pos
    cbb_image, pos = assemble_panic(cbb_image, pos, 0xAA, panic_fcn_address)
    cbb_image, _ = assemble_branch(cbb_image, 0x73A4, panic_aa_stub)
    panics_area.create_func_and_set_head("panic_aa_stub", pos)

    # create codecave so we can POST 0x31
    cbb_image = make_post_codecave(cbb_image, free_space_area, 0x73A8, 0x31)

    # put POST 0x32 at 0x73c0
    cbb_image, _ = assemble_post_call(cbb_image, 0x73c0, post_fcn_address, 0x32)

    # 0x73EC: the typical "CD" exploit code has its entrypoint at 0x270,
    # which is invalid on 7378 (expects at least 0x310).
    # so let's restore 0x270 as the minimum value.
    cbb_image[0x73EE:0x73F0] = bytes([0x02, 0x70])

    # 0x7430: panic because CD header is invalid
    pos = panics_area.head()
    panic_ab_stub = pos
    cbb_image, pos = assemble_panic(cbb_image, pos, 0xAB, panic_fcn_address)
    cbb_image, _ = assemble_branch(cbb_image, 0x7430, panic_ab_stub)
    panics_area.create_func_and_set_head("panic_ab_stub", pos)

    # create codecave so we can POST 0x33
    cbb_image = make_post_codecave(cbb_image, free_space_area, 0x7434, 0x33)

    # now back to reality
    # in xeBuild scenarios, CD is encrypted,
    # so we still have to run the decryption functions...

    # POST 0x34 @ 0x7464
    cbb_image, _ = assemble_post_call(cbb_image, 0x7464, post_fcn_address, 0x34)

    # POST 0x35 @ 0x74B4
    cbb_image, _ = assemble_post_call(cbb_image, 0x74B4, post_fcn_address, 0x35)

    # POST 0x36 @ 0x74D0
    cbb_image, _ = assemble_post_call(cbb_image, 0x74D0, post_fcn_address, 0x36)

    # POST 0x37 @ 0x74F8
    cbb_image, _ = assemble_post_call(cbb_image, 0x74F8, post_fcn_address, 0x37)

    # 0x7530: we're verifying the SHA hash here.
    # patch in POST 0x39 to keep the glitch chips happy
    # but then immediately set r3 to -1 so it looks like the check succeeded.
    cbb_image, pos = assemble_post_call(cbb_image, 0x7530, post_fcn_address, 0x39)
    cbb_image[pos:pos+4] = bytes([0x38, 0x60, 0xff, 0xff]) # `li r3,-1`
    pos += 4
    cbb_image, pos = assemble_branch(cbb_image, pos, 0x758C) # skip to next step

    # 0x758C: copies and modifies CD image flags, in part based on stuff we
    # already calculated. this differs slightly than 5722/9188.
    # - 0x75b4: scrambles some flags before they are stored. could be harmless
    # - 0x75c0: writes something nasty which could kill CD execution,
    #   so we have to nop that out
    cbb_image, _ = assemble_nop(cbb_image, 0x75c0)

    # 0x75C8: PCI init happens here, but it's immediately followed by
    # a ton of code that decrypts some nonsense used only by newer bootloaders
    # and passes the extra parameters in r5 and r6.
    # an older CD certainly doesn't need it, so we'll ignore it all.
    # instead, let's POST 0x3B, run PCI init, then POST 0x3A and skip right to cd_jump.
    cbb_image, pos = assemble_post_call(cbb_image, 0x75C8, post_fcn_address, 0x3B)
    cbb_image, pos = assemble_branch_with_link(cbb_image, pos, 0x71a0) # = pci_init
    cbb_image, pos = assemble_post_call(cbb_image, pos, post_fcn_address, 0x3A)
    cbb_image, pos = assemble_branch(cbb_image, pos, 0x7634)

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
    cbb_image, _ = assemble_branch(cbb_image, 0xE20, cdjump_preamble_inject_point)

    return cbb_image

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

    return cbb_image

def do_patches(cbb_image: bytes) -> bytes:
    # free space candidate @ 0x8f44-0x9050
    # this is just an obfuscated memcmp of sorts for the hash check
    free_space_area = FreeSpaceArea(0x8f44, 0x9050)

    # install POST and panic functions in some free space
    cbb_image, _ = assemble_post_function(cbb_image, 0x7894)
    free_space_area.create_func_at_address("post", 0x7894)
    cbb_image, _ = assemble_panic_function(cbb_image, 0x7648, 0x7894)
    free_space_area.create_func_at_address("panic", 0x7648)

    # and now let's actually do some patches
    cbb_image = patch_entry_point(cbb_image, free_space_area)
    cbb_image = patch_fuse_check(cbb_image, free_space_area)
    cbb_image = patch_init_seceng(cbb_image, free_space_area)
    cbb_image = patch_after_relocation_steps(cbb_image, free_space_area)
    cbb_image = patch_hwinit_proxy(cbb_image, free_space_area)
    cbb_image = patch_cd_load_and_jump(cbb_image, free_space_area)
    cbb_image = patch_cd_jump(cbb_image)
    cbb_image = patch_exception_handler(cbb_image)


    # vanity string at end of free space
    vanity_string = b"wurthless elektroniks presents elpiss for xeBuild\x00"
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

    # produce xebuild binary as debugging artifact
    with open("cbb_7378_xebuild.bin", "wb") as f:
        f.write(cbb_image)


if __name__ == '__main__':
    main()
