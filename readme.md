# elpiss: Hacked CB_B for Elpis systems with Samsung RAMs

Finally this stupid Xbox 360 revision can be modded.

## DANGER, MON FRERE - THIS IS IN BETA

This is in an experimental/early stage. Bugs still need to be fixed. You can try it on your system, but I can't guarantee it works in
a real-world scenario.

## Why doesn't Elpis work with EXT_CLK right now?

CB_B 9188, which current Glitch2 images use, does not support Elpis boards with Samsung SDRAMs.
If you try to run EXT_CLK against a Samsung Elpis with CB_B 9188, it will mostly fail to glitch, and on the
occasions it does, the CPU will run HWINIT, but an exception will be thrown eventually and the program will
force a jump to absolute address 0x100, which reboots. This is likely because there are edge cases
in the HWINIT configuration list, the format of which hasn't been reverse engineered. 

Reasons nobody has bothered to support Elpis in RGH scenarios include:

- It's a specific hardware revision that is far less desirable than other boards
- It still has Xenon-related headaches, including high power consumption, no HDMI support, and failed CPU rail caps
- RGH is slow or useless on Xenon boards so people assumed it would be slow on Elpis too
- Even after EXT_CLK was released, people found that Elpis boards were the slowest Waternoose-based board to glitch

Meanwhile, I am a simple man who goes to thrift stores and eBay auctions looking for Xboxen to torture.
When I find a phat revision on the shelf it is almost always a Xenon, a Falcon, or an Elpis. Jaspers are
uncommon and I've only ever seen a Zephyr once (twice if you count the one that I had to scrap).

If Elpis systems show up all the time in the wild, then I figure they should be supported, but the 360
modding scene is more or less dead these days with all the big names retired or busy with real-life obligations.
So, armed with absolutely no knowledge of PowerPC assembly and only very high-level knowledge of the 360 boot process,
I charged into this like an idiot and this is the result.

## What does this patch do?

This patches CB_B 7378, which is the latest CB_B version to run on Elpis boards. It reinstates POST codes,
patches out a ton of useless crap, and runs the "CD" exploit code the same way as CB_B 9188.

Octal450 says that other CB_B revisions support Elpis. I just chose 7378 because it made the most sense.

Also, I wouldn't be surprised if the Winbond-compatible CB_B used on Coronas was already capable of
booting Elpis boards and that I completely wasted my time with this. But the CB_B is poorly documented
so someone had to dive into it.

## How do I use it?

### XeLL image

1. `python3 patch_7378.py`
2. Feed `cbb_7378_patched.bin` into the ECC builder of your choice.

Alternatively, you can use `elpis_glitch2.ecc` with J-Runner by selecting Nand -> Load Glitch2 XeLL. Remember to back up your NAND first!

### XeBuild

Run `python3 patch_7378_xebuild.py` to produce the following:

- `cbb_7378_xebuild.bin`: Patched version of the CB_B for xeBuild scenarios
- `cbb_7378_xebuild_patchlist.bin`: Patchlist that will be combined with the `xebuild_common_<kernel_version>.bin` files
- `xebuild/<kernel_version>/bin/patches_g2xenon.bin`: Full patchlist file for xeBuild, for that particular kernel
- `xebuild_jank/<kernel_version>/bin/patches_g2falcon.bin`: The same as patches_g2xenon.bin but for jank applications.

The `xebuild_jank` directory is designed to be pasted on top of an existing J-Runner install. Paste its contents on top of
the contents of your xeBuild directory and CB_B 7378 will be used when making Falcon builds. (J-Runner uses the Falcon
bootloaders for Xenon Glitch2 builds.)

**If you choose to use the jank approach, remember to back up the existing xeBuild directory first.** If you keep the contents
in place, then 7378 will be used for Falcon builds. The RGH1.2 timing files aren't tuned for it, so you will get slower boots
on Falcon, if the system even boots at all. The jank files are only provided so that they can be used until J-Runner supports
7378 properly.

## Okay, cool. When can we expect this to be widely supported/added to J-Runner?

When enough people test it and any bugs that exist are fixed. I only have one Elpis, and thank the good
lords above that I'm not a big name in the 360 modding community otherwise people would be all over this
like flies to dogshit and treat this proof of concept like it's the word of God. There are likely edge
cases that will cause it to fail on some Elpis boards or the thing may refuse to work with a full xeBuild NAND image.

## Anything else I should know?

Expect slow boots. Elpis boards are the slowest to boot with EXT_CLK, so it may take up to a minute
for your board to boot. Careful wire routing and the use of 192 MHz timing files are recommended here.
I tested this using [pigli360](https://github.com/wurthless-elektroniks/pigli360), and even with speedup
hacks it doesn't boot anywhere as fast as a normal Xenon.

After a stable version of the hack was made, I tested on a Matrix glitcher with Octal450's EXT_CLK timing
files. In this case, it performs around the same as a normal Xenon, in that you can get instaboots but it
can take several tries before you get a successful boot.

Also, remember to replace the CPU power rail capacitors if they're failing. Microsoft didn't bother
replacing them when they serviced the boards.

With this release, all Xbox 360s made from 2005 from 2014 can be hardmodded. The only one left is the
seemingly invincible Winchester, but it will fall to a hardware exploit eventually.

Happy modding!

## Acknowledgements

- GliGli and team for the original hacked CB_B 9188, which I used as reference against 7378
- Octal450 and other contributors to XenonLibrary, for explaining what the POST codes mean
- Nadaman for providing a XeLL build that wouldn't crash when connecting Ethernet
- 15432 for his RGH3 image builder, which I used a lot in development
- Tiros for NandPro, which was also used for building test images
- c0z and other contributors to xeBuild (please open source it before the world explodes)
- Whoever was dumb enough to leak a production-only CB_B with all the POST codes enabled

## License

Public domain
