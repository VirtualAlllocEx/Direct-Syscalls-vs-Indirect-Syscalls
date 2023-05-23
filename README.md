# Direct-Syscalls-vs-Indirect-Syscalls
Direct syscalls are a technique that has been, or is being, widely used by attackers and red teamers for various activities such as running shellcode or creating a memory dump of lsass.exe. However, depending on the EDR, direct syscalls may no longer be sufficient to bypass the EDR in the context of various attack techniques as of today (May 2023). This is because more and more vendors are implementing mechanisms in their products, such as callbacks, that can be used to determine the memory area from which the return statement is executed. If the return statement is executed outside the memory area of ntdll.dll, this is abnormal behaviour under Windows and a clear Indicator of Compromise (IOC).

In order to eliminate this IOC from the perspective of the attacker (red team), or to avoid detection by the EDR, direct syscalls can be replaced by indirect syscalls. Put simply, indirect syscalls are a sensible evolution of direct syscalls and allow, for example, the syscall statement and the return statement to be executed not in the memory of the assembly itself, but in the memory of the ntdll.dll, as is usual under Windows.

More details in my related blog post https://redops.at/en/blog/direct-syscalls-vs-indirect-syscalls

# **Disclaimer**
The content and all code examples in this article are for research purposes only and must not be used in an unethical context! The code used is not new and I make no claim to it. The basis for the code comes, as so often, from the ired.team, thank you @spotheplanet for your brilliant work and sharing it with us all!

At the beginning of this blog post I would like to thank the following people who helped me with this topic: [@NinjaParanoid](https://twitter.com/NinjaParanoid), [@Jean_Maes_1994](https://twitter.com/Jean_Maes_1994), [@ShitSecure](https://twitter.com/ShitSecure) and [@NUL0x4C](https://twitter.com/NUL0x4C). If you are interested in malware, check out @NinjaParanoid's MOS course and join the MaldevAcademy project.

# **References**
- https://www.guru99.com/system-call-operating-system.html
- https://alice.climent-pommeret.red/posts/a-syscall-journey-in-the-windows-kernel/#:~:text=This%20number%20is%20called%20syscall,OS%20versions%20or%20service%20packs
- https://alice.climent-pommeret.red/posts/direct-syscalls-hells-halos-syswhispers2/
- https://maldevacademy.com/modules/89
- https://0xdarkvortex.dev/hiding-in-plainsight/
- https://blog.sektor7.net/#!res/2021/halosgate.md
