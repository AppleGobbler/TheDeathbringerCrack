.code
Time64Hook proc
	push RBX
	sub RSP, 040h

	mov RAX, 0ABABABABABABABABh ; OFUNC
	call RAX
	mov RCX, qword ptr [RCX]
	mov qword ptr [RSP+030h], RCX

	mov RCX, 0FE624E212AC18000h
	mov RAX, 0483F078DD478000h
	add RCX, qword ptr [RSP+030h]
	cmp RCX, RAX
	jge FirstJump
	mov RAX, 0D6BF94D5E57A42BDh
	imul RCX
	add RDX, RCX
	sar RDX, 017h
	mov RAX, RDX
	shr RAX, 03Fh
	add RDX, RAX
	jmp SecondJump
FirstJump:
	or RDX, 0FFFFFFFFFFFFFFFFh
SecondJump:
	test RBX, RBX
	je ThirdJump
	mov qword ptr [RBX], RDX
ThirdJump:
	mov RAX, RDX
	mov qword ptr [RSP+030h], RAX

	mov RDX, 0BEEFBEEFBEEFBEEFh ; OCCURENCES
	mov ECX, EAX
	cmp dword ptr [RDX], 01h
	jne OccurenceNotOne
	mov qword ptr [0DEADBEEFDEADBEEFh], RAX ; INPUT1
	mov EAX, ECX
	inc dword ptr [RDX]
	add RSP, 040h
	pop RBX
	ret
OccurenceNotOne:
	mov qword ptr [0BEEFDEADBEEFDEADh], RAX ; INPUT2
	mov EAX, ECX
	inc dword ptr [RDX]

	add RSP, 040h
	pop RBX
	ret
Time64Hook endp
end