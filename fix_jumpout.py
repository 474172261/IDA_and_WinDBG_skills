import idc, idautils, idaapi

def fixJmpOut(function_ea):
	func = idaapi.get_func(function_ea)
	start = func.startEA
	end = func.endEA
	name = idc.GetFunctionName(start)
	if name.startswith('sub_'):
		return
	g = idaapi.FlowChart(func)
	sub_funcs = {}
	for node in g:
		addr = node.startEA
		while addr < node.endEA:
			assembly = idc.GetDisasm(addr)
			if ' sub_' in assembly:
				sub_ea = int(assembly.split('sub_')[1], 16)
				sub_funcs[sub_ea] = 1
			addr += idc.ItemSize(addr)

	if len(sub_funcs.keys()) == 0:
		return
	for key in sub_funcs.keys():
		sub_func = idaapi.get_func(key)
		sub_start = sub_func.startEA
		sub_end = sub_func.endEA
		idc.MakeUnkn(sub_start, 0)
		idc.MakeCode(sub_start)

	print "reparse function: ", name
	idc.MakeUnkn(start, 0)
	idc.MakeCode(start)
	idc.MakeFunction(start)

sub_funcs = []
for function_ea in idautils.Functions():
	if not idc.GetFunctionName(function_ea).startswith('sub_'):
		fixJmpOut(function_ea)

pre_funcs = []
for function_ea in idautils.Functions():
	if not idc.GetFunctionName(function_ea).startswith('sub_'):
		# ignore previous redefined functions
		continue
	func = idaapi.get_func(function_ea)
	start = func.startEA
	pre_code = idc.GetDisasm(start - 1)
	print hex(start)
	if 'ret' not in pre_code:
		idc.MakeUnkn(function_ea, 0)
		idc.MakeCode(function_ea)
		pre_func_name = idc.GetFunctionName(start - 1)
		if pre_func_name == '' or 'sub_' in pre_func_name:
			continue
		pre_func_ea = idaapi.get_func(start - 1).startEA
		pre_funcs.append((pre_func_name, pre_func_ea))

for f in pre_funcs:
	print f[0]
	func_ea = f[1]
	idc.MakeUnkn(func_ea, 0)
	idc.MakeCode(func_ea)
	idc.MakeFunction(func_ea)
